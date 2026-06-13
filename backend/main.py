import os
import sys
import shutil
import stat
import tempfile
import traceback
import zipfile
import asyncio
import logging
from typing import Dict

# Ensure the backend package directory is on sys.path so that sibling modules
# (scanner, cbom_builder, risk_scorer, llm_enricher, ml_classifier) can be
# imported whether uvicorn is launched from the project root or from within
# the backend/ directory itself.
_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cbom_backend")


def _remove_readonly(func, path, _):
    """onerror handler for shutil.rmtree — fixes Windows read-only files (e.g. .git pack files)."""
    os.chmod(path, stat.S_IWRITE)
    func(path)


def _cleanup_tmpdir(path: str):
    """Safely remove a temporary directory, handling Windows file-locking."""
    try:
        shutil.rmtree(path, onerror=_remove_readonly)
    except Exception:
        pass

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    tb = traceback.format_exc()
    logger.error("Unhandled exception on %s %s:\n%s", request.method, request.url, tb)
    return JSONResponse(
        status_code=500,
        content={"detail": f"{type(exc).__name__}: {exc}", "traceback": tb},
    )


class RepoScanRequest(BaseModel):
    github_url: str


def _read_supported_files(root_path: str) -> Dict[str, str]:
    supported_ext = {".py", ".js", ".java", ".c", ".cpp", ".h", ".txt", ".pem", ".json", ".yaml", ".yml", ".rs", ".go"}
    skip_dirs = {
        "node_modules", ".git", "__pycache__", "dist", "build", "vendor",
        "tests", "test", "vectors", "docs", ".github", "website",
        "venv", ".venv", "env", ".env", "temp"
    }
    file_map: Dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root_path):
        # Filter out skipped directories in-place to prevent os.walk from descending into them
        dirnames[:] = [d for d in dirnames if d.lower() not in skip_dirs]
        
        normalized_path = dirpath.replace('\\', '/')
        path_parts = set(p.lower() for p in normalized_path.split('/'))
        if path_parts.intersection(skip_dirs):
            continue
            
        for fn in filenames:
            _, ext = os.path.splitext(fn)
            if ext.lower() not in supported_ext:
                continue
            path = os.path.join(dirpath, fn)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    rel = os.path.relpath(path, root_path)
                    file_map[rel.replace('\\', '/')] = fh.read()
            except Exception:
                continue
    return file_map


async def _process_scan_dir(base_path: str) -> Dict:
    """Process a directory: scan, ML classify, score, enrich, build CBOM."""
    from scanner import scan_files
    from risk_scorer import score_findings
    from llm_enricher import enrich_findings
    from cbom_builder import build_cbom

    # Try to load the ML classifier — gracefully degrade on MemoryError / ImportError
    # (can happen on constrained systems when scipy/numpy fail to initialise).
    _ml_enabled = False
    try:
        from ml_classifier import MODEL, classify_snippet
        _ml_enabled = True
    except (MemoryError, ImportError, Exception) as exc:
        logger.warning("ML classifier unavailable, skipping ML pass: %s", exc)

    # 2. Read files
    file_map = await asyncio.to_thread(_read_supported_files, base_path)
    logger.info("Read %d files from %s", len(file_map), base_path)

    # 3. findings from regex scanner
    findings = await asyncio.to_thread(scan_files, file_map)
    logger.info("Regex scan produced %d findings", len(findings))

    # 4. ML classify any 5-line windows not caught by regex (if ML is available)
    if _ml_enabled:
        MAX_ML_WINDOWS_PER_FILE = 5   # cap per file to keep runtime bounded

        def _ml_pass(file_map, existing_findings):
            existing_positions = set(
                (f.get("filename"), f.get("line_number")) for f in existing_findings
            )
            ml_findings = []
            for filename, content in file_map.items():
                lines = content.splitlines()
                windows_checked = 0
                for i in range(0, max(0, len(lines) - 4)):
                    if windows_checked >= MAX_ML_WINDOWS_PER_FILE:
                        break
                    line_number = i + 1
                    overlap = any(
                        fn == filename and abs(ln - line_number) < 5
                        for fn, ln in existing_positions
                    )
                    if overlap:
                        continue
                    snippet = "\n".join(lines[i : i + 5])
                    cls = classify_snippet(MODEL, snippet)
                    windows_checked += 1
                    if cls and cls.get("classification") != "unknown":
                        ml_findings.append(
                            {
                                "filename": filename,
                                "line_number": line_number,
                                "algorithm": cls.get("classification"),
                                "classification": cls.get("classification"),
                                "code_snippet": snippet,
                                "detection_method": "ml",
                            }
                        )
            return ml_findings

        try:
            ml_findings = await asyncio.to_thread(_ml_pass, file_map, findings)
            findings.extend(ml_findings)
            logger.info("ML pass added %d findings", len(ml_findings))
        except (MemoryError, Exception) as exc:
            logger.warning("ML pass failed, continuing without ML findings: %s", exc)

    # 5. score findings
    findings = await asyncio.to_thread(score_findings, findings)

    # 6. llm enrichment
    llm_data = await asyncio.to_thread(enrich_findings, findings)

    # 7. build cbom
    cbom = await asyncio.to_thread(build_cbom, findings, llm_data, {"files_scanned": len(file_map)})
    logger.info("CBOM built with %d components", len(cbom.get("components", [])))

    return cbom


@app.post("/scan/upload")
async def scan_upload(file: UploadFile):
    tmpdir = tempfile.mkdtemp(dir=os.getcwd())
    try:
        zip_path = os.path.join(tmpdir, "upload.zip")
        contents = await file.read()
        with open(zip_path, "wb") as fh:
            fh.write(contents)

        # extract
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(tmpdir)

        cbom = await _process_scan_dir(tmpdir)

        return cbom
    finally:
        _cleanup_tmpdir(tmpdir)


@app.post("/scan/repo")
async def scan_repo(request: RepoScanRequest):
    import git

    tmpdir = tempfile.mkdtemp(dir=os.getcwd())
    try:
        # clone the repo
        url = request.github_url.strip()
        def _clone():
            return git.Repo.clone_from(url, tmpdir)

        # timeout entire operation at 60s
        try:
            await asyncio.wait_for(asyncio.to_thread(_clone), timeout=120)
        except asyncio.TimeoutError:
            raise HTTPException(status_code=504, detail="Repository clone timed out")
        except git.exc.GitCommandError as ge:
            err_msg = str(ge.stderr or ge)
            if "not found" in err_msg.lower() or "repository not found" in err_msg.lower():
                raise HTTPException(status_code=404, detail="GitHub repository not found. Please check the URL.")
            raise HTTPException(status_code=400, detail=f"Git clone failed: {err_msg}")

        cbom = await asyncio.wait_for(_process_scan_dir(tmpdir), timeout=300)
        return cbom
    finally:
        _cleanup_tmpdir(tmpdir)


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
