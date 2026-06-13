import os
import shutil
import tempfile
import zipfile
import asyncio
from typing import Dict

from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
    from ml_classifier import MODEL, classify_snippet
    from risk_scorer import score_findings
    from llm_enricher import enrich_findings
    from cbom_builder import build_cbom

    # 2. Read files
    file_map = await asyncio.to_thread(_read_supported_files, base_path)

    # 3. findings from regex scanner
    findings = await asyncio.to_thread(scan_files, file_map)

    # 4. ML classify any 5-line windows not caught by regex
    # Run entire ML pass in ONE background thread — avoids spawning thousands of
    # threads (one per snippet) which caused CancelledError / TimeoutError on large repos.
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

    ml_findings = await asyncio.to_thread(_ml_pass, file_map, findings)
    findings.extend(ml_findings)

    # 5. score findings
    findings = await asyncio.to_thread(score_findings, findings)

    # 6. llm enrichment
    llm_data = await asyncio.to_thread(enrich_findings, findings)

    # 7. build cbom
    cbom = await asyncio.to_thread(build_cbom, findings, llm_data, {"files_scanned": len(file_map)})

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
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass


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
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
