# -*- coding: utf-8 -*-
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

"""
End-to-end test for the CBOM scanner.

Repo: https://github.com/nicowillis/crypto-examples
  - A tiny (~10 file) Python repo that explicitly uses RSA, AES, MD5, SHA1, ECDSA
  - Finishes scanning in <30 seconds

Fallback repo: https://github.com/Legrandin/pycryptodome  (medium, ~200 files)
"""

import httpx
import json
import time

BASE = "http://localhost:8000"

# --- small focused repo with known crypto usage ---
TEST_REPO = "https://github.com/nicowillis/crypto-examples"

def print_cbom(cbom: dict, elapsed: float):
    meta = cbom.get("metadata", {})
    summary = cbom.get("summary", {})
    components = cbom.get("components", [])

    print(f"\n{'='*60}")
    print("  CBOM SCAN RESULT")
    print(f"{'='*60}")
    print(f"  Tool            : {meta.get('tool')}")
    print(f"  Scan duration   : {elapsed}s")
    print(f"  Files scanned   : {meta.get('files_scanned')}")
    print(f"  Total findings  : {meta.get('total_findings')}")

    # FIX: guard against None before calling .upper() / :.1f
    overall_risk = summary.get('overall_risk_score')
    migration_urgency = summary.get('migration_urgency') or "unknown"

    print(f"\n--- SUMMARY ---")
    print(f"  Quantum Vulnerable : {summary.get('quantum_vulnerable_count')}")
    print(f"  Classically Weak   : {summary.get('classically_weak_count')}")
    print(f"  Quantum Safe       : {summary.get('quantum_safe_count')}")
    print(f"  ML Detected        : {summary.get('ml_detected_count')}")
    print(f"  Overall Risk Score : {overall_risk:.1f} / 100" if overall_risk is not None else "  Overall Risk Score : N/A")
    print(f"  Migration Urgency  : {migration_urgency.upper()}")
    print(f"  Top Risk Files     :")
    for f in summary.get("top_risk_files", []):
        print(f"    - {f}")

    print(f"\n--- COMPONENTS ({len(components)} unique algorithms) ---")
    for c in sorted(components, key=lambda x: x.get("risk_score", 0), reverse=True):
        occ   = len(c.get("occurrences", []))
        llm   = c.get("llm_analysis", {})
        name  = c.get("name", "")
        cls   = c.get("classification", "")
        score = c.get("risk_score", 0)
        nist  = llm.get("nist_standard", "N/A")
        urgency = llm.get("urgency", "?")
        # FIX: use :.0f so float risk_score prints cleanly without extra decimals
        print(f"  [{cls:20}] {name:20} risk={score:.0f}  occ={occ:4}  nist={nist}  urgency={urgency}")

    print(f"\n--- SAMPLE DETAIL (highest risk) ---")
    top = sorted(components, key=lambda x: x.get("risk_score", 0), reverse=True)
    if top:
        c   = top[0]
        occ = c.get("occurrences", [{}])[0]
        llm = c.get("llm_analysis", {})
        print(f"  Algorithm  : {c.get('name')}")
        print(f"  File       : {occ.get('filename')}")
        print(f"  Line       : {occ.get('line_number')}")
        print(f"  Snippet    :")
        for line in (occ.get("code_snippet") or "").splitlines():
            print(f"    {line}")
        print(f"\n  LLM Risk   : {llm.get('risk_explanation')}")
        print(f"  LLM Reco   : {llm.get('migration_recommendation')}")
        print(f"  NIST Std   : {llm.get('nist_standard')}")
        print(f"  Urgency    : {llm.get('urgency')}")

    with open("test_cbom_output.json", "w") as fh:
        json.dump(cbom, fh, indent=2)
    print(f"  Full JSON saved -> test_cbom_output.json")
    print(f"{'='*60}\n")

def verify_results(cbom: dict) -> bool:
    """Basic correctness assertions."""
    summary    = cbom.get("summary", {})
    components = cbom.get("components", [])
    errors = []

    # 1. There must be findings
    total = cbom.get("metadata", {}).get("total_findings", 0)
    if total == 0:
        errors.append("FAIL: No findings at all — scanner may be broken")

    # 2. quantum_vulnerable_count should be > 0 for any crypto repo
    if summary.get("quantum_vulnerable_count", 0) == 0:
        errors.append("WARN: No quantum-vulnerable algorithms found (expected RSA/ECDSA/etc.)")

    # 3. Every component must have an llm_analysis block
    for c in components:
        if not c.get("llm_analysis"):
            errors.append(f"FAIL: Component '{c.get('name')}' missing llm_analysis")

    # 4. Risk scores must be in 0-100
    for c in components:
        rs = c.get("risk_score", -1)
        if not (0 <= rs <= 100):
            errors.append(f"FAIL: Component '{c.get('name')}' has out-of-range risk_score={rs}")

    # 5. migration_urgency must be valid
    urgency = summary.get("migration_urgency", "")
    if urgency not in ("critical", "high", "medium", "low"):
        errors.append(f"FAIL: Invalid migration_urgency='{urgency}'")

    if errors:
        print("\n[VERIFICATION ISSUES]")
        for e in errors:
            print(f"  !! {e}")
        return False
    else:
        print("\n[VERIFICATION] All checks passed OK")
        return True


# FIX: wrap all script-level execution in __main__ guard so the file can be
#      safely imported / tested without immediately firing HTTP requests.
if __name__ == "__main__":
    success = True

    # ── HEALTH CHECK ──────────────────────────────────────────────
    print("1. Health check ...")
    try:
        r = httpx.get(f"{BASE}/health", timeout=10)
        assert r.status_code == 200 and r.json().get("status") == "ok", \
            f"Health failed: {r.text}"
        print("   OK\n")
    except Exception as e:
        print(f"   HEALTH CHECK FAILED: {e}")
        sys.exit(1)

    # ── REPO SCAN ─────────────────────────────────────────────────
    print(f"2. Repo scan: {TEST_REPO}")
    print("   (cloning + scanning — may take up to 2 min) ...")
    start   = time.time()
    r       = httpx.post(f"{BASE}/scan/repo", json={"github_url": TEST_REPO}, timeout=300)
    elapsed = round(time.time() - start, 1)

    print(f"   HTTP {r.status_code}  ({elapsed}s)")

    if r.status_code == 200:
        cbom = r.json()
        print_cbom(cbom, elapsed)
        # FIX: use verify_results() return value to set the exit code
        if not verify_results(cbom):
            success = False
    else:
        print(f"   ERROR: {r.status_code} — {r.text[:500]}")
        print("\n   Trying fallback repo: https://github.com/dlitz/pycrypto ...")
        start = time.time()
        r2    = httpx.post(f"{BASE}/scan/repo",
                           json={"github_url": "https://github.com/dlitz/pycrypto"},
                           timeout=300)
        elapsed = round(time.time() - start, 1)
        print(f"   HTTP {r2.status_code}  ({elapsed}s)")
        if r2.status_code == 200:
            print_cbom(r2.json(), elapsed)
            # FIX: use fallback verify result too
            if not verify_results(r2.json()):
                success = False
        else:
            print(f"   FALLBACK ERROR: {r2.text[:300]}")
            success = False

    # FIX: exit with non-zero code on any failure so CI pipelines can detect it
    sys.exit(0 if success else 1)
