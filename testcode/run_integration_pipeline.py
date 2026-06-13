"""Integration runner: create sample files, run scanning pipeline, print CBOM."""
import os
import json
from unittest.mock import MagicMock

# Ensure backend package import path
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from scanner import scan_files
# ML classifier may not be available in this environment; stub classification
def classify_snippet(model, snippet):
    return {"classification": "unknown", "confidence": 0.0}
from risk_scorer import score_findings
import sys
from unittest.mock import MagicMock

# Mock groq to avoid external dependency during integration run
sys.modules['groq'] = MagicMock()
sys.modules['dotenv'] = MagicMock()
import llm_enricher
from cbom_builder import build_cbom


def make_sample():
    content = """
from Crypto.PublicKey import RSA
key = RSA.generate(2048)
cipher = PKCS1_OAEP.new(key.publickey())
enc = cipher.encrypt(b'secret')
print('done')
"""
    return {'sample.py': content}


def mock_llm_client():
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message = MagicMock()
    mock_response.choices[0].message.content = json.dumps({
        "risk_explanation": "RSA is vulnerable to quantum attacks.",
        "migration_recommendation": "Migrate to Kyber.",
        "nist_standard": "Kyber",
        "urgency": "high"
    })
    client = MagicMock()
    client.chat.completions.create.return_value = mock_response
    return client


def run():
    file_map = make_sample()
    print('Scanning files...')
    findings = scan_files(file_map)
    print('Findings:', findings)

    # ML classify windows not already found
    existing_positions = set((f.get('filename'), f.get('line_number')) for f in findings)
    for filename, content in file_map.items():
        lines = content.splitlines()
        for i in range(0, max(0, len(lines) - 4)):
            line_number = i + 1
            overlap = any(fn == filename and abs(ln - line_number) < 5 for fn, ln in existing_positions)
            if overlap:
                continue
            snippet = '\n'.join(lines[i:i+5])
            cls = classify_snippet(None, snippet)
            if cls and cls.get('classification') != 'unknown':
                findings.append({
                    'filename': filename,
                    'line_number': line_number,
                    'algorithm': cls.get('classification'),
                    'classification': cls.get('classification'),
                    'code_snippet': snippet,
                    'detection_method': 'ml',
                })

    findings = score_findings(findings)

    # mock llm client
    llm_enricher.client = mock_llm_client()
    llm_data = llm_enricher.enrich_findings(findings)

    cbom = build_cbom(findings, llm_data, {'files_scanned': len(file_map)})
    print('\n=== CBOM ===')
    print(json.dumps(cbom, indent=2))


if __name__ == '__main__':
    run()
