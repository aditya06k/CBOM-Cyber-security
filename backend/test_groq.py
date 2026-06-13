"""Quick end-to-end test for the Groq API key and llm_enricher."""
import sys, os, json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

key = os.getenv("GROQ_API_KEY", "")
print(f"[1] GROQ_API_KEY loaded: {bool(key)} | length={len(key)}")

# --- Direct Groq API test ---
try:
    from groq import Groq
    client = Groq(api_key=key)
    response = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        temperature=0.1,
        messages=[
            {
                "role": "system",
                "content": "You are a PQC migration expert. Respond only in valid JSON, no markdown, no backticks.",
            },
            {
                "role": "user",
                "content": (
                    'Algorithm: RSA. Classification: quantum_vulnerable. '
                    'Return JSON only: {"risk_explanation": "2 sentences", '
                    '"migration_recommendation": "2 sentences", '
                    '"nist_standard": "replacement algo or N/A", '
                    '"urgency": "critical"}'
                ),
            },
        ],
    )
    raw = response.choices[0].message.content.strip()
    print(f"[2] Raw Groq response:\n{raw}\n")
    parsed = json.loads(raw)
    print(f"[3] JSON parsed successfully: {list(parsed.keys())}")
except Exception as exc:
    print(f"[2] GROQ DIRECT CALL FAILED: {exc}")
    sys.exit(1)

# --- llm_enricher module test ---
print("\n--- Testing llm_enricher.enrich_findings() ---")
from llm_enricher import enrich_findings, _LLM_ENABLED

print(f"[4] _LLM_ENABLED in llm_enricher: {_LLM_ENABLED}")

test_findings = [
    {"algorithm": "RSA", "classification": "quantum_vulnerable"},
    {"algorithm": "AES", "classification": "quantum_safe"},
]
result = enrich_findings(test_findings)
print(f"[5] enrich_findings result keys: {list(result.keys())}")
for algo, analysis in result.items():
    print(f"    {algo}: urgency={analysis.get('urgency')} | nist={analysis.get('nist_standard')}")

print("\n✅ All checks passed — Groq is working correctly!")
