import os
import json
from dotenv import load_dotenv

load_dotenv()

_GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
_PLACEHOLDER_VALUES = {"", "your_key_here", "YOUR_KEY_HERE", "your-key-here"}
_LLM_ENABLED = _GROQ_API_KEY not in _PLACEHOLDER_VALUES

# Only import and initialise Groq client if we have a real key.
# Avoids crashing the entire server on startup when the key is missing.
if _LLM_ENABLED:
    from groq import Groq
    _client = Groq(api_key=_GROQ_API_KEY)
else:
    _client = None
    print("[llm_enricher] WARNING: GROQ_API_KEY not set or is placeholder — "
          "LLM enrichment disabled, fallback data will be used.")

CACHE: dict = {}

_FALLBACK = {
    "risk_explanation": "LLM analysis unavailable (GROQ_API_KEY not configured).",
    "migration_recommendation": "Consult NIST PQC standards for migration guidance.",
    "nist_standard": "N/A",
    "urgency": "high",
}


def enrich_findings(findings: list[dict]) -> dict:
    """Enrich findings with LLM-generated analysis.

    Returns a dict mapping algorithm name -> analysis dict.
    Falls back gracefully if the Groq key is absent or any API call fails.
    """
    # get unique algorithms not already cached
    unique = {
        f["algorithm"]: f["classification"]
        for f in findings
        if f.get("algorithm")
    }

    for algo, classification in unique.items():
        if algo in CACHE:
            continue

        # Skip LLM entirely if not configured
        if not _LLM_ENABLED or _client is None:
            CACHE[algo] = _FALLBACK
            continue

        try:
            response = _client.chat.completions.create(
                model="llama-3.1-8b-instant",
                temperature=0.1,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a PQC migration expert. "
                            "Respond only in valid JSON, no markdown, no backticks."
                        ),
                    },
                    {
                        "role": "user",
                        "content": (
                            f"Algorithm: {algo}. Classification: {classification}. "
                            f"Return JSON only: "
                            f'{{"risk_explanation": "2 sentences", '
                            f'"migration_recommendation": "2 sentences", '
                            f'"nist_standard": "replacement algo or N/A", '
                            f'"urgency": "critical|high|medium|low"}}'
                        ),
                    },
                ],
            )

            raw = response.choices[0].message.content.strip()
            # Strip markdown fences if the model adds them anyway
            raw = raw.replace("```json", "").replace("```", "").strip()
            CACHE[algo] = json.loads(raw)

        except Exception as exc:
            print(f"[llm_enricher] WARNING: LLM call failed for '{algo}': {exc}")
            CACHE[algo] = _FALLBACK

    # Return only algorithms present in this scan
    return {
        f["algorithm"]: CACHE.get(f["algorithm"], _FALLBACK)
        for f in findings
        if f.get("algorithm")
    }
