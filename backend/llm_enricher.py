import os
import json
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))
CACHE = {}

def enrich_findings(findings: list[dict]) -> dict:
    
    fallback = {
        "risk_explanation": "Analysis unavailable.",
        "migration_recommendation": "Consult NIST PQC standards.",
        "nist_standard": "N/A",
        "urgency": "high"
    }
    
    # get unique algorithms not in cache
    unique = {
        f["algorithm"]: f["classification"] 
        for f in findings 
        if f.get("algorithm")
    }
    
    for algo, classification in unique.items():
        if algo in CACHE:
            continue
        
        try:
            response = client.chat.completions.create(
                model="llama-3.1-8b-instant",
                temperature=0.1,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a PQC migration expert. Respond only in valid JSON, no markdown, no backticks."
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
                        )
                    }
                ]
            )
            
            raw = response.choices[0].message.content.strip()
            # strip markdown if model adds it anyway
            raw = raw.replace("```json", "").replace("```", "").strip()
            CACHE[algo] = json.loads(raw)
            
        except Exception:
            CACHE[algo] = fallback
    
    # return only algorithms in this scan
    return {
        f["algorithm"]: CACHE.get(f["algorithm"], fallback)
        for f in findings
        if f.get("algorithm")
    }
