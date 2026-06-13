"""Risk scoring for detected cryptographic components."""
from typing import List, Dict


def score_findings(findings: List[Dict]) -> List[Dict]:
	"""Annotate findings with a `risk_score` between 0-100.

	The scoring is heuristic: certain classifications map to base risk scores.
	"""
	mapping = {
		"quantum_vulnerable": 90,
		"classically_weak": 70,
		"quantum_safe": 20,
		"key_risk": 85,
		"unknown": 30,
	}

	for f in findings:
		cls = f.get("classification", "unknown")
		base = mapping.get(cls, 30)
		# small adjustment for detection method
		detection = f.get("detection_method", "regex")
		if detection == "ml":
			adj = -5
		elif detection == "regex":
			adj = 0
		else:
			adj = 0

		score = max(0, min(100, base + adj))
		f["risk_score"] = score

	return findings

