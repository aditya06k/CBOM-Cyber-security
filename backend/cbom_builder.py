"""CBOM (Cryptography Bill of Materials) builder."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def build_cbom(findings: list[dict[str, Any]], llm_data: dict[str, dict], meta: dict) -> dict:
	"""Build a CycloneDX-style CBOM from findings and LLM data.

	Args:
		findings: list of finding dicts (must include algorithm, classification, filename,
			line_number, code_snippet, detection_method, risk_score)
		llm_data: mapping algorithm -> analysis dict
		meta: metadata dict, expects keys like `files_scanned`

	Returns:
		dict representing the CBOM JSON structure described in the spec.
	"""
	now = datetime.now(timezone.utc).isoformat()

	# summary counts
	quantum_vulnerable_count = sum(1 for f in findings if f.get("classification") == "quantum_vulnerable")
	classically_weak_count = sum(1 for f in findings if f.get("classification") == "classically_weak")
	quantum_safe_count = sum(1 for f in findings if f.get("classification") == "quantum_safe")
	ml_detected_count = sum(1 for f in findings if f.get("detection_method") == "ml")

	# overall risk score (mean of risk_score)
	scores = [float(f.get("risk_score", 0)) for f in findings]
	overall_risk_score = float(sum(scores) / len(scores)) if scores else 0.0

	if overall_risk_score > 75:
		migration_urgency = "critical"
	elif overall_risk_score > 50:
		migration_urgency = "high"
	elif overall_risk_score > 25:
		migration_urgency = "medium"
	else:
		migration_urgency = "low"

	# top risk files by max risk_score
	file_max: dict[str, float] = {}
	for f in findings:
		fn = f.get("filename")
		rs = float(f.get("risk_score", 0))
		if fn:
			file_max[fn] = max(file_max.get(fn, 0.0), rs)

	top_risk_files = [k for k, _ in sorted(file_max.items(), key=lambda x: x[1], reverse=True)][:5]

	# group components by algorithm
	components: dict[str, dict] = {}
	for f in findings:
		algo = f.get("algorithm") or f.get("classification")
		if not algo:
			continue
		comp = components.setdefault(algo, {
			"type": "component",
			"name": algo,
			"classification": f.get("classification"),
			"risk_score": 0.0,
			"detection_method": f.get("detection_method"),
			"occurrences": [],
			"llm_analysis": llm_data.get(algo, {}),
		})

		comp["occurrences"].append(
			{
				"filename": f.get("filename"),
				"line_number": f.get("line_number"),
				"code_snippet": f.get("code_snippet"),
			}
		)

		# keep max risk_score and canonical detection method
		comp["risk_score"] = max(comp.get("risk_score", 0.0), float(f.get("risk_score", 0.0)))
		if comp.get("detection_method") != "regex" and f.get("detection_method") == "regex":
			comp["detection_method"] = "regex"

	cbom = {
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"metadata": {
			"timestamp": now,
			"tool": "CryptoPulse v1.0",
			"files_scanned": int(meta.get("files_scanned", 0)),
			"total_findings": len(findings),
		},
		"summary": {
			"quantum_vulnerable_count": int(quantum_vulnerable_count),
			"classically_weak_count": int(classically_weak_count),
			"quantum_safe_count": int(quantum_safe_count),
			"ml_detected_count": int(ml_detected_count),
			"overall_risk_score": overall_risk_score,
			"migration_urgency": migration_urgency,
			"top_risk_files": top_risk_files,
		},
		"components": list(components.values()),
	}

	return cbom

