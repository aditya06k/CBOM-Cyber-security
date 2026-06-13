"""Repository and file scanning utilities."""

import re
from typing import Any

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "dist", "build", "vendor",
    "tests", "test", "vectors", "docs", ".github", "website",
    "venv", ".venv", "env", ".env", "temp", "results", "output",
    "cache", "logs", "log",
}

# Key-risk patterns only apply to these source-code extensions
# (not JSON/YAML/text data files which legitimately contain UUIDs/hashes)
_SOURCE_CODE_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java",
    ".c", ".cpp", ".h", ".hpp", ".go", ".rs", ".rb", ".php",
    ".cs", ".swift", ".kt", ".scala",
}

PATTERN_GROUPS: list[tuple[str, list[str]]] = [
    (
        "quantum_vulnerable",
        [
            "RSA",
            "DSA",
            "ECDSA",
            "ECDH",
            "DiffieHellman",
            "X25519",
            "Ed25519",
            "secp256",
            "prime256",
        ],
    ),
    (
        "classically_weak",
        [
            "MD5",
            "SHA1",
            "DES",
            "3DES",
            "RC4",
            "AES-ECB",
            "AES-CBC",
            "Blowfish",
        ],
    ),
    (
        "quantum_safe",
        [
            "ML-KEM",
            "ML-DSA",
            "SLH-DSA",
            "Kyber",
            "Dilithium",
            "FALCON",
            "AES-GCM",
            "SHA-256",
            "SHA-3",
            "ChaCha20",
        ],
    ),
]

KEY_RISK_PATTERNS: list[tuple[str, str]] = [
    # Only match hex strings that appear as an assigned value/string literal
    # in source code — bare UUIDs in JSON data files are excluded by the
    # _SOURCE_CODE_EXTS check performed at scan time.
    (
        "hex_string",
        r'(?i)(?:key|secret|token|iv|nonce|salt|seed|password)\s*[=:]\s*["\']?[0-9a-fA-F]{32,}["\']?',
    ),
    (
        "hardcoded_credential",
        r'(?i)(key|secret|password|token)\s*=\s*["\'][^"\']{8,}["\']',
    ),
]

_COMPILED_GROUPS: list[tuple[str, re.Pattern[str], str]] = []
for classification, patterns in PATTERN_GROUPS:
    for name in sorted(patterns, key=len, reverse=True):
        escaped = re.escape(name)
        pattern = re.compile(
            rf"(?<![A-Za-z0-9_-]){escaped}(?![A-Za-z0-9_-])",
            re.IGNORECASE,
        )
        _COMPILED_GROUPS.append((classification, pattern, name))

_COMPILED_KEY_RISK: list[tuple[str, re.Pattern[str]]] = [
    (name, re.compile(regex)) for name, regex in KEY_RISK_PATTERNS
]


def _should_skip(filename: str) -> bool:
    normalized = filename.replace("\\", "/")
    parts = normalized.split("/")
    return any(part in SKIP_DIRS for part in parts)


def _snippet(lines: list[str], line_index: int) -> str:
    start = max(0, line_index - 2)
    end = min(len(lines), line_index + 3)
    return "\n".join(lines[start:end])


def _match_on_line(
    line: str,
    pattern: re.Pattern[str],
    algorithm: str,
    classification: str,
    filename: str,
    line_number: int,
    lines: list[str],
    line_index: int,
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for _ in pattern.finditer(line):
        matches.append(
            {
                "filename": filename,
                "line_number": line_number,
                "algorithm": algorithm,
                "classification": classification,
                "code_snippet": _snippet(lines, line_index),
                "detection_method": "regex",
            }
        )
    return matches


def _file_ext(filename: str) -> str:
    """Return the lowercased file extension including the dot."""
    import os
    return os.path.splitext(filename)[1].lower()


def scan_files(file_map: dict[str, str]) -> list[dict]:
    """Scan file contents for cryptographic patterns and key-risk indicators."""
    findings: list[dict] = []

    for filename, content in file_map.items():
        if _should_skip(filename):
            continue

        ext = _file_ext(filename)
        is_source = ext in _SOURCE_CODE_EXTS
        lines = content.splitlines()

        for line_index, line in enumerate(lines):
            line_number = line_index + 1

            for classification, pattern, algorithm in _COMPILED_GROUPS:
                findings.extend(
                    _match_on_line(
                        line,
                        pattern,
                        algorithm,
                        classification,
                        filename,
                        line_number,
                        lines,
                        line_index,
                    )
                )

            # Key-risk patterns (hardcoded secrets/hex keys) only apply
            # to source code files, not to data/config/binary files.
            if is_source:
                for algorithm, pattern in _COMPILED_KEY_RISK:
                    findings.extend(
                        _match_on_line(
                            line,
                            pattern,
                            algorithm,
                            "key_risk",
                            filename,
                            line_number,
                            lines,
                            line_index,
                        )
                    )

    return findings
