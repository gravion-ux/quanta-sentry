import re
from pathlib import Path

PATTERNS = {
    "RSA": re.compile(r"\bRSA\b|rsaEncryption", re.IGNORECASE),
    "ECDSA": re.compile(r"\bECDSA\b|ecPublicKey", re.IGNORECASE),
    "ECDH": re.compile(r"\bECDH\b|secp256|prime256v1", re.IGNORECASE),
    # ML-DSA/SLH-DSA are post-quantum, not legacy DSA: do not match a hyphen or word char before DSA.
    "DSA": re.compile(r"(?<![-\w])DSA\b", re.IGNORECASE),
    "ML-KEM": re.compile(r"ML-KEM|Kyber", re.IGNORECASE),
    "ML-DSA": re.compile(r"ML-DSA|Dilithium", re.IGNORECASE),
    "SLH-DSA": re.compile(r"SLH-DSA|SPHINCS", re.IGNORECASE),
}
EXTENSIONS={".py",".js",".ts",".java",".go",".rs",".c",".h",".cpp",".yaml",".yml",".json",".toml",".conf"}
# Dependency and build directories hold third-party or generated code, not project source.
IGNORED_DIRS={".git",".venv","venv","node_modules","__pycache__","build","dist",
              ".tox",".nox",".mypy_cache",".pytest_cache",".ruff_cache",".eggs","site-packages"}

def _is_ignored(path: Path, root: Path) -> bool:
    try:
        parts=path.relative_to(root).parts[:-1]
    except ValueError:
        parts=path.parts[:-1]
    return any(part in IGNORED_DIRS for part in parts)

def inventory(root: Path):
    root=root.resolve()
    if root.is_file():
        files=[root]
    else:
        files=sorted((p for p in root.rglob("*")
                      if p.is_file() and p.suffix.lower() in EXTENSIONS and not _is_ignored(p,root)),
                     key=lambda p: str(p.relative_to(root)))
    results=[]
    for path in files:
        try: lines=path.read_text(encoding="utf-8",errors="replace").splitlines()
        except OSError: continue
        for number,line in enumerate(lines,1):
            for algorithm,pattern in PATTERNS.items():
                if pattern.search(line):
                    results.append({"algorithm_reference":algorithm,"path":str(path.relative_to(root)) if root.is_dir() else path.name,
                                    "line":number,"evidence":line.strip()[:200],
                                    "status":"requires-manual-validation"})
    return results
