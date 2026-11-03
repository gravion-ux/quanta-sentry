import re
from pathlib import Path

PATTERNS = {
    "RSA": re.compile(r"\bRSA\b|rsaEncryption", re.IGNORECASE),
    "ECDSA": re.compile(r"\bECDSA\b|ecPublicKey", re.IGNORECASE),
    "ECDH": re.compile(r"\bECDH\b|secp256|prime256v1", re.IGNORECASE),
    "DSA": re.compile(r"\bDSA\b", re.IGNORECASE),
    "ML-KEM": re.compile(r"ML-KEM|Kyber", re.IGNORECASE),
    "ML-DSA": re.compile(r"ML-DSA|Dilithium", re.IGNORECASE),
    "SLH-DSA": re.compile(r"SLH-DSA|SPHINCS", re.IGNORECASE),
}
EXTENSIONS={".py",".js",".ts",".java",".go",".rs",".c",".h",".cpp",".yaml",".yml",".json",".toml",".conf"}

def inventory(root: Path):
    root=root.resolve()
    files=[root] if root.is_file() else [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in EXTENSIONS and ".git" not in p.parts]
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
