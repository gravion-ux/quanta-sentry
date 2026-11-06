"""Static cryptographic inventory for QuantaSentry.

The inventory reads source and configuration files only. Key material and
environment files are deliberately not read, so a generated report can never
carry secret material.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

__all__ = [
    "EXTENSIONS",
    "IGNORED_DIRS",
    "KNOWN_FILENAMES",
    "PATTERNS",
    "inventory",
    "inventory_report",
]

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

# Source and configuration file types. Private key material and environment
# files are excluded on purpose: an inventory report must not leak secrets.
EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rs", ".c", ".h", ".cpp", ".hpp",
    ".cs", ".swift", ".kt", ".kts", ".scala", ".rb", ".php", ".pl", ".sh", ".bash", ".ps1",
    ".bat", ".cmd", ".sql", ".yaml", ".yml", ".json", ".toml", ".conf", ".ini", ".cfg",
    ".properties", ".xml", ".tf", ".tfvars", ".gradle", ".cmake", ".mk",
}

# Build and dependency files that carry no extension.
KNOWN_FILENAMES = {
    "Dockerfile", "Makefile", "CMakeLists.txt", "requirements.txt", "go.mod", "Cargo.toml",
    "Pipfile", "build.gradle", "pom.xml",
}

# File types that may hold key material or credentials. They are never read, so
# an inventory report cannot carry secret material.
SECRET_BEARING_EXTENSIONS = {
    ".pem", ".key", ".env", ".p12", ".pfx", ".jks", ".keystore", ".crt", ".cer", ".der",
}

# Dependency and build directories hold third-party or generated code, not project source.
IGNORED_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", "build", "dist",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".eggs", "site-packages",
    "target", ".idea", ".vscode", "vendor", "third_party", "coverage", "htmlcov",
}


def _is_ignored(path: Path, root: Path) -> bool:
    try:
        parts = path.relative_to(root).parts[:-1]
    except ValueError:
        parts = path.parts[:-1]
    return any(part in IGNORED_DIRS for part in parts)


def _is_scannable(path: Path) -> bool:
    """True when the file type is part of the inventory scope."""
    if path.name in KNOWN_FILENAMES:
        return True
    return path.suffix.lower() in EXTENSIONS


def should_scan(path: Path, root: Path) -> bool:
    """Decide whether a path is part of the inventory scope.

    Symbolic links are never followed, ignored directories are skipped, key
    material is never read, and only source and configuration file types are
    in scope.
    """
    if path.is_symlink():
        return False
    if _is_ignored(path, root):
        return False
    if path.suffix.lower() in SECRET_BEARING_EXTENSIONS:
        return False
    return _is_scannable(path)


def _iter_files(root: Path):
    """Yield the files to scan.

    Symbolic links are never followed: a link can point outside the project, or
    back at a parent directory, which would make the scan read unrelated files
    or never terminate.
    """
    if root.is_file():
        # A file named explicitly is inventoried even when its type is outside
        # the traversal scope, but key material is never read.
        if root.suffix.lower() not in SECRET_BEARING_EXTENSIONS:
            yield root
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            name for name in dirnames
            if name not in IGNORED_DIRS and not (Path(dirpath) / name).is_symlink()
        )
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if should_scan(path, root):
                yield path


def _display_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def inventory(root: Path) -> list[dict]:
    """List the cryptographic algorithm references found under a path."""
    root = root.resolve()
    results: list[dict] = []
    for path in _iter_files(root):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for number, line in enumerate(lines, 1):
            for algorithm, pattern in PATTERNS.items():
                if pattern.search(line):
                    results.append(
                        {
                            "algorithm_reference": algorithm,
                            "path": _display_path(path, root),
                            "line": number,
                            "evidence": line.strip()[:200],
                            "status": "requires-manual-validation",
                        }
                    )
    return results


def inventory_report(root: Path) -> dict:
    """Return the inventory together with a summary of what was scanned."""
    root = root.resolve()
    results = inventory(root)
    by_algorithm: dict[str, int] = {}
    for row in results:
        algorithm = row["algorithm_reference"]
        by_algorithm[algorithm] = by_algorithm.get(algorithm, 0) + 1
    scanned = sum(1 for _ in _iter_files(root))
    return {
        "files_scanned": scanned,
        "findings": len(results),
        "by_algorithm": dict(sorted(by_algorithm.items())),
        "inventory": results,
    }
