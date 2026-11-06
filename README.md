# QuantaSentry

> Cryptographic inventory and post-quantum migration-readiness reporting from source/configuration evidence.

**Status:** MVP scaffold / research prototype. Not production-certified.

## Features
- Detect selected cryptographic algorithm references in source and configuration files.
- Record file and line evidence for every reference, together with the matched line.
- Summarize the findings per algorithm in a migration-review inventory.
- Never read secret-bearing file types, so a generated report cannot carry key material.
- Never follow a symbolic link, so a scan cannot read outside the project.
- Skip dependency and build directories, and keep prose files out of scope.
- Emit a machine-readable JSON report with a `schema_version` field for CI pipelines.

## Detections

| Pattern | Matches | Class |
| --- | --- | --- |
| `RSA` | `RSA`, `rsaEncryption` | legacy |
| `ECDSA` | `ECDSA`, `ecPublicKey` | legacy |
| `ECDH` | `ECDH`, `secp256`, `prime256v1` | legacy |
| `DSA` | `DSA` as a standalone word | legacy |
| `ML-KEM` | `ML-KEM`, `Kyber` | post-quantum |
| `ML-DSA` | `ML-DSA`, `Dilithium` | post-quantum |
| `SLH-DSA` | `SLH-DSA`, `SPHINCS` | post-quantum |

Matching is case-insensitive. The `DSA` pattern does not match `ML-DSA` or `SLH-DSA`,
so a post-quantum signature is not reported as legacy DSA. Every finding carries the
`algorithm_reference`, the `path`, the `line`, the matching `evidence`, and the status
`requires-manual-validation`. The post-quantum names follow the standards listed in
[Standards references](docs/REFERENCES.md).

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
# Windows: .venv\\Scripts\\activate
pip install -e ".[dev]"
pytest
```

## Command-line usage

```bash
quanta-sentry path/to/project
quanta-sentry path/to/project --output inventory.json
quanta-sentry path/to/project --fail-on-findings
```

| Option | Meaning |
| --- | --- |
| `path` | Required positional argument: the source directory or file to inventory |
| `--output PATH` | Write the JSON report to `PATH` in addition to printing it |
| `--fail-on-findings` | Exit with status `1` when at least one reference is reported |

| Exit code | Meaning |
| --- | --- |
| `0` | The path was inventoried and no error occurred |
| `1` | The report could not be written, or findings were reported with `--fail-on-findings` |
| `2` | The path does not exist, or the command line was not valid |

The report is JSON and carries `tool`, `mode`, `schema_version`,
`standard_references`, `files_scanned`, `findings`, `by_algorithm`, `inventory`, and
a `notice` stating that an inventory hint is not a compliance or quantum-safety
determination.

## Python API

```python
from pathlib import Path

from quantasentry import inventory, inventory_report
from quantasentry.inventory import should_scan

rows = inventory(Path("src"))           # one row per detected reference
report = inventory_report(Path("src"))  # files_scanned, findings, by_algorithm, inventory
```

`should_scan(path, root)` is the scope decision helper: it rejects symbolic links,
ignored directories, and secret-bearing file types. The package exports a stable
public API (`quantasentry.__all__`) and reports its version as
`quantasentry.__version__` (`0.2.0`).

## Safety and scope
Static inventory only. A detected algorithm name does not prove a live cryptographic use or establish exploitability. No endpoint probing or cryptographic downgrade is performed.

Secret-bearing file types are never read: `.pem`, `.key`, `.env`, `.p12`, `.pfx`, `.jks`, `.keystore`, `.crt`, `.cer`, and `.der`. This is a deliberate safety property, not an oversight, so a generated report cannot leak key material. Prose files (`.md`, `.txt`) stay out of scope, and the scan follows no symbolic link.

## Roadmap
- [x] Stable public API and versioned schemas
- [x] More unit, integration and adversarial tests (25 passing, 1 skipped)
- [ ] Reproducible benchmarks and sample datasets
- [ ] Signed releases and dependency review
- [x] Documentation and contribution guide

## License
MIT. See [LICENSE](LICENSE). The LICENSE file now carries the complete MIT text, including the warranty and liability clauses.
