# Remediation notes — 2026-11

This document records the audit and remediation applied to QuantaSentry in November 2026.
It is additive: the original README, SECURITY.md, CONTRIBUTING.md, and
`docs/REFERENCES.md` remain in the repository and were updated only where they were
inaccurate or inconsistent.

## Method

Every source file was read line by line and each suspected defect was confirmed with
an executable regression test. The new tests were first run against the previously
published revision to confirm the defect was real (red phase: 16 failing tests), and
only then were the fixes applied (green phase: 25 passing and 1 skipped test).

The one skipped test is the symbolic-link integration test. It needs the symlink
privilege that this Windows host does not grant, and it runs in GitHub Actions on
ubuntu.

## Defects fixed

| Severity | Defect | Fix |
| --- | --- | --- |
| High | The scan used `rglob` and followed symlinked directories, so a scan could read files outside the project or loop forever | `_iter_files` walks with `os.walk(followlinks=False)`, and `should_scan` rejects every symbolic link |
| Medium | Key material and environment files could be read and copied into a report | Secret-bearing types (`.pem`, `.key`, `.env`, `.p12`, `.pfx`, `.jks`, `.keystore`, `.crt`, `.cer`, `.der`) are never read. This is a deliberate safety property, not an oversight |
| Medium | The scan scope was narrow: several source and configuration types were skipped, and extension-less build files were missed | The scope now covers the full `EXTENSIONS` set and the known build files in `KNOWN_FILENAMES`, while prose files stay out of scope |
| Medium | The command line raised a raw Python traceback for a missing path | `cli.main` reports one-line messages and uses exit codes `0` / `1` / `2` |
| Medium | A report could not be written to a file, and a CI pipeline had no way to fail on findings | `--output` and `--fail-on-findings` options, with an explicit error when the report cannot be written |
| Low | The report carried no scan counts and no per-algorithm summary | `inventory_report` returns `files_scanned`, `findings`, `by_algorithm`, and the inventory rows |
| Low | The package exposed no public API, and the report carried no format marker | `quantasentry.__all__`, `quantasentry.__version__`, and `schema_version` in the report |

## Documentation and spelling corrections

- `LICENSE` shipped a truncated MIT text: the warranty and liability paragraphs were
  missing. The complete, canonical MIT text is now in place, and the original
  copyright holder line is preserved.
- Spelling was inconsistent across the same file set. The prose now uses one
  convention throughout: American English. Dated records were left untouched.
- The roadmap listed "Stable public API and versioned schemas" and "Documentation and
  contribution guide" as unfinished while the package exposes `__all__`,
  `__version__`, and a versioned report schema, and while `CONTRIBUTING.md`,
  `SECURITY.md`, and this file exist. The checklist now reflects reality.
- The README documented no command-line usage, no detection catalogue, and no Python
  API, although the project ships a console script and a public API. All three are now
  documented.
- A dictionary spelling scan (`codespell`) now reports no misspelling in this
  repository.

## Continuous integration hardening

The workflow previously ran the test suite only. It now also runs a credential scan
on every push and pull request.

| Job | What it does |
| --- | --- |
| `secret-scan` | Runs `scripts/scan-secrets.py`, which fails the build when the repository contains a high-confidence credential pattern (cloud keys, tokens, private key blocks, JWTs) or a file that must never be committed (`.env`, `*.pem`, `*.key`, `*.p12`, `id_rsa`, credential files) |

The scanner is the one already used by the Gravion Toolkit split repositories, so
every toolkit project now shares one definition of what counts as a secret. A
"soft" match, such as a dummy `api_key` inside a test fixture, is reported for
review but does not fail the build.

One allowance is recorded explicitly. The test suite writes a synthetic PEM header
to a temporary file to prove that secret-bearing files are never read. That fixture
holds no key material, so it is listed by name in the scanner instead of weakening
the private-key pattern for the whole repository.

## Verification

| Check | Before | After |
| --- | --- | --- |
| Secret scan in CI | absent | present |
| Tests | 16 failing in the red phase | 25 passing, 1 skipped |
| Symlinked directories | followed | never followed |
| Secret-bearing file types | could be read | never read |
| Scan scope | narrow source-only set | full source and configuration set, plus the known build files |
| Report contents | inventory rows only | `files_scanned`, `findings`, `by_algorithm`, `inventory` |
| CLI failure modes | traceback | one-line message, exit code `0` / `1` / `2` |
| Public API | none | `__all__` and `__version__` `0.2.0` |
| Report format marker | none | `schema_version: 1` |

## Residual limitations

- Detection is textual. A detected algorithm name does not prove a live cryptographic
  use: the match may sit in a comment, a test fixture, a string literal, or an
  unrelated identifier.
- QuantaSentry inventories references. It does not implement or certify ML-KEM,
  ML-DSA, or SLH-DSA, and it makes no compliance or quantum-safety determination.
- The patterns are deliberately narrow. A legacy algorithm under a different name, an
  indirect call, or a custom implementation is not reported.
- Files are read as text with replacement characters, so a binary file that happens to
  carry an in-scope extension is read as text.
- A file named explicitly on the command line is inventoried even when its type is
  outside the traversal scope. Secret-bearing types are the exception and are never
  read.
- `inventory` skips a file it cannot read and does not report the skip. Use
  `inventory_report` when the scan coverage matters.
