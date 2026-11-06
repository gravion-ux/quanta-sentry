"""Command-line entry point for QuantaSentry.

Problems are reported as one-line messages instead of Python tracebacks so the
tool can be used directly in CI pipelines.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .inventory import inventory_report

EXIT_OK = 0
EXIT_INVALID_INPUT = 1
EXIT_USAGE = 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="quanta-sentry",
        description="Cryptographic inventory and migration-readiness reporting.",
    )
    parser.add_argument("path", type=Path, help="Source directory or file to inventory")
    parser.add_argument("--output", type=Path, help="Optional path for the JSON report")
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit with status 1 when at least one reference is reported",
    )
    args = parser.parse_args(argv)

    if not args.path.exists():
        print(f"quanta-sentry: path does not exist: {args.path}", file=sys.stderr)
        return EXIT_USAGE

    report = inventory_report(args.path)
    report.update(
        {
            "tool": "QuantaSentry",
            "mode": "static-cryptographic-inventory",
            "schema_version": 1,
            "standard_references": ["FIPS 203", "FIPS 204", "FIPS 205"],
            "notice": (
                "Inventory hints are not a compliance or quantum-safety determination. "
                "A detected algorithm name does not prove a live cryptographic use."
            ),
        }
    )
    out = json.dumps(report, indent=2)
    if args.output:
        try:
            args.output.write_text(out + "\n", encoding="utf-8")
        except OSError as exc:
            print(
                f"quanta-sentry: cannot write report to {args.output}: {exc.strerror or exc}",
                file=sys.stderr,
            )
            return EXIT_INVALID_INPUT
    print(out)

    if args.fail_on_findings and report["findings"]:
        return EXIT_INVALID_INPUT
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
