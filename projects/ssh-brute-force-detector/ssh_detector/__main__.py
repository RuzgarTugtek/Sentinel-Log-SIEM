"""Command-line interface for offline SSH authentication log analysis."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from .core import analyze_lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect bursts of failed SSH logins.")
    parser.add_argument("--log", type=Path, required=True, help="Path to auth.log/syslog")
    parser.add_argument("--threshold", type=int, default=5, help="Minimum failed attempts")
    parser.add_argument("--window-minutes", type=int, default=10, help="Sliding window")
    parser.add_argument("--year", type=int, default=datetime.now().year, help="Log year")
    parser.add_argument("--json", action="store_true", help="Print JSON findings")
    args = parser.parse_args(argv)

    if args.threshold < 1 or args.window_minutes < 1:
        parser.error("--threshold and --window-minutes must be positive")
    try:
        with args.log.open("r", encoding="utf-8", errors="replace") as log:
            findings = analyze_lines(
                log,
                threshold=args.threshold,
                window_minutes=args.window_minutes,
                year=args.year,
            )
    except OSError as exc:
        parser.error(f"cannot read log: {exc}")

    if args.json:
        print(json.dumps([asdict(finding) for finding in findings], indent=2))
    elif not findings:
        print("No suspicious failed-login bursts detected.")
    else:
        for finding in findings:
            print(
                f"{finding.ip}  |  {finding.attempts} attempts  |  "
                f"{finding.first_seen}  ->  {finding.last_seen}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
