#!/usr/bin/env python3
"""Run pytest with a baseline-failures ratchet gate."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

FAILED_PATTERN = re.compile(r"^FAILED\s+(\S+)")


def read_baseline(path: Path) -> set[str]:
    """Read baseline node ids from a newline-separated text file."""
    if not path.exists():
        raise FileNotFoundError(f"Baseline file not found: {path}")
    entries = {
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    if not entries:
        raise ValueError(f"Baseline file is empty: {path}")
    return entries


def parse_failures(output: str) -> set[str]:
    """Parse failed pytest node ids from summary lines."""
    failures: set[str] = set()
    for line in output.splitlines():
        match = FAILED_PATTERN.match(line.strip())
        if match:
            failures.add(match.group(1))
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baseline-file",
        default="tests/ratchet_baseline_failures.txt",
        help="Path to baseline failures file.",
    )
    parser.add_argument(
        "pytest_args",
        nargs=argparse.REMAINDER,
        help="Extra pytest arguments. Example: -- tests/test_signin.py -k request",
    )
    args = parser.parse_args()

    baseline = read_baseline(Path(args.baseline_file))
    pytest_args = list(args.pytest_args)
    if pytest_args[:1] == ["--"]:
        pytest_args = pytest_args[1:]

    cmd = [
        "uv",
        "run",
        "--extra",
        "test",
        "pytest",
        "-q",
        "--color=no",
        "--disable-warnings",
        *pytest_args,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)

    if proc.stdout:
        sys.stdout.write(proc.stdout)
    if proc.stderr:
        sys.stderr.write(proc.stderr)

    output = f"{proc.stdout}\n{proc.stderr}"
    current_failures = parse_failures(output)

    new_failures = sorted(current_failures - baseline)
    fixed_failures = sorted(baseline - current_failures)

    print(
        f"\n[ratchet] baseline={len(baseline)} current={len(current_failures)}",
        file=sys.stderr,
    )
    if fixed_failures:
        print(f"[ratchet] fixed_since_baseline={len(fixed_failures)}", file=sys.stderr)

    exit_code = 0

    if new_failures:
        print(f"[ratchet] new_failures={len(new_failures)}", file=sys.stderr)
        for failure in new_failures:
            print(f"  + {failure}", file=sys.stderr)
        exit_code = 1

    if len(current_failures) > len(baseline):
        print(
            "[ratchet] failure count regressed above baseline",
            file=sys.stderr,
        )
        exit_code = 1

    if proc.returncode not in (0, 1):
        print(
            f"[ratchet] pytest exited unexpectedly with code {proc.returncode}",
            file=sys.stderr,
        )
        exit_code = 1

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
