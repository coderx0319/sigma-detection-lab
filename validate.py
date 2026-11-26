#!/usr/bin/env python3
"""Validate every Sigma rule in this repository and run its detection tests.

A rule that does not fire on the behaviour it claims to detect is worse than
no rule at all, because it creates the appearance of coverage. This harness
asserts both halves: the rule fires on true positives, and stays quiet on the
benign events that look similar.

    python validate.py                 # validate + test everything
    python validate.py --coverage      # also print ATT&CK coverage
    python validate.py --rule lsass    # only rules whose path matches
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).parent))

from src.loader import load_rules
from src.matcher import SigmaConditionError, evaluate
from src.report import render_coverage, render_results, render_summary

ROOT = Path(__file__).parent
RULES_DIR = ROOT / "rules"
CASES_DIR = ROOT / "tests" / "testcases"


def run(rule_filter: str | None = None, show_coverage: bool = False) -> int:
    rules = load_rules(RULES_DIR)
    if rule_filter:
        rules = [r for r in rules if rule_filter.lower() in str(r.path).lower()]

    if not rules:
        print("No rules found.", file=sys.stderr)
        return 1

    invalid = 0
    for rule in rules:
        if not rule.is_valid:
            invalid += 1
            print(f"[SCHEMA] {rule.path.relative_to(ROOT)}")
            for error in rule.errors:
                print(f"         - {error}")

    results: List[Tuple[str, str, bool, str]] = []
    coverage: Dict[str, List[str]] = defaultdict(list)

    for rule in rules:
        for technique in rule.techniques:
            coverage[technique].append(rule.title)

        case_file = CASES_DIR / f"{rule.path.stem}.json"
        if not case_file.exists():
            results.append((rule.title, "-", False, "no test cases defined"))
            continue

        payload = json.loads(case_file.read_text(encoding="utf-8"))
        for case in payload.get("cases", []):
            expected = bool(case["expect"])
            try:
                actual = evaluate(rule.data, case["event"])
            except SigmaConditionError as exc:
                results.append((rule.title, case["name"], False, f"condition error: {exc}"))
                continue

            if actual == expected:
                detail = "fired as expected" if expected else "correctly stayed quiet"
            elif expected:
                detail = "MISSED - rule did not fire on true positive"
            else:
                detail = "FALSE POSITIVE - rule fired on benign event"

            results.append((rule.title, case["name"], actual == expected, detail))

    print()
    print(render_results(results))

    if show_coverage:
        print()
        print(render_coverage(dict(coverage)))

    passed = sum(1 for *_, ok, _ in ((r[0], r[1], r[2], r[3]) for r in results) if ok)
    print(render_summary(total=len(results), passed=passed, invalid=invalid))

    return 0 if passed == len(results) and invalid == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rule", help="only rules whose path contains this string")
    parser.add_argument("--coverage", action="store_true", help="print ATT&CK coverage table")
    args = parser.parse_args()
    return run(rule_filter=args.rule, show_coverage=args.coverage)


if __name__ == "__main__":
    raise SystemExit(main())
