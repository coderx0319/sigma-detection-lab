"""Pytest wrapper around the detection test cases.

Running `pytest` gives one test per rule/case pair, so a broken rule points
straight at the case that broke.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.loader import load_rules, validate_rule  # noqa: E402
from src.matcher import evaluate  # noqa: E402

RULES = load_rules(ROOT / "rules")
CASES_DIR = ROOT / "tests" / "testcases"


def _case_params():
    for rule in RULES:
        case_file = CASES_DIR / f"{rule.path.stem}.json"
        if not case_file.exists():
            continue
        payload = json.loads(case_file.read_text(encoding="utf-8"))
        for case in payload.get("cases", []):
            yield pytest.param(rule, case, id=f"{rule.path.stem}::{case['name']}")


@pytest.mark.parametrize("rule", RULES, ids=[r.path.stem for r in RULES])
def test_rule_schema_is_valid(rule):
    assert validate_rule(rule.data) == [], f"{rule.path}: {rule.errors}"


@pytest.mark.parametrize("rule", RULES, ids=[r.path.stem for r in RULES])
def test_rule_has_attack_tags(rule):
    assert rule.techniques, f"{rule.path} has no attack.tXXXX tag"


@pytest.mark.parametrize("rule", RULES, ids=[r.path.stem for r in RULES])
def test_rule_has_test_cases(rule):
    assert (CASES_DIR / f"{rule.path.stem}.json").exists(), f"{rule.path.stem} has no test cases"


@pytest.mark.parametrize("rule,case", list(_case_params()))
def test_detection_behaviour(rule, case):
    actual = evaluate(rule.data, case["event"])
    assert actual == bool(case["expect"]), (
        f"{rule.title!r} on case {case['name']!r}: expected {case['expect']}, got {actual}"
    )
