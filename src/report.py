"""Console reporting for rule validation and detection test results."""

from __future__ import annotations

from typing import Dict, Iterable, List, Sequence, Tuple

__all__ = ["render_results", "render_coverage", "render_summary"]

TICK = "PASS"
CROSS = "FAIL"


def _column_widths(rows: Sequence[Sequence[str]]) -> List[int]:
    if not rows:
        return []
    return [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]


def _render_table(header: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    all_rows = [list(header)] + [list(r) for r in rows]
    widths = _column_widths(all_rows)
    divider = "-+-".join("-" * w for w in widths)

    lines = [" | ".join(cell.ljust(w) for cell, w in zip(header, widths)), divider]
    lines += [" | ".join(cell.ljust(w) for cell, w in zip(row, widths)) for row in rows]
    return "\n".join(lines)


def render_results(results: Iterable[Tuple[str, str, bool, str]]) -> str:
    """results: (rule title, case name, passed, detail)."""
    rows = [
        [title, case, TICK if passed else CROSS, detail]
        for title, case, passed, detail in results
    ]
    if not rows:
        return "No test cases found."
    return _render_table(["RULE", "TEST CASE", "RESULT", "DETAIL"], rows)


def render_coverage(coverage: Dict[str, List[str]]) -> str:
    """coverage: ATT&CK technique -> rule titles covering it."""
    if not coverage:
        return "No ATT&CK techniques tagged."
    rows = [[technique, str(len(titles)), ", ".join(titles)] for technique, titles in sorted(coverage.items())]
    return _render_table(["ATT&CK", "RULES", "COVERED BY"], rows)


def render_summary(total: int, passed: int, invalid: int) -> str:
    failed = total - passed
    status = "ALL CHECKS PASSED" if failed == 0 and invalid == 0 else "CHECKS FAILED"
    return (
        f"\n{status}\n"
        f"  rules with schema errors : {invalid}\n"
        f"  detection tests run      : {total}\n"
        f"  detection tests passed   : {passed}\n"
        f"  detection tests failed   : {failed}"
    )
