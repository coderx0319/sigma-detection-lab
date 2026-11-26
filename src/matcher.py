"""Evaluate Sigma detection logic against a single log event.

Implements the subset of the Sigma specification needed to test the rules in
this repository: field modifiers, wildcards, list-as-OR semantics, and the
condition grammar (and/or/not, parentheses, "1 of"/"all of" with wildcards).

Sigma string matching is case-insensitive by default, which this follows.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any, Dict, Iterable, List, Sequence

__all__ = ["evaluate", "SigmaConditionError"]


class SigmaConditionError(ValueError):
    """Raised when a rule's condition cannot be parsed."""


# --------------------------------------------------------------------------
# Value matching
# --------------------------------------------------------------------------

def _as_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _wildcard_match(haystack: str, pattern: str) -> bool:
    """Case-insensitive glob match. Sigma uses * and ? as wildcards."""
    return fnmatch.fnmatch(haystack.lower(), pattern.lower())


def _match_single(event_value: Any, pattern: Any, modifiers: Sequence[str]) -> bool:
    # Sigma uses a null value to mean "field is absent or empty".
    if pattern is None:
        return event_value in (None, "")

    if event_value is None:
        return False

    if "re" in modifiers:
        return re.search(str(pattern), _as_text(event_value), re.IGNORECASE) is not None

    text = _as_text(event_value).lower()
    needle = _as_text(pattern).lower()

    if "contains" in modifiers:
        return needle in text
    if "startswith" in modifiers:
        return text.startswith(needle)
    if "endswith" in modifiers:
        return text.endswith(needle)

    # No modifier: exact match, but honour embedded wildcards.
    if "*" in needle or "?" in needle:
        return _wildcard_match(text, needle)
    return text == needle


def _match_field(event: Dict[str, Any], key: str, expected: Any) -> bool:
    """Match one `field|modifier: value` entry from a detection block."""
    field, *modifiers = key.split("|")
    modifiers = [m.lower() for m in modifiers]

    # `field` may be absent from the event entirely.
    event_value = event.get(field)

    # A list of values is an OR, unless the `all` modifier makes it an AND.
    if isinstance(expected, list):
        results = (_match_single(event_value, item, modifiers) for item in expected)
        return all(results) if "all" in modifiers else any(results)

    return _match_single(event_value, expected, modifiers)


def _match_block(event: Dict[str, Any], block: Any) -> bool:
    """A detection block: a map of fields (AND), or a list of maps (OR)."""
    if isinstance(block, list):
        return any(_match_block(event, item) for item in block)

    if isinstance(block, dict):
        return all(_match_field(event, key, value) for key, value in block.items())

    # A bare keyword block: search every value in the event.
    needle = _as_text(block).lower()
    return any(needle in _as_text(v).lower() for v in event.values())


# --------------------------------------------------------------------------
# Condition parsing
# --------------------------------------------------------------------------

# Selection names may contain a trailing wildcard ("selection_*"), so the
# token pattern must not require a word boundary after it.
_TOKEN_RE = re.compile(r"\(|\)|[\w*]+")


def _tokenise(condition: str) -> List[str]:
    return _TOKEN_RE.findall(condition)


class _Parser:
    """Recursive-descent parser for Sigma condition expressions."""

    def __init__(
        self,
        tokens: List[str],
        selections: Dict[str, Any],
        event: Dict[str, Any],
    ) -> None:
        self.tokens = tokens
        self.pos = 0
        self.selections = selections
        self.event = event

    # -- token helpers -----------------------------------------------------
    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        token = self._peek()
        if token is None:
            raise SigmaConditionError("unexpected end of condition")
        self.pos += 1
        return token

    def _accept(self, token: str) -> bool:
        if (self._peek() or "").lower() == token:
            self.pos += 1
            return True
        return False

    # -- grammar -----------------------------------------------------------
    def parse(self, event: Dict[str, Any]) -> bool:
        result = self._parse_or(event)
        if self._peek() is not None:
            raise SigmaConditionError(f"trailing tokens from {self._peek()!r}")
        return result

    def _parse_or(self, event: Dict[str, Any]) -> bool:
        result = self._parse_and(event)
        while self._accept("or"):
            # Evaluate both sides: no short-circuit, so parsing stays complete.
            result = self._parse_and(event) or result
        return result

    def _parse_and(self, event: Dict[str, Any]) -> bool:
        result = self._parse_unary(event)
        while self._accept("and"):
            result = self._parse_unary(event) and result
        return result

    def _parse_unary(self, event: Dict[str, Any]) -> bool:
        if self._accept("not"):
            return not self._parse_unary(event)
        return self._parse_primary(event)

    def _parse_primary(self, event: Dict[str, Any]) -> bool:
        if self._accept("("):
            result = self._parse_or(event)
            if not self._accept(")"):
                raise SigmaConditionError("missing closing parenthesis")
            return result

        token = self._next()
        lowered = token.lower()

        # Quantifiers: "1 of selection*", "all of them".
        if lowered in {"1", "any", "all"}:
            if not self._accept("of"):
                raise SigmaConditionError(f"expected 'of' after {token!r}")
            target = self._next()
            matches = self._resolve_group(target)
            return all(matches) if lowered == "all" else any(matches)

        return self._lookup(token, event)

    # -- selection resolution ---------------------------------------------
    def _lookup(self, name: str, event: Dict[str, Any]) -> bool:
        if name not in self.selections:
            raise SigmaConditionError(f"condition refers to unknown selection {name!r}")
        return _match_block(event, self.selections[name])

    def _resolve_group(self, target: str) -> List[bool]:
        if target.lower() == "them":
            names: Iterable[str] = self.selections
        else:
            names = [n for n in self.selections if fnmatch.fnmatch(n, target)]
            if not names:
                raise SigmaConditionError(f"no selections match {target!r}")
        return [_match_block(self.event, self.selections[n]) for n in names]


def evaluate(rule: Dict[str, Any], event: Dict[str, Any]) -> bool:
    """Return True when `event` triggers `rule`.

    `rule` is a parsed Sigma rule (as loaded from YAML); `event` is a flat
    mapping of field names to values.
    """
    detection = rule.get("detection")
    if not isinstance(detection, dict):
        raise SigmaConditionError("rule has no detection block")

    condition = detection.get("condition")
    if not isinstance(condition, str):
        raise SigmaConditionError("rule has no string condition")

    selections = {k: v for k, v in detection.items() if k != "condition"}
    if not selections:
        raise SigmaConditionError("rule has no selections")

    return _Parser(_tokenise(condition), selections, event).parse(event)
