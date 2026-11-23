"""Parser for Sigma-style detection conditions.

Supported grammar (keywords are case-insensitive)::

    expr       := and_expr ("or" and_expr)*
    and_expr   := not_expr ("and" not_expr)*
    not_expr   := "not" not_expr | atom
    atom       := "(" expr ")" | quantifier | NAME
    quantifier := ("1" | "any" | "all") "of" (PATTERN | "them")

NAME refers to a selection defined in the rule. PATTERN may use ``*`` as a
wildcard, for example ``1 of filter_*``. ``them`` means every selection whose
name does not start with an underscore.

Conditions are compiled once, when a rule is loaded, into plain Python
closures. Selections are evaluated lazily, so ``a and b`` never evaluates
``b`` when ``a`` is false.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

Lookup = Callable[[str], bool]
Condition = Callable[[Lookup], bool]

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")
_KEYWORDS = {"and", "or", "not", "of", "them", "all", "any"}


class ConditionError(ValueError):
    """Raised when a condition string cannot be parsed."""


def tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    text = text.strip()
    pos = 0
    while pos < len(text):
        match = _TOKEN.match(text, pos)
        if not match:
            raise ConditionError(f"invalid character near '{text[pos:pos + 12]}'")
        tokens.append(match.group(1))
        pos = match.end()
        while pos < len(text) and text[pos].isspace():
            pos += 1
    return tokens


@dataclass
class _Parser:
    tokens: list[str]
    names: Sequence[str]
    pos: int = 0

    def peek(self) -> str:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else ""

    def take(self, expected: str | None = None) -> str:
        if self.pos >= len(self.tokens):
            raise ConditionError("condition ends unexpectedly")
        token = self.tokens[self.pos]
        if expected is not None and token.lower() != expected:
            raise ConditionError(f"expected '{expected}' but found '{token}'")
        self.pos += 1
        return token

    def parse(self) -> Condition:
        if not self.tokens:
            raise ConditionError("condition is empty")
        node = self.or_expr()
        if self.pos < len(self.tokens):
            raise ConditionError(f"unexpected token '{self.peek()}'")
        return node

    def or_expr(self) -> Condition:
        parts = [self.and_expr()]
        while self.peek().lower() == "or":
            self.take()
            parts.append(self.and_expr())
        if len(parts) == 1:
            return parts[0]
        return lambda lookup: any(part(lookup) for part in parts)

    def and_expr(self) -> Condition:
        parts = [self.not_expr()]
        while self.peek().lower() == "and":
            self.take()
            parts.append(self.not_expr())
        if len(parts) == 1:
            return parts[0]
        return lambda lookup: all(part(lookup) for part in parts)

    def not_expr(self) -> Condition:
        if self.peek().lower() == "not":
            self.take()
            inner = self.not_expr()
            return lambda lookup: not inner(lookup)
        return self.atom()

    def atom(self) -> Condition:
        token = self.take()
        lowered = token.lower()
        if token == "(":
            inner = self.or_expr()
            self.take(")")
            return inner
        if lowered in {"1", "any", "all"} and self.peek().lower() == "of":
            self.take("of")
            matched = self._expand(self.take())
            if lowered == "all":
                return lambda lookup: all(lookup(name) for name in matched)
            return lambda lookup: any(lookup(name) for name in matched)
        if token == ")" or lowered in _KEYWORDS:
            raise ConditionError(f"unexpected '{token}'")
        if "*" in token:
            raise ConditionError(f"wildcard '{token}' is only allowed after '1 of' or 'all of'")
        if token not in self.names:
            raise ConditionError(f"condition refers to unknown selection '{token}'")
        return lambda lookup: lookup(token)

    def _expand(self, target: str) -> list[str]:
        if target.lower() == "them":
            matched = [n for n in self.names if not n.startswith("_")]
        else:
            matched = [n for n in self.names if fnmatch.fnmatchcase(n, target)]
        if not matched:
            raise ConditionError(f"'{target}' does not match any selection")
        return matched


def compile_condition(text: str, names: Iterable[str]) -> Condition:
    """Compile ``text`` into a callable that takes a selection lookup function."""
    return _Parser(tokenize(str(text)), list(names)).parse()
