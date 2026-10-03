"""Acceptance #13: only agent.py / judge.py / run.py (and tests) may import langchain."""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "mitre_mapper"
ALLOWED = {"agent.py", "judge.py", "run.py"}


def _imports(path: Path) -> set[str]:
    out: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            out |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            out.add(node.module)
    return out


def test_langchain_only_in_allowed_modules():
    offenders = [
        p.name
        for p in sorted(SRC.glob("*.py"))
        if p.name not in ALLOWED
        and any(m.split(".")[0] in {"langchain", "langchain_core", "langgraph"} for m in _imports(p))
    ]
    assert offenders == []


def test_scan_sees_the_allowed_modules():
    assert any(m.startswith("langchain") for m in _imports(SRC / "agent.py"))
