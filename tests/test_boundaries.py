"""The tool must not import its own test scaffolding.

`tests/stubs/` holds a stub identity provider written to gate M7. It is test infrastructure, and
the moment anything under `perfgen/` reaches for it, the tool has a dependency on its own tests -
which breaks a real installation, where `tests/` is not shipped at all.

Asserted mechanically rather than left as a convention, because a convention holds right up until
someone is in a hurry. The reverse direction, tests importing perfgen, is the whole point of a test
suite and is unaffected.
"""

from __future__ import annotations

import ast
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent / "perfgen"


def imported_modules(source: Path) -> set[str]:
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
    return found


def test_nothing_in_perfgen_imports_the_test_suite():
    offenders: list[str] = []
    for source in sorted(PACKAGE.rglob("*.py")):
        for module in imported_modules(source):
            if module == "tests" or module.startswith("tests."):
                offenders.append(f"{source.relative_to(PACKAGE.parent)} imports {module}")

    assert not offenders, "the package imports its own test scaffolding:\n  " + "\n  ".join(
        offenders
    )


def test_the_check_would_notice_an_offender(tmp_path):
    """A guard nobody has seen fail is a guard nobody knows works."""
    offender = tmp_path / "leaky.py"
    offender.write_text("from tests.stubs.oidc_provider import StubProvider\n", encoding="utf-8")

    assert "tests.stubs.oidc_provider" in imported_modules(offender)
