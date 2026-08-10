"""Golden-file tests, compared structurally rather than by string equality.

Element class names and structure differ across JMeter releases, so the emitter is
version-sensitive. These tests exist so that a version bump surfaces as a failing test rather than
as scripts that silently will not open.

The comparison walks the tree and compares element tags, testnames and properties. String equality
would fail on whitespace and attribute order without telling you anything useful.

Regenerate with:  pytest --golden-update
"""

from __future__ import annotations

from pathlib import Path

import pytest
from lxml import etree

from perfgen.emit.emitter import build_tree

GOLDEN_DIR = Path(__file__).parent / "fixtures" / "golden"
PINNED_JMETER_VERSION = "5.6.3"


def _canonical(element: etree._Element, depth: int = 0) -> list[str]:
    """A structural fingerprint: tag, testname, and every named property with its value."""
    lines: list[str] = []
    indent = "  " * depth
    if not isinstance(element.tag, str):
        return lines

    testname = element.get("testname")
    header = f"{indent}{element.tag}"
    if testname:
        header += f" [{testname}]"
    for attr in ("guiclass", "testclass"):
        if element.get(attr):
            header += f" {attr}={element.get(attr)}"
    lines.append(header)

    for child in element:
        if not isinstance(child.tag, str):
            continue
        if child.tag in {"stringProp", "boolProp", "intProp", "longProp", "doubleProp"}:
            lines.append(f"{indent}  {child.tag}:{child.get('name')}={child.text or ''}")
        elif child.tag in {"elementProp", "collectionProp"}:
            lines.append(f"{indent}  {child.tag}:{child.get('name')}")
            lines.extend(_canonical(child, depth + 2))
        else:
            lines.extend(_canonical(child, depth + 1))
    return lines


def canonical_form(xml: bytes) -> str:
    root = etree.fromstring(xml)
    lines: list[str] = [
        f"jmeterTestPlan version={root.get('version')} "
        f"properties={root.get('properties')} jmeter={root.get('jmeter')}"
    ]

    def walk(hash_tree: etree._Element, depth: int) -> None:
        children = [c for c in hash_tree if isinstance(c.tag, str)]
        for index in range(0, len(children), 2):
            element, pair = children[index], children[index + 1]
            lines.extend(_canonical(element, depth))
            walk(pair, depth + 1)

    walk(next(c for c in root if c.tag == "hashTree"), 1)
    return "\n".join(lines) + "\n"


@pytest.mark.parametrize("fixture_name", ["simple_flow", "auth_shared_token"])
def test_golden_structure(fixture_name, request, pytestconfig):
    ir = request.getfixturevalue(fixture_name)
    xml, _ = build_tree(ir, PINNED_JMETER_VERSION)
    actual = canonical_form(xml)

    golden_path = GOLDEN_DIR / f"{fixture_name}.txt"
    if pytestconfig.getoption("--golden-update") or not golden_path.exists():
        golden_path.parent.mkdir(parents=True, exist_ok=True)
        golden_path.write_text(actual, encoding="utf-8")
        pytest.skip(f"golden file written: {golden_path.name}")

    expected = golden_path.read_text(encoding="utf-8")
    assert actual == expected, (
        f"emitted structure no longer matches {golden_path.name}. If this is an intended change "
        f"(including a JMeter version bump), review the diff and rerun with --golden-update."
    )


def test_golden_files_pin_the_configured_jmeter_version():
    """The version is in the fingerprint, so an upgrade cannot pass silently."""
    for path in GOLDEN_DIR.glob("*.txt"):
        first_line = path.read_text(encoding="utf-8").splitlines()[0]
        assert f"jmeter={PINNED_JMETER_VERSION}" in first_line, (
            f"{path.name} was generated for a different JMeter version"
        )
