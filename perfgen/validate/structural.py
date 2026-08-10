"""Structural validation of an emitted `.jmx`.

Structural only: the file parses, `hashTree` elements pair correctly, and every `${var}` referenced
has a producing extractor or a defined variable. This does not check that the script is a good
test — it checks that JMeter will open it and that no reference dangles.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from lxml import etree

# ${name} and ${__P(name,default)} / ${__env(NAME)} function calls.
_VAR_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_PROP_REF = re.compile(r"\$\{__P\(([A-Za-z_][A-Za-z0-9_]*)\s*(,[^)]*)?\)\}")
_ENV_REF = re.compile(r"\$\{__(?:env|groovy)\([^}]*\)\}")
_UNRESOLVED_PLACEHOLDER = re.compile(r"(?<!\$)\{([A-Za-z_][A-Za-z0-9_]*)\}")

# Functions JMeter does not ship with. An unrecognised function is not an error in JMeter - it is
# passed through as literal text - so a script using one fails silently at run time.
_NON_CORE_FUNCTIONS = {
    "__env": (
        "__env is not a core JMeter function (it ships with the jpgc Custom Functions plugin). "
        "JMeter will send the literal text instead of the value. Use "
        "${__groovy(System.getenv('NAME'))}."
    ),
}

# Elements whose presence means a variable is being produced.
_EXTRACTOR_REFNAME = {
    "JSONPostProcessor": "JSONPostProcessor.referenceNames",
    "RegexExtractor": "RegexExtractor.refname",
    "BoundaryExtractor": "BoundaryExtractor.refname",
    "XPath2Extractor": "XPathExtractor.refname",
}


@dataclass
class ValidationReport:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def __str__(self) -> str:
        if self.ok and not self.warnings:
            return "Structural validation passed."
        lines = []
        for error in self.errors:
            lines.append(f"  [ERROR]   {error}")
        for warning in self.warnings:
            lines.append(f"  [warning] {warning}")
        return "\n".join(lines)


def validate_file(path: str | Path) -> ValidationReport:
    data = Path(path).read_bytes()
    return validate_xml(data)


def validate_xml(data: bytes) -> ValidationReport:
    report = ValidationReport()
    try:
        root = etree.fromstring(data)
    except etree.XMLSyntaxError as exc:
        report.errors.append(f"file does not parse as XML: {exc}")
        return report

    if root.tag != "jmeterTestPlan":
        report.errors.append(f"root element is {root.tag!r}, expected 'jmeterTestPlan'")
        return report

    _check_pairing(root, report)
    _check_references(root, report)
    _check_functions(root, report)
    return report


def _check_functions(root: etree._Element, report: ValidationReport) -> None:
    """Catch functions stock JMeter cannot resolve, which it would emit as literal text."""
    for element in root.iter():
        if not isinstance(element.tag, str) or not element.text:
            continue
        for function, explanation in _NON_CORE_FUNCTIONS.items():
            if f"${{{function}(" in element.text:
                report.errors.append(f"{explanation} Found in {_locate(element)}.")


def _check_pairing(root: etree._Element, report: ValidationReport) -> None:
    """Inside every hashTree, children must alternate element, hashTree, element, hashTree."""
    top_level = [child for child in root if isinstance(child.tag, str)]
    if len(top_level) != 1 or top_level[0].tag != "hashTree":
        report.errors.append(
            f"jmeterTestPlan must contain exactly one hashTree, found "
            f"{[c.tag for c in top_level]}"
        )
        return

    for hash_tree in root.iter("hashTree"):
        children = [child for child in hash_tree if isinstance(child.tag, str)]
        if len(children) % 2 != 0:
            report.errors.append(
                f"hashTree has {len(children)} children - elements must be followed by a paired "
                f"hashTree, so the count is always even. Children: {[c.tag for c in children]}"
            )
            continue
        for index in range(0, len(children), 2):
            element, pair = children[index], children[index + 1]
            if element.tag == "hashTree":
                report.errors.append(
                    f"unexpected hashTree in element position at index {index} "
                    f"(testname={element.get('testname')!r})"
                )
            if pair.tag != "hashTree":
                report.errors.append(
                    f"element {element.tag!r} (testname={element.get('testname')!r}) is not "
                    f"followed by a hashTree; found {pair.tag!r}"
                )


def _check_references(root: etree._Element, report: ValidationReport) -> None:
    produced = _produced_variables(root)
    properties = _referenced_properties(root)

    for element in root.iter():
        if not isinstance(element.tag, str) or element.text is None:
            continue
        text = element.text
        # Property and env references resolve at run time, not from an extractor.
        stripped = _PROP_REF.sub("", _ENV_REF.sub("", text))
        for match in _VAR_REF.finditer(stripped):
            name = match.group(1)
            if name.startswith("__"):
                continue
            if name not in produced:
                report.errors.append(
                    f"${{{name}}} is referenced but nothing produces it "
                    f"(in {_locate(element)})"
                )
        for match in _UNRESOLVED_PLACEHOLDER.finditer(text):
            report.errors.append(
                f"unresolved placeholder {{{match.group(1)}}} left in the output: no extractor "
                f"produces {match.group(1)!r}"
            )

    for name in sorted(properties):
        # A property with an inline default always resolves, so it needs no producer. One without
        # a default resolves to the literal string "${__P(name)}" if nothing supplies it, which
        # fails at run time in a way that is hard to read - so flag it.
        if name not in produced:
            report.warnings.append(
                f"${{__P({name})}} is read with no default and no extractor publishes it. "
                f"It must be supplied by a property file or a -J flag at run time."
            )


def _locate(element: etree._Element) -> str:
    """Name the enclosing element, so a dangling reference can be found in the tree."""
    parent = element.getparent()
    if parent is not None and parent.get("testname"):
        return f"{parent.tag} {parent.get('testname')!r}"
    return element.tag


def _produced_variables(root: etree._Element) -> set[str]:
    """Variables produced by extractors, UDVs, or published to properties."""
    produced: set[str] = set()

    for tag, prop_name in _EXTRACTOR_REFNAME.items():
        for element in root.iter(tag):
            for prop in element.findall(f".//stringProp[@name='{prop_name}']"):
                if prop.text:
                    produced.update(part.strip() for part in prop.text.split(";") if part.strip())

    # User Defined Variables
    for arguments in root.iter("Arguments"):
        for prop in arguments.findall(".//stringProp[@name='Argument.name']"):
            if prop.text:
                produced.add(prop.text.strip())

    # props.put("name", ...) inside a JSR223 post-processor
    for element in root.iter("JSR223PostProcessor"):
        for prop in element.findall(".//stringProp[@name='script']"):
            if prop.text:
                produced.update(re.findall(r'props\.put\(\s*"([^"]+)"', prop.text))

    return produced


def _referenced_properties(root: etree._Element) -> set[str]:
    """Property names read *without* an inline default — those are the ones that can dangle."""
    names: set[str] = set()
    for element in root.iter():
        if isinstance(element.tag, str) and element.text:
            for name, default in _PROP_REF.findall(element.text):
                if not default:
                    names.add(name)
    return names
