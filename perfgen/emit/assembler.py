"""Tree assembly with structurally guaranteed `hashTree` pairing.

A `.jmx` is deeply nested XML where every element is followed by a sibling `hashTree` holding its
children. One mispaired tag produces a file JMeter silently refuses to open, so pairing is never a
template's responsibility: templates render a single element with no children, and this module is
the only thing that writes `hashTree` at all. There is no way to express an unpaired tree with this
API.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from lxml import etree

TEMPLATE_DIR = Path(__file__).parent / "templates"

_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=True,  # values are user data; XML-escape them
    undefined=StrictUndefined,  # a missing template variable is a bug, not an empty string
    trim_blocks=True,
    lstrip_blocks=True,
    keep_trailing_newline=False,
)


def render_element(template: str, /, **context: object) -> etree._Element:
    """Render one JMeter element from its template. The result has no children and no hashTree."""
    xml = _env.get_template(f"{template}.xml.j2").render(**context)
    try:
        return etree.fromstring(xml.encode("utf-8"))
    except etree.XMLSyntaxError as exc:  # pragma: no cover - template bug, not input data
        raise ValueError(f"template {template!r} produced invalid XML: {exc}\n{xml}") from exc


@dataclass
class Node:
    """A JMeter element plus the children that belong in its paired `hashTree`."""

    element: etree._Element
    children: list[Node] = field(default_factory=list)

    def add(self, node: Node) -> Node:
        """Append a child and return it, so callers can keep nesting."""
        self.children.append(node)
        return node

    def add_element(self, template: str, /, **context: object) -> Node:
        """Render a template and append it as a child in one step."""
        return self.add(Node(render_element(template, **context)))

    def extend(self, nodes: list[Node]) -> None:
        self.children.extend(nodes)

    @property
    def testname(self) -> str:
        return self.element.get("testname", "")


def node(template: str, /, **context: object) -> Node:
    """Build a standalone Node from a template."""
    return Node(render_element(template, **context))


def build_document(root_children: list[Node], jmeter_version: str) -> etree._ElementTree:
    """Assemble the `jmeterTestPlan` document around a list of top-level nodes."""
    plan = etree.Element("jmeterTestPlan")
    plan.set("version", "1.2")
    plan.set("properties", "5.0")
    plan.set("jmeter", jmeter_version)

    root_hash_tree = etree.SubElement(plan, "hashTree")
    for child in root_children:
        _append(root_hash_tree, child)

    etree.indent(plan, space="  ")
    return etree.ElementTree(plan)


def _append(parent_hash_tree: etree._Element, node_: Node) -> None:
    """Append an element and its paired hashTree. These two always travel together."""
    parent_hash_tree.append(node_.element)
    hash_tree = etree.SubElement(parent_hash_tree, "hashTree")
    for child in node_.children:
        _append(hash_tree, child)


def to_xml(tree: etree._ElementTree) -> bytes:
    return etree.tostring(tree, xml_declaration=True, encoding="UTF-8", pretty_print=False)


def comment(text: str) -> etree._Element:
    """An XML comment, used to carry warnings into the JMX where a tester will see them."""
    return etree.Comment(f" {text} ")
