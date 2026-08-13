"""Turning a response body into `(location, value)` leaves, whatever format it arrived in.

The location is not a label. `engine._expression_for` turns it into the extractor expression that
ends up in the generated script, so whatever this module produces has to be valid as an expression
against the same document:

    JSON  $.results[0].id          -> JSONPostProcessor
    XML   /order/items/item[1]/id  -> XPath2Extractor
    form  clientRef                -> RegexExtractor, expression built at emit time

**Content-Type is a hint, not an instruction.** It selects which parser to try first; every parser
is then tried in a fixed fallback order. Servers mislabel bodies routinely, and a JSON response
served as `text/plain` was indexed correctly before this module existed - losing that to a tidier
dispatch rule would be a regression disguised as a cleanup.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import parse_qsl

from lxml import etree

from perfgen.probe.redact import looks_form_encoded

BodyFormat = Literal["json", "xml", "form"]

# Fallback order. JSON first because it is the most common and the strictest; form last because it
# is the loosest and will happily "parse" text that is nothing of the kind.
FALLBACK_ORDER: tuple[BodyFormat, ...] = ("json", "xml", "form")

_JSON_TYPES = re.compile(r"(^|/|\+)json($|;)", re.I)
_XML_TYPES = re.compile(r"(^|/|\+)xml($|;)", re.I)
_FORM_TYPES = re.compile(r"x-www-form-urlencoded", re.I)


@dataclass
class ParsedBody:
    format: BodyFormat
    leaves: list[tuple[str, str]] = field(default_factory=list)
    declared_type: str = ""
    mismatch: str | None = None
    """Set when the parser that worked is not the one the Content-Type advertised."""


def preferred_format(content_type: str) -> BodyFormat | None:
    """Which parser the declared Content-Type points at, if any."""
    if not content_type:
        return None
    if _JSON_TYPES.search(content_type):
        return "json"
    if _XML_TYPES.search(content_type):
        return "xml"
    if _FORM_TYPES.search(content_type):
        return "form"
    return None


def parse_body(body: str, content_type: str = "") -> ParsedBody | None:
    """Index a response body, or return None if no parser could read it."""
    if not body or not body.strip():
        return None

    preferred = preferred_format(content_type)
    order = [preferred, *[f for f in FALLBACK_ORDER if f != preferred]] if preferred else list(
        FALLBACK_ORDER
    )

    for fmt in order:
        leaves = _PARSERS[fmt](body, content_type)
        if leaves is None:
            continue
        mismatch = None
        if preferred is not None and fmt != preferred:
            mismatch = (
                f"declared {content_type.split(';')[0].strip()} but the body parsed as {fmt}"
            )
        return ParsedBody(
            format=fmt, leaves=leaves, declared_type=content_type, mismatch=mismatch
        )
    return None


# --------------------------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------------------------


def _parse_json(body: str, content_type: str = "") -> list[tuple[str, str]] | None:
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return None
    leaves: list[tuple[str, str]] = []
    _walk_json(payload, "$", leaves)
    return leaves


def _walk_json(node: Any, path: str, out: list[tuple[str, str]]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            _walk_json(value, f"{path}.{key}", out)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _walk_json(value, f"{path}[{index}]", out)
    elif isinstance(node, bool) or node is None:
        return  # never an identifier
    elif isinstance(node, str | int | float):
        out.append((path, str(node)))


# --------------------------------------------------------------------------------------------
# XML
# --------------------------------------------------------------------------------------------


def _xml_parser() -> etree.XMLParser:
    """Hardened: these bodies come off the network from a service we do not control.

    Entity resolution is how XXE and billion-laughs work, and lxml does not disable all of it by
    default. Nothing here needs entities, DTDs or network access to resolve a document.
    """
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        huge_tree=False,
        load_dtd=False,
        dtd_validation=False,
        recover=False,
    )


def _parse_xml(body: str, content_type: str = "") -> list[tuple[str, str]] | None:
    try:
        root = etree.fromstring(body.encode("utf-8"), parser=_xml_parser())
    except (etree.XMLSyntaxError, ValueError):
        return None
    if root is None or not isinstance(root.tag, str):
        return None

    # A namespaced document cannot be addressed by plain element names, and binding prefixes in the
    # extractor is one more thing to keep in step. local-name() is verbose but self-contained.
    namespaced = any(isinstance(el.tag, str) and el.tag.startswith("{") for el in root.iter())

    leaves: list[tuple[str, str]] = []
    _walk_xml(root, f"/{_segment(root.tag, namespaced)}", leaves, namespaced)
    return leaves


def _local_name(tag: str) -> str:
    return tag.split("}", 1)[1] if tag.startswith("{") else tag


def _segment(tag: str, namespaced: bool) -> str:
    name = _local_name(tag)
    return f"*[local-name()='{name}']" if namespaced else name


def _walk_xml(
    element: etree._Element, path: str, out: list[tuple[str, str]], namespaced: bool
) -> None:
    for name, value in element.attrib.items():
        if value and value.strip():
            attr = _local_name(str(name))
            selector = f"@*[local-name()='{attr}']" if str(name).startswith("{") else f"@{attr}"
            out.append((f"{path}/{selector}", value.strip()))

    children = [c for c in element if isinstance(c.tag, str)]
    if not children:
        text = (element.text or "").strip()
        if text:
            out.append((path, text))
        return

    # XPath positional predicates are 1-based, where the JSON walker's list indices are 0-based.
    # Same position in the document, different number; both are correct for their own language.
    totals = Counter(c.tag for c in children)
    seen: Counter[str] = Counter()
    for child in children:
        seen[child.tag] += 1
        segment = _segment(child.tag, namespaced)
        if totals[child.tag] > 1:
            segment += f"[{seen[child.tag]}]"
        _walk_xml(child, f"{path}/{segment}", out, namespaced)


# --------------------------------------------------------------------------------------------
# Form encoded
# --------------------------------------------------------------------------------------------


def _parse_form(body: str, content_type: str = "") -> list[tuple[str, str]] | None:
    """Only when the server says so, or the body is unambiguously key=value pairs.

    Left unguarded this parser succeeds on prose, HTML and anything else containing an `=`, which
    is why it is last in the fallback order and gated here.
    """
    declared = preferred_format(content_type) == "form"
    if not declared and not looks_form_encoded(body):
        return None

    try:
        pairs = parse_qsl(body, keep_blank_values=True)
    except ValueError:
        return None
    if not pairs:
        return None

    leaves: list[tuple[str, str]] = []
    seen: Counter[str] = Counter()
    for key, value in pairs:
        seen[key] += 1
        location = key if seen[key] == 1 else f"{key}[{seen[key]}]"
        if value:
            leaves.append((location, value))
    return leaves


_PARSERS = {"json": _parse_json, "xml": _parse_xml, "form": _parse_form}
