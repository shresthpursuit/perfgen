"""Response body parsing: the `(location, value)` leaves every format reduces to.

The location is the part that matters. It becomes the extractor expression in the generated
script, so a location that is merely descriptive - rather than valid against the document it came
from - produces a script that runs and extracts nothing.
"""

from __future__ import annotations

import json

import pytest
from lxml import etree

from perfgen.correlate.bodies import parse_body, preferred_format

# --------------------------------------------------------------------------------------------
# JSON, unchanged from before this module existed
# --------------------------------------------------------------------------------------------


def test_json_locations_are_json_paths():
    parsed = parse_body(json.dumps({"results": [{"id": "X-1"}], "total": 1}), "application/json")

    assert parsed.format == "json"
    assert ("$.results[0].id", "X-1") in parsed.leaves


def test_json_booleans_and_nulls_are_not_leaves():
    parsed = parse_body(json.dumps({"ok": True, "missing": None, "ref": "R-1"}), "application/json")
    assert [loc for loc, _ in parsed.leaves] == ["$.ref"]


# --------------------------------------------------------------------------------------------
# XML locations must be valid XPath against the document they came from
# --------------------------------------------------------------------------------------------


def xpath_finds(document: str, location: str) -> list[str]:
    """Evaluate a produced location against the source document.

    This is the assertion that actually matters: a location that does not select its own value is
    a broken extractor expression, however plausible it looks.
    """
    tree = etree.fromstring(document.encode())
    return [
        (r if isinstance(r, str) else (r.text or "")).strip() for r in tree.xpath(location)
    ]


def test_nested_elements_produce_a_path():
    doc = "<order><ref>ORD-1</ref></order>"
    parsed = parse_body(doc, "application/xml")

    assert parsed.format == "xml"
    assert ("/order/ref", "ORD-1") in parsed.leaves
    assert xpath_finds(doc, "/order/ref") == ["ORD-1"]


def test_repeated_siblings_are_indexed_and_xpath_is_one_based():
    """JSON list indices start at 0; XPath predicates start at 1. Both correct, different."""
    doc = "<order><item><id>A</id></item><item><id>B</id></item></order>"
    parsed = parse_body(doc, "application/xml")
    locations = dict((loc, val) for loc, val in parsed.leaves)

    assert locations["/order/item[1]/id"] == "A"
    assert locations["/order/item[2]/id"] == "B"
    assert xpath_finds(doc, "/order/item[2]/id") == ["B"]


def test_a_single_child_gets_no_index():
    parsed = parse_body("<order><item><id>A</id></item></order>", "application/xml")
    assert any(loc == "/order/item/id" for loc, _ in parsed.leaves)


def test_attributes_are_addressable():
    doc = '<order><item id="ITEM-9"/></order>'
    parsed = parse_body(doc, "application/xml")

    assert ("/order/item/@id", "ITEM-9") in parsed.leaves
    assert xpath_finds(doc, "/order/item/@id") == ["ITEM-9"]


def test_a_namespaced_document_uses_local_name():
    """A plain path matches nothing when a default namespace is in play."""
    doc = '<order xmlns="http://example.com/ns"><ref>ORD-2</ref></order>'
    parsed = parse_body(doc, "application/xml")

    assert ("/*[local-name()='order']/*[local-name()='ref']", "ORD-2") in parsed.leaves
    assert xpath_finds(doc, "/order/ref") == [], "the naive path is exactly what does not work"
    assert xpath_finds(doc, "/*[local-name()='order']/*[local-name()='ref']") == ["ORD-2"]


def test_a_namespaced_document_with_prefixes():
    doc = '<s:order xmlns:s="http://example.com/ns"><s:ref>ORD-3</s:ref></s:order>'
    parsed = parse_body(doc, "application/xml")
    location = "/*[local-name()='order']/*[local-name()='ref']"

    assert (location, "ORD-3") in parsed.leaves
    assert xpath_finds(doc, location) == ["ORD-3"]


def test_namespaced_indices_still_work():
    doc = (
        '<order xmlns="http://x"><item><id>A</id></item><item><id>B</id></item></order>'
    )
    parsed = parse_body(doc, "application/xml")
    location = "/*[local-name()='order']/*[local-name()='item'][2]/*[local-name()='id']"

    assert (location, "B") in parsed.leaves
    assert xpath_finds(doc, location) == ["B"]


def test_whitespace_only_text_is_not_a_leaf():
    parsed = parse_body("<order>\n  <ref>  ORD-4  </ref>\n</order>", "application/xml")
    assert ("/order/ref", "ORD-4") in parsed.leaves
    assert not any(loc == "/order" for loc, _ in parsed.leaves)


# --------------------------------------------------------------------------------------------
# XML parsing is hardened - these bodies come off the network
# --------------------------------------------------------------------------------------------


def test_external_entities_are_not_resolved():
    """XXE: an entity pointing at a local file must not be expanded into a leaf."""
    doc = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        "<r><v>&xxe;</v></r>"
    )
    parsed = parse_body(doc, "application/xml")
    text = json.dumps(parsed.leaves if parsed else [])
    assert "root:" not in text and "/etc/passwd" not in text


def test_a_billion_laughs_body_does_not_expand():
    doc = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE lol [<!ENTITY lol "lol">'
        '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
        '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>'
        "<lolz>&lol3;</lolz>"
    )
    parsed = parse_body(doc, "application/xml")
    if parsed is not None:
        for _, value in parsed.leaves:
            assert len(value) < 10_000, "entity expansion must not run away"


# --------------------------------------------------------------------------------------------
# Form encoded
# --------------------------------------------------------------------------------------------


def test_form_locations_are_parameter_names():
    parsed = parse_body("clientRef=ABC-1&status=new", "application/x-www-form-urlencoded")

    assert parsed.format == "form"
    assert ("clientRef", "ABC-1") in parsed.leaves


def test_repeated_form_keys_are_indexed():
    parsed = parse_body("id=A&id=B", "application/x-www-form-urlencoded")
    assert ("id", "A") in parsed.leaves
    assert ("id[2]", "B") in parsed.leaves


def test_prose_is_not_mistaken_for_form_encoded():
    """The loosest parser must not claim text that merely contains an equals sign."""
    assert parse_body("Service unavailable = try later", "text/plain") is None


def test_html_is_not_mistaken_for_form_encoded():
    assert parse_body("<html><body><p>Oops</body></html>", "text/html") is None


# --------------------------------------------------------------------------------------------
# Dispatch: Content-Type is a hint, not an instruction
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("declared", "expected"),
    [
        ("application/json", "json"),
        ("application/vnd.api+json; charset=utf-8", "json"),
        ("text/xml", "xml"),
        ("application/soap+xml", "xml"),
        ("application/x-www-form-urlencoded", "form"),
        ("text/plain", None),
        ("", None),
    ],
)
def test_preferred_format_from_content_type(declared, expected):
    assert preferred_format(declared) == expected


def test_json_mislabelled_text_plain_still_parses():
    """The behaviour that existed before dispatch did, and must survive it."""
    parsed = parse_body(json.dumps({"ref": "R-9"}), "text/plain")

    assert parsed is not None
    assert parsed.format == "json"
    assert ("$.ref", "R-9") in parsed.leaves
    assert parsed.mismatch is None, "no declared preference means nothing to contradict"


def test_xml_mislabelled_as_json_is_found_by_fallback():
    parsed = parse_body("<order><ref>ORD-5</ref></order>", "application/json")

    assert parsed.format == "xml"
    assert parsed.mismatch is not None
    assert "declared application/json" in parsed.mismatch


def test_a_correctly_labelled_body_reports_no_mismatch():
    assert parse_body('{"a": "bbbbbbbb"}', "application/json").mismatch is None


def test_an_unreadable_body_returns_none():
    assert parse_body("Service Unavailable - please retry", "text/plain") is None


def test_an_empty_body_returns_none():
    assert parse_body("", "application/json") is None
    assert parse_body("   ", "application/json") is None
