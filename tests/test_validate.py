"""Structural validation.

Negative cases matter most here: a validator that passes everything is indistinguishable from no
validator at all, and the failure it exists to catch (a mispaired hashTree) is exactly the one
JMeter reports as a silent refusal to open the file.
"""

from __future__ import annotations

from perfgen.emit.emitter import build_tree
from perfgen.validate import validate_xml

WELL_FORMED = b"""<jmeterTestPlan version="1.2" properties="5.0" jmeter="5.6.3">
  <hashTree>
    <TestPlan testname="ok"/>
    <hashTree/>
  </hashTree>
</jmeterTestPlan>"""


def test_emitted_fixtures_validate(simple_flow, auth_shared_token):
    for ir in (simple_flow, auth_shared_token):
        xml, _ = build_tree(ir, "5.6.3")
        report = validate_xml(xml)
        assert report.ok, str(report)


def test_well_formed_minimal_plan_passes():
    assert validate_xml(WELL_FORMED).ok


def test_unparseable_file_is_reported():
    report = validate_xml(b"<jmeterTestPlan><hashTree></jmeterTestPlan>")
    assert not report.ok
    assert "does not parse" in report.errors[0]


def test_wrong_root_element_is_reported():
    report = validate_xml(b"<notAPlan/>")
    assert not report.ok
    assert "expected 'jmeterTestPlan'" in report.errors[0]


def test_element_without_a_paired_hash_tree_is_reported():
    """The core invariant: an element and its hashTree always travel together."""
    xml = b"""<jmeterTestPlan>
      <hashTree>
        <TestPlan testname="lonely"/>
      </hashTree>
    </jmeterTestPlan>"""
    report = validate_xml(xml)
    assert not report.ok
    assert any("always even" in e for e in report.errors)


def test_element_followed_by_the_wrong_tag_is_reported():
    xml = b"""<jmeterTestPlan>
      <hashTree>
        <TestPlan testname="a"/>
        <ThreadGroup testname="b"/>
      </hashTree>
    </jmeterTestPlan>"""
    report = validate_xml(xml)
    assert not report.ok
    assert any("is not followed by a hashTree" in e for e in report.errors)


def test_variable_with_no_producer_is_reported():
    xml = b"""<jmeterTestPlan>
      <hashTree>
        <HTTPSamplerProxy testname="s">
          <stringProp name="HTTPSampler.path">/items/${orphan}</stringProp>
        </HTTPSamplerProxy>
        <hashTree/>
      </hashTree>
    </jmeterTestPlan>"""
    report = validate_xml(xml)
    assert not report.ok
    assert any("${orphan} is referenced but nothing produces it" in e for e in report.errors)


def test_variable_produced_by_an_extractor_resolves():
    xml = b"""<jmeterTestPlan>
      <hashTree>
        <HTTPSamplerProxy testname="s">
          <stringProp name="HTTPSampler.path">/items/${itemId}</stringProp>
        </HTTPSamplerProxy>
        <hashTree>
          <JSONPostProcessor testname="e">
            <stringProp name="JSONPostProcessor.referenceNames">itemId</stringProp>
          </JSONPostProcessor>
          <hashTree/>
        </hashTree>
      </hashTree>
    </jmeterTestPlan>"""
    assert validate_xml(xml).ok


def test_variable_produced_by_a_udv_resolves():
    xml = b"""<jmeterTestPlan>
      <hashTree>
        <Arguments testname="udv">
          <collectionProp name="Arguments.arguments">
            <elementProp name="baseHost" elementType="Argument">
              <stringProp name="Argument.name">baseHost</stringProp>
              <stringProp name="Argument.value">example.internal</stringProp>
            </elementProp>
          </collectionProp>
        </Arguments>
        <hashTree/>
        <HTTPSamplerProxy testname="s">
          <stringProp name="HTTPSampler.domain">${baseHost}</stringProp>
        </HTTPSamplerProxy>
        <hashTree/>
      </hashTree>
    </jmeterTestPlan>"""
    assert validate_xml(xml).ok


def test_property_published_by_a_jsr223_resolves():
    xml = b"""<jmeterTestPlan>
      <hashTree>
        <JSR223PostProcessor testname="pub">
          <stringProp name="script">props.put("authToken", vars.get("authToken"));</stringProp>
        </JSR223PostProcessor>
        <hashTree/>
        <HeaderManager testname="h">
          <stringProp name="Header.value">Bearer ${__P(authToken)}</stringProp>
        </HeaderManager>
        <hashTree/>
      </hashTree>
    </jmeterTestPlan>"""
    report = validate_xml(xml)
    assert report.ok
    assert not report.warnings


def test_property_without_a_default_or_producer_warns_but_does_not_fail():
    xml = b"""<jmeterTestPlan>
      <hashTree>
        <HeaderManager testname="h">
          <stringProp name="Header.value">Bearer ${__P(mystery)}</stringProp>
        </HeaderManager>
        <hashTree/>
      </hashTree>
    </jmeterTestPlan>"""
    report = validate_xml(xml)
    assert report.ok
    assert any("mystery" in w for w in report.warnings)


def test_property_with_an_inline_default_is_not_flagged():
    """Load parameters carry defaults and are supplied by property files, so they never dangle."""
    xml = b"""<jmeterTestPlan>
      <hashTree>
        <ThreadGroup testname="g">
          <stringProp name="ThreadGroup.num_threads">${__P(users_F01,15)}</stringProp>
        </ThreadGroup>
        <hashTree/>
      </hashTree>
    </jmeterTestPlan>"""
    report = validate_xml(xml)
    assert report.ok
    assert not report.warnings


def test_unresolved_brace_placeholder_is_reported():
    """A `{var}` that survived emission means no extractor produced it."""
    xml = b"""<jmeterTestPlan>
      <hashTree>
        <HTTPSamplerProxy testname="s">
          <stringProp name="HTTPSampler.path">/items/{itemId}</stringProp>
        </HTTPSamplerProxy>
        <hashTree/>
      </hashTree>
    </jmeterTestPlan>"""
    report = validate_xml(xml)
    assert not report.ok
    assert any("unresolved placeholder {itemId}" in e for e in report.errors)


def test_groovy_env_lookup_is_accepted():
    """The portable way to read a secret at run time in stock JMeter."""
    lookup = "${__groovy(System.getenv('PERF_CLIENT_ID'))}"
    xml = f"""<jmeterTestPlan>
      <hashTree>
        <HTTPSamplerProxy testname="s">
          <stringProp name="Argument.value">client_id={lookup}</stringProp>
        </HTTPSamplerProxy>
        <hashTree/>
      </hashTree>
    </jmeterTestPlan>""".encode()
    report = validate_xml(xml)
    assert report.ok, str(report)


def test_non_core_env_function_is_rejected():
    """`__env` ships with a plugin, not JMeter. Unresolved, it is sent as literal text.

    This was found by running a generated script: the auth request posted the string
    "${__env(PERF_CLIENT_ID)}" as its client_id and the failure looked like bad credentials.
    """
    xml = b"""<jmeterTestPlan>
      <hashTree>
        <HTTPSamplerProxy testname="s">
          <stringProp name="Argument.value">client_id=${__env(PERF_CLIENT_ID)}</stringProp>
        </HTTPSamplerProxy>
        <hashTree/>
      </hashTree>
    </jmeterTestPlan>"""
    report = validate_xml(xml)
    assert not report.ok
    assert any("not a core JMeter function" in e for e in report.errors)


def test_emitted_credentials_use_a_core_function(auth_shared_token):
    xml, _ = build_tree(auth_shared_token, "5.6.3")
    text = xml.decode()
    assert "__env(" not in text
    assert "System.getenv('PERF_CLIENT_ID')" in text


def test_step_with_an_unproduced_placeholder_fails_validation_end_to_end(simple_flow):
    """The emitter leaves it intact deliberately so validation reports it."""
    simple_flow.flows[0].steps[1].path = "/catalogue/items/{neverExtracted}"
    xml, _ = build_tree(simple_flow, "5.6.3")
    report = validate_xml(xml)
    assert not report.ok
    assert any("neverExtracted" in e for e in report.errors)
