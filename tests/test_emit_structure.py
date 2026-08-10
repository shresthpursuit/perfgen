"""Emitter structure: hashTree pairing, scope-dependent references, and the tree shape."""

from __future__ import annotations

import pytest
from lxml import etree

from perfgen.emit.assembler import Node, build_document, node, render_element
from perfgen.emit.emitter import build_tree, rewrite_placeholders
from perfgen.ir.models import AuthStrategy, Scope
from perfgen.validate import validate_xml


def _tree(ir):
    xml, _ = build_tree(ir, "5.6.3")
    return etree.fromstring(xml)


# --------------------------------------------------------------------------------------------
# hashTree pairing
# --------------------------------------------------------------------------------------------


def test_every_element_is_followed_by_a_hash_tree(auth_shared_token):
    root = _tree(auth_shared_token)
    for hash_tree in root.iter("hashTree"):
        children = [c for c in hash_tree if isinstance(c.tag, str)]
        assert len(children) % 2 == 0
        for index in range(0, len(children), 2):
            assert children[index].tag != "hashTree"
            assert children[index + 1].tag == "hashTree"


def test_assembler_cannot_produce_an_unpaired_tree():
    """Pairing is structural: children are declared on the Node, never as raw XML."""
    root = node("cookie_manager")
    root.add(Node(render_element("cache_manager")))
    document = build_document([root], "5.6.3")
    xml = etree.tostring(document)
    root_el = etree.fromstring(xml)
    assert validate_xml(xml).ok
    assert root_el.find("hashTree/CookieManager") is not None


def test_declared_jmeter_version_is_written_to_the_root():
    document = build_document([node("cookie_manager")], "5.6.3")
    assert document.getroot().get("jmeter") == "5.6.3"
    assert document.getroot().get("version") == "1.2"


# --------------------------------------------------------------------------------------------
# Placeholder rewriting by scope
# --------------------------------------------------------------------------------------------


def test_global_placeholder_becomes_a_property_reference():
    scopes = {"authToken": Scope.GLOBAL}
    assert rewrite_placeholders("/x/{authToken}", scopes) == "/x/${__P(authToken)}"


def test_iteration_placeholder_becomes_a_variable_reference():
    scopes = {"itemId": Scope.ITERATION}
    assert rewrite_placeholders("/x/{itemId}", scopes) == "/x/${itemId}"


def test_thread_placeholder_becomes_a_variable_reference():
    scopes = {"sessionId": Scope.THREAD}
    assert rewrite_placeholders("/x/{sessionId}", scopes) == "/x/${sessionId}"


def test_unknown_placeholder_is_left_intact_for_the_validator_to_report():
    assert rewrite_placeholders("/x/{mystery}", {}) == "/x/{mystery}"


def test_scope_drives_the_reference_in_the_emitted_path(auth_shared_token):
    root = _tree(auth_shared_token)
    paths = [
        p.text
        for p in root.iter("stringProp")
        if p.get("name") == "HTTPSampler.path" and p.text
    ]
    assert "/api/v2/catalogue/items/${itemId}" in paths, (
        "an iteration-scoped value must be read as a plain variable"
    )


def test_global_token_is_read_as_a_property_in_the_auth_header(auth_shared_token):
    root = _tree(auth_shared_token)
    values = [
        p.text for p in root.iter("stringProp") if p.get("name") == "Header.value" and p.text
    ]
    assert "Bearer ${__P(authToken)}" in values


def test_per_thread_auth_reads_a_thread_variable_and_emits_no_setup_group(auth_shared_token):
    auth_shared_token.auth.strategy = AuthStrategy.PER_THREAD
    root = _tree(auth_shared_token)
    assert not list(root.iter("SetupThreadGroup")), (
        "per_thread auth moves the token acquisition inside each thread group"
    )
    values = [
        p.text for p in root.iter("stringProp") if p.get("name") == "Header.value" and p.text
    ]
    assert "Bearer ${authToken}" in values


def test_per_thread_auth_actually_acquires_a_token_in_each_group(auth_shared_token):
    """No setUp group means each thread group must acquire the token itself, once per user."""
    auth_shared_token.auth.strategy = AuthStrategy.PER_THREAD
    root = _tree(auth_shared_token)

    groups = list(root.iter("ThreadGroup"))
    for group in groups:
        children = group.getnext()
        once = children.find("OnceOnlyController")
        assert once is not None, (
            f"{group.get('testname')!r} has no OnceOnlyController; without it every iteration "
            f"would log in again"
        )
        sampler = once.getnext().find("HTTPSamplerProxy")
        assert sampler is not None and sampler.get("testname") == "Acquire token"

    # Thread-scoped, so it must NOT be published to a JVM-wide property.
    assert not list(root.iter("JSR223PostProcessor")), (
        "a per-thread token published to a property would be shared across users"
    )


def test_per_thread_auth_output_passes_structural_validation(auth_shared_token):
    """The token variable must actually have a producer, or the script fails at run time."""
    auth_shared_token.auth.strategy = AuthStrategy.PER_THREAD
    xml, _ = build_tree(auth_shared_token, "5.6.3")
    report = validate_xml(xml)
    assert report.ok, str(report)


def test_per_thread_auth_header_does_not_reach_the_token_request(auth_shared_token):
    """An unresolved Authorization header sent to the auth endpoint can get the request rejected."""
    auth_shared_token.auth.strategy = AuthStrategy.PER_THREAD
    root = _tree(auth_shared_token)
    token_sampler = next(
        s for s in root.iter("HTTPSamplerProxy") if s.get("testname") == "Acquire token"
    )
    headers = token_sampler.getnext().find("HeaderManager")
    names = [p.text for p in headers.iter("stringProp") if p.get("name") == "Header.name"]
    assert "Authorization" not in names


# --------------------------------------------------------------------------------------------
# Tree shape
# --------------------------------------------------------------------------------------------


def test_setup_group_present_only_for_shared_setup(auth_shared_token, simple_flow):
    assert list(_tree(auth_shared_token).iter("SetupThreadGroup"))
    assert not list(_tree(simple_flow).iter("SetupThreadGroup"))


def test_one_thread_group_per_flow(auth_shared_token):
    groups = list(_tree(auth_shared_token).iter("ThreadGroup"))
    assert len(groups) == len(auth_shared_token.flows)


def test_transaction_controller_names_are_stable_and_sortable(auth_shared_token):
    names = [c.get("testname") for c in _tree(auth_shared_token).iter("TransactionController")]
    assert names == [
        "F01_01_search_catalogue",
        "F01_02_open_record_detail",
        "F02_01_create_request",
    ]
    assert names == sorted(names)


def test_emission_is_deterministic(auth_shared_token):
    first, _ = build_tree(auth_shared_token, "5.6.3")
    second, _ = build_tree(auth_shared_token, "5.6.3")
    assert first == second, "the same IR must always produce byte-identical output"


def test_thread_counts_are_per_flow_properties_never_per_profile(auth_shared_token):
    root = _tree(auth_shared_token)
    counts = [
        p.text
        for p in root.iter("stringProp")
        if p.get("name") == "ThreadGroup.num_threads" and p.text
    ]
    assert "${__P(users_F01,15)}" in counts
    assert "${__P(users_F02,10)}" in counts
    assert not any("baseline" in c or "peak" in c for c in counts), (
        "a profile-named property would hardcode one profile into the JMX (D1)"
    )


def test_throughput_is_converted_to_samples_per_minute(auth_shared_token):
    root = _tree(auth_shared_token)
    values = [
        p.text for p in root.iter("stringProp") if p.get("name") == "throughput" and p.text
    ]
    # 1200 tph across a 60/40 split is 20/min total -> 12 and 8.
    assert "${__P(tput_F01,12.0)}" in values
    assert "${__P(tput_F02,8.0)}" in values


def test_no_duration_assertion_is_ever_emitted(auth_shared_token):
    """Per-sample duration assertions mark slow-but-successful responses as errors."""
    root = _tree(auth_shared_token)
    assert not list(root.iter("DurationAssertion"))


def test_response_assertion_uses_java_hash_code_key(simple_flow):
    root = _tree(simple_flow)
    assertion = next(root.iter("ResponseAssertion"))
    prop = assertion.find("collectionProp/stringProp")
    assert prop.text == "200"
    assert prop.get("name") == "49586"  # "200".hashCode() in Java


def test_content_type_inferred_from_a_json_body(auth_shared_token):
    root = _tree(auth_shared_token)
    sampler = next(
        s for s in root.iter("HTTPSamplerProxy") if s.get("testname") == "Create request"
    )
    header_manager = sampler.getnext().find("HeaderManager")
    values = {
        h.find("stringProp[@name='Header.name']").text: h.find(
            "stringProp[@name='Header.value']"
        ).text
        for h in header_manager.iter("elementProp")
    }
    assert values["Content-Type"] == "application/json"


def test_timeouts_are_set_on_every_sampler(auth_shared_token):
    root = _tree(auth_shared_token)
    samplers = list(root.iter("HTTPSamplerProxy"))
    assert samplers
    for sampler in samplers:
        assert sampler.find("stringProp[@name='HTTPSampler.connect_timeout']").text
        assert sampler.find("stringProp[@name='HTTPSampler.response_timeout']").text
        assert sampler.find("boolProp[@name='HTTPSampler.use_keepalive']").text == "true"


def test_emitting_without_an_enabled_profile_is_refused(simple_flow):
    for profile in simple_flow.load_profiles:
        profile.enabled = False
    with pytest.raises(ValueError, match="no enabled load profile"):
        build_tree(simple_flow, "5.6.3")
