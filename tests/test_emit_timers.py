"""D2: timer scoping.

JMeter timers are scoped, not sequential — a timer fires before *every* sampler within its scope.
A timer emitted as a sibling of the Transaction Controller would sit at thread-group level and
apply to every sampler in the group, so N steps would stack N timers and a 3-step flow with 3s
think time would pause 9s before each request.

The timer therefore lives inside the controller (scoped to that controller's one sampler), and the
controller carries an explicit `includeTimers=false` so the delay stays out of the transaction's
elapsed time and the SLA percentile stays measurable.
"""

from __future__ import annotations

from lxml import etree

from perfgen.emit.emitter import build_tree


def _tree(ir):
    xml, _ = build_tree(ir, "5.6.3")
    return etree.fromstring(xml)


def _paired_hash_tree(element: etree._Element) -> etree._Element:
    nxt = element.getnext()
    assert nxt is not None and nxt.tag == "hashTree"
    return nxt


def _timers_in_scope_of(sampler: etree._Element) -> list[etree._Element]:
    """Every timer that would fire before this sampler.

    A timer applies to a sampler when it is a sibling of that sampler (same hashTree) or a sibling
    of any ancestor controller. That is JMeter's scoping rule, and it is what makes stacked
    sibling timers a bug rather than a style preference.
    """
    timers: list[etree._Element] = []
    container = sampler.getparent()
    while container is not None:
        for child in container:
            if isinstance(child.tag, str) and child.tag.endswith("Timer"):
                timers.append(child)
        # Step out to the controller that owns this hashTree, then to its container.
        owner = container.getprevious()
        container = owner.getparent() if owner is not None else None
    return timers


def test_exactly_one_timer_in_scope_per_sampler(auth_shared_token):
    """The regression guard: two steps in F01, and neither sees two timers."""
    root = _tree(auth_shared_token)
    flow_samplers = [
        s
        for s in root.iter("HTTPSamplerProxy")
        if s.get("testname") in {"Search catalogue", "Open record detail"}
    ]
    assert len(flow_samplers) == 2, "expected both F01 steps"

    for sampler in flow_samplers:
        timers = _timers_in_scope_of(sampler)
        constant = [t for t in timers if t.tag == "ConstantTimer"]
        assert len(constant) == 1, (
            f"{sampler.get('testname')!r} has {len(constant)} think-time timers in scope; "
            f"stacked timers would multiply the think time by the step count"
        )


def test_think_time_timer_is_inside_its_transaction_controller(auth_shared_token):
    root = _tree(auth_shared_token)
    for controller in root.iter("TransactionController"):
        children = _paired_hash_tree(controller)
        timers = [c for c in children if c.tag == "ConstantTimer"]
        assert len(timers) == 1, (
            f"{controller.get('testname')!r} should hold exactly one ConstantTimer, "
            f"found {len(timers)}"
        )


def test_every_transaction_controller_excludes_timers_explicitly(auth_shared_token):
    """Never rely on the element default — write includeTimers=false every time."""
    root = _tree(auth_shared_token)
    controllers = list(root.iter("TransactionController"))
    assert controllers, "fixture should produce transaction controllers"
    for controller in controllers:
        prop = controller.find("boolProp[@name='TransactionController.includeTimers']")
        assert prop is not None, (
            f"{controller.get('testname')!r} has no explicit includeTimers property"
        )
        assert prop.text == "false", (
            f"{controller.get('testname')!r} includes timers in the transaction sample, which "
            f"inflates it by the think time and corrupts the SLA percentile"
        )


def test_no_timer_is_a_direct_child_of_a_thread_group(auth_shared_token):
    """A ConstantTimer at thread-group level would apply to every sampler in the group."""
    root = _tree(auth_shared_token)
    for group in root.iter("ThreadGroup"):
        children = _paired_hash_tree(group)
        stray = [c for c in children if c.tag == "ConstantTimer"]
        assert not stray, (
            f"{group.get('testname')!r} has a ConstantTimer at group level; it would fire before "
            f"every sampler in the group and stack with the per-step timers"
        )


def test_throughput_timer_sits_at_thread_group_level(auth_shared_token):
    """The throughput timer *should* be group-scoped — it paces the whole flow."""
    root = _tree(auth_shared_token)
    groups = {g.get("testname"): g for g in root.iter("ThreadGroup")}
    assert groups
    for group in groups.values():
        children = _paired_hash_tree(group)
        timers = [c for c in children if c.tag == "ConstantThroughputTimer"]
        assert len(timers) == 1


def test_no_timer_emitted_when_think_time_is_zero(simple_flow):
    simple_flow.flows[0].think_time_ms = 0
    root = _tree(simple_flow)
    assert not list(root.iter("ConstantTimer"))


# A guard that cannot fail is worth nothing, so pin the detector against the arrangement it is
# meant to catch: two controllers with their timers hoisted to thread-group level. Under JMeter's
# scoping rules both timers then apply to both samplers.
_STACKED_TIMERS = b"""<jmeterTestPlan>
  <hashTree>
    <ThreadGroup testname="F01"/>
    <hashTree>
      <TransactionController testname="F01_01"/>
      <hashTree>
        <HTTPSamplerProxy testname="step one"/>
        <hashTree/>
      </hashTree>
      <ConstantTimer testname="think 1"/>
      <hashTree/>
      <TransactionController testname="F01_02"/>
      <hashTree>
        <HTTPSamplerProxy testname="step two"/>
        <hashTree/>
      </hashTree>
      <ConstantTimer testname="think 2"/>
      <hashTree/>
    </hashTree>
  </hashTree>
</jmeterTestPlan>"""


def test_scope_detector_catches_stacked_sibling_timers():
    root = etree.fromstring(_STACKED_TIMERS)
    for sampler in root.iter("HTTPSamplerProxy"):
        timers = _timers_in_scope_of(sampler)
        assert len(timers) == 2, (
            "the detector must see both hoisted timers in scope of each sampler, otherwise the "
            "regression guard above proves nothing"
        )
