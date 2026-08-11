"""Synthetic traffic carrying known false-positive bait.

The brief asks for the correlation filters to be tested against a record containing values that
look like correlations and are not. Everything here is deliberate:

* `ITEM-42-abcdef` and `REQ-8f2c91ab-7d3e` are real correlations - server-generated, reused later.
* `"true"`, `"USD"` and `200` travel from a response into a later request purely by coincidence.
* `client-supplied-ref-001` is sent BY the client and echoed back by the server, so it looks like
  a correlation from the response side and is not one.
* `application/json` appears in nearly every response, so it is ambient rather than a link.
"""

from __future__ import annotations

import json

from perfgen.probe.records import (
    ProbeRecord,
    RecordedCall,
    RecordedRequest,
    RecordedResponse,
)

REAL_ITEM_ID = "ITEM-42-abcdef"
REAL_REQUEST_REF = "REQ-8f2c91ab-7d3e"
ECHOED_CLIENT_VALUE = "client-supplied-ref-001"


def _call(
    name: str,
    *,
    flow_id: str | None,
    step_index: int | None,
    method: str,
    url: str,
    request_body: str | None = None,
    status: int = 200,
    response_body: dict | None = None,
    response_headers: dict[str, str] | None = None,
) -> RecordedCall:
    return RecordedCall(
        flow_id=flow_id,
        step_index=step_index,
        name=name,
        request=RecordedRequest(
            method=method,
            url=url,
            headers={"Content-Type": "application/json"},
            body=request_body,
        ),
        response=RecordedResponse(
            status=status,
            headers={"Content-Type": "application/json", **(response_headers or {})},
            body=json.dumps(response_body) if response_body is not None else None,
        ),
    )


def bait_record() -> ProbeRecord:
    """A record where two correlations are real and four traps look real."""
    return ProbeRecord(
        application="Bait",
        performed_at="2026-08-10T00:00:00Z",
        calls=[
            # 1. Search returns a genuine identifier, plus low-entropy noise.
            _call(
                "Search catalogue",
                flow_id="F01",
                step_index=1,
                method="GET",
                url="https://api.example.internal/v1/catalogue/search?q=widget",
                response_body={
                    "results": [{"id": REAL_ITEM_ID, "name": "Widget", "inStock": "true"}],
                    "currency": "USD",
                    "total": 200,
                    "status": "active",
                },
            ),
            # 2. The identifier is reused in the path - a real correlation.
            #    "true", "USD" and 200 also reappear here, by coincidence.
            _call(
                "Open record detail",
                flow_id="F01",
                step_index=2,
                method="GET",
                url=(
                    f"https://api.example.internal/v1/catalogue/items/{REAL_ITEM_ID}"
                    "?includeStock=true&currency=USD&limit=200"
                ),
                response_body={"id": REAL_ITEM_ID, "stock": 7, "currency": "USD"},
            ),
            # 3. The client sends its own reference; the server echoes it back verbatim.
            _call(
                "Create request",
                flow_id="F02",
                step_index=1,
                method="POST",
                url="https://api.example.internal/v1/requests",
                request_body=json.dumps(
                    {"clientRef": ECHOED_CLIENT_VALUE, "type": "standard"}
                ),
                status=201,
                response_body={
                    "requestRef": REAL_REQUEST_REF,
                    "clientRef": ECHOED_CLIENT_VALUE,
                    "accepted": "true",
                },
            ),
            # 4. Both the server-generated ref and the echoed client ref are sent again.
            _call(
                "Check status",
                flow_id="F02",
                step_index=2,
                method="GET",
                url=(
                    f"https://api.example.internal/v1/requests/{REAL_REQUEST_REF}/status"
                    f"?clientRef={ECHOED_CLIENT_VALUE}&verbose=true"
                ),
                response_body={"state": "pending"},
            ),
        ],
    )


def degraded_record() -> ProbeRecord:
    """A probe that could not run at all."""
    return ProbeRecord(
        application="Bait",
        performed_at="2026-08-10T00:00:00Z",
        degraded=True,
        degraded_reason="the token endpoint could not be reached",
        calls=[],
    )
