from __future__ import annotations

from pathlib import Path

import pytest

from perfgen.ir.io import load_ir
from perfgen.ir.models import TestPlanIR

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "ir"


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--golden-update",
        action="store_true",
        default=False,
        help="rewrite the golden structural fingerprints from current emitter output",
    )


@pytest.fixture
def simple_flow() -> TestPlanIR:
    return load_ir(FIXTURE_DIR / "simple_flow.yaml")


@pytest.fixture
def auth_shared_token() -> TestPlanIR:
    return load_ir(FIXTURE_DIR / "auth_shared_token.yaml")
