"""YAML round-trip for the Test Plan IR.

The IR is committed to git and reviewed by hand, so dumps keep field declaration order and render
multi-line strings as block scalars — a diff on a request body should show the changed line, not a
re-wrapped blob.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from perfgen.ir.models import TestPlanIR


class _IRDumper(yaml.SafeDumper):
    """Dumper that renders multi-line strings as block scalars."""


def _represent_str(dumper: yaml.SafeDumper, data: str) -> yaml.ScalarNode:
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


_IRDumper.add_representer(str, _represent_str)


def load_ir(path: str | Path) -> TestPlanIR:
    """Read and validate an IR YAML file."""
    raw = Path(path).read_text(encoding="utf-8")
    data: Any = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise ValueError(
            f"{path}: expected a YAML mapping at the top level, got {type(data).__name__}"
        )
    return TestPlanIR.model_validate(data)


def ir_to_yaml(ir: TestPlanIR) -> str:
    """Serialise an IR to YAML text."""
    data = ir.model_dump(mode="json")
    return yaml.dump(
        data,
        Dumper=_IRDumper,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=100,
    )


def dump_ir(ir: TestPlanIR, path: str | Path) -> Path:
    """Write an IR to disk, creating parent directories as needed."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(ir_to_yaml(ir), encoding="utf-8")
    return target
