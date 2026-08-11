"""Configuration, loaded from `config.yaml` at the repository root.

Every stage reads its settings from here rather than from constants scattered through the code, so
a JMeter upgrade or a timeout change is one edit in one file.

Unknown keys are rejected. A setting that is silently ignored is worse than one that fails: the
operator believes the run was configured a particular way and the output says nothing to the
contrary. The same principle is why `llm.temperature` reports itself as unsupported rather than
being quietly dropped - see `LLMConfig.unsupported_settings`.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

CONFIG_FILENAME = "config.yaml"


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LLMConfig(_Base):
    provider: str = "claude-code"
    model: str = Field(default="", description="blank uses the provider's default")
    temperature: float = 0.2

    def unsupported_settings(self) -> list[str]:
        """Settings this provider cannot honour, so the run can say so out loud.

        The `claude-code` provider runs through the Claude Agent SDK, whose options carry a model
        but no temperature - and passing `--temperature` to the underlying CLI fails the call
        outright with "unknown option". Sampling is therefore fixed by the provider.
        """
        unsupported: list[str] = []
        if self.provider == "claude-code" and self.temperature != LLMConfig().temperature:
            unsupported.append(
                f"llm.temperature ({self.temperature}) has no effect with provider "
                f"'{self.provider}': the Claude Agent SDK exposes no temperature setting. "
                f"Adjudication runs at the provider's default sampling."
            )
        return unsupported


class ProbeConfig(_Base):
    enabled: bool = True
    timeout_s: int = Field(default=30, ge=1)


class SecretsConfig(_Base):
    provider: str = "env"


class JMeterConfig(_Base):
    version: str = "5.6.3"


class PathsConfig(_Base):
    specs: Path = Path("data/specs")
    ir: Path = Path("data/ir")
    probe_records: Path = Path("data/probe")
    outputs: Path = Path("outputs")
    logs: Path = Path("logs")


class Config(_Base):
    llm: LLMConfig = Field(default_factory=LLMConfig)
    probe: ProbeConfig = Field(default_factory=ProbeConfig)
    secrets: SecretsConfig = Field(default_factory=SecretsConfig)
    jmeter: JMeterConfig = Field(default_factory=JMeterConfig)
    paths: PathsConfig = Field(default_factory=PathsConfig)

    source: Path | None = Field(
        default=None, description="where this was loaded from; None means built-in defaults"
    )

    def warnings(self) -> list[str]:
        return self.llm.unsupported_settings()


def find_config(start: str | Path | None = None) -> Path | None:
    """Look for `config.yaml` in the given directory, then upwards to the filesystem root."""
    current = Path(start or Path.cwd()).resolve()
    for directory in [current, *current.parents]:
        candidate = directory / CONFIG_FILENAME
        if candidate.is_file():
            return candidate
    return None


def load_config(path: str | Path | None = None) -> Config:
    """Load configuration, falling back to defaults when there is no file.

    A missing file is fine - the defaults match the shipped `config.yaml`. A malformed one is not:
    it means the operator intended something that is not happening.
    """
    source = Path(path) if path is not None else find_config()
    if source is None:
        return Config()

    raw = yaml.safe_load(Path(source).read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{source}: expected a YAML mapping at the top level")

    config = Config.model_validate(raw)
    config.source = Path(source)
    return config
