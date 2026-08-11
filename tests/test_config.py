"""Configuration loading.

A setting that is silently ignored is worse than one that fails: the operator believes the run was
configured a particular way and nothing in the output says otherwise. So unknown keys are rejected,
and a setting the provider cannot honour reports itself rather than disappearing.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from perfgen.config import Config, LLMConfig, find_config, load_config

VALID = """\
llm:
  provider: claude-code
  model: ""
  temperature: 0.2
probe:
  enabled: true
  timeout_s: 30
secrets:
  provider: env
jmeter:
  version: "5.6.3"
paths:
  specs: data/specs
  ir: data/ir
  probe_records: data/probe
  outputs: outputs
  logs: logs
"""


def write(tmp_path, text: str):
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_shipped_config_shape_loads():
    """The config.yaml committed at the repo root must actually parse."""
    config = load_config("config.yaml")
    assert config.jmeter.version
    assert config.paths.outputs.name == "outputs"


def test_values_are_read(tmp_path):
    config = load_config(write(tmp_path, VALID))
    assert config.probe.timeout_s == 30
    assert config.jmeter.version == "5.6.3"
    assert config.secrets.provider == "env"
    assert config.source is not None


def test_no_config_anywhere_falls_back_to_defaults(tmp_path):
    """Defaults match the shipped config.yaml, so a bare checkout still works."""
    assert find_config(tmp_path) is None
    config = Config()
    assert config.jmeter.version == "5.6.3"
    assert config.probe.timeout_s == 30
    assert config.source is None


def test_config_is_found_by_searching_upwards(tmp_path):
    written = write(tmp_path, VALID)
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    assert find_config(nested) == written


def test_an_explicitly_named_missing_config_is_an_error(tmp_path):
    """Asking for a particular file and silently getting defaults would hide the mistake."""
    with pytest.raises(OSError):
        load_config(tmp_path / "absent.yaml")


def test_partial_config_keeps_defaults_for_the_rest(tmp_path):
    config = load_config(write(tmp_path, "jmeter:\n  version: '5.5'\n"))
    assert config.jmeter.version == "5.5"
    assert config.probe.timeout_s == 30


def test_unknown_key_is_rejected(tmp_path):
    """A typo must fail rather than quietly do nothing."""
    with pytest.raises(ValidationError):
        load_config(write(tmp_path, "jmeter:\n  verison: '5.5'\n"))


def test_non_mapping_config_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="mapping"):
        load_config(write(tmp_path, "- a\n- b\n"))


def test_empty_file_is_defaults(tmp_path):
    assert load_config(write(tmp_path, "")).jmeter.version == "5.6.3"


def test_negative_timeout_is_rejected(tmp_path):
    with pytest.raises(ValidationError):
        load_config(write(tmp_path, "probe:\n  timeout_s: 0\n"))


# --------------------------------------------------------------------------------------------
# The setting the provider cannot honour
# --------------------------------------------------------------------------------------------


def test_default_temperature_produces_no_warning():
    assert LLMConfig().unsupported_settings() == []


def test_changed_temperature_is_reported_as_unsupported():
    """Verified against the SDK: ClaudeAgentOptions has no temperature field, and passing
    --temperature to the CLI fails the call with 'unknown option'."""
    warnings = LLMConfig(temperature=0.9).unsupported_settings()
    assert len(warnings) == 1
    assert "llm.temperature" in warnings[0]
    assert "no effect" in warnings[0]


def test_temperature_warning_reaches_the_config_warnings(tmp_path):
    config = load_config(write(tmp_path, "llm:\n  temperature: 0.9\n"))
    assert any("temperature" in w for w in config.warnings())


def test_another_provider_is_not_warned_about():
    """The limitation is specific to claude-code, not to the setting."""
    assert LLMConfig(provider="something-else", temperature=0.9).unsupported_settings() == []


def test_model_is_carried_through(tmp_path):
    config = load_config(write(tmp_path, "llm:\n  model: claude-opus-5\n"))
    assert config.llm.model == "claude-opus-5"
    assert config.warnings() == []
