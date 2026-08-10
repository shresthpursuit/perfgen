"""Workbook -> Test Plan IR. Deterministic parsing; no LLM, no network."""

from perfgen.parse.workbook import ParseResult, parse_workbook

__all__ = ["ParseResult", "parse_workbook"]
