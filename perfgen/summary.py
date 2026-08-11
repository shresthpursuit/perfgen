"""What the run tells the operator when it finishes.

The target user has never opened JMeter. They will read this and then hand the script to someone,
or run it themselves and believe the numbers. So the summary's job is not to report success - it
is to make the parts that are *not* trustworthy impossible to miss.

Correlations inferred without evidence are the sharpest edge in the whole tool. A wrong extractor
does not crash: the script runs, the samples pass, and the measurement is meaningless. That is why
`needs_review` is a banner with a count and a ratio at the top of the summary, with each flagged
extractor's evidence quoted, rather than a field someone might notice inside the IR.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from perfgen.ir.gaps import blocking
from perfgen.ir.models import Confidence, Gap, Severity, TestPlanIR

WIDTH = 78


@dataclass
class FlaggedExtract:
    flow_id: str
    step_index: int
    step_name: str
    var: str
    confidence: str
    evidence: str


@dataclass
class RunSummary:
    """Everything the operator needs to decide whether to trust the output."""

    application: str
    stages: list[str] = field(default_factory=list)
    artifacts: list[Path] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    config_warnings: list[str] = field(default_factory=list)

    total_correlations: int = 0
    flagged: list[FlaggedExtract] = field(default_factory=list)

    probe_performed: bool = False
    probe_degraded: bool = False
    skipped_flows: list[str] = field(default_factory=list)
    llm_called: bool = False
    llm_skip_reason: str | None = None

    next_command: str | None = None

    @property
    def trustworthy(self) -> bool:
        return not self.flagged and not self.probe_degraded

    def render(self) -> str:
        blocks = [self._header()]
        if self.flagged or self.probe_degraded:
            blocks.append(self._review_banner())
        blocks.append(self._stages())
        if self.gaps:
            blocks.append(self._gaps())
        if self.warnings or self.config_warnings or self.notes:
            blocks.append(self._notices())
        if self.artifacts:
            blocks.append(self._artifacts())
        if self.next_command:
            blocks.append(f"Next:\n  {self.next_command}")
        return "\n\n".join(block for block in blocks if block)

    # ----------------------------------------------------------------------------------

    def _header(self) -> str:
        return f"{'=' * WIDTH}\n  perfgen - {self.application}\n{'=' * WIDTH}"

    def _review_banner(self) -> str:
        """The one block that must survive skimming."""
        lines = ["!" * WIDTH]

        if self.flagged:
            total = self.total_correlations or len(self.flagged)
            lines.append(
                f"  {len(self.flagged)} OF {total} CORRELATION(S) IN THIS SCRIPT ARE GUESSES"
            )
            lines.append("")
            lines.append(
                "  These were not confirmed against observed traffic. A wrong extractor does"
            )
            lines.append(
                "  not crash the test - it runs, passes, and measures nothing. Check each one"
            )
            lines.append("  before trusting any number this script produces.")
            lines.append("")
            for item in self.flagged:
                lines.append(
                    f"  - {item.var}  ({item.flow_id} step {item.step_index}, "
                    f"{item.step_name}; confidence: {item.confidence})"
                )
                for wrapped in _wrap(item.evidence, WIDTH - 8):
                    lines.append(f"        {wrapped}")
                lines.append("")

        if self.probe_degraded:
            lines.append("  THE PROBE DID NOT RUN.")
            lines.append(
                "  Nothing in this script was verified against the real service. Every"
            )
            lines.append("  correlation is inferred from names in the specification.")
            lines.append("")

        lines.append("!" * WIDTH)
        return "\n".join(lines)

    def _stages(self) -> str:
        """The stages in the order they ran, then the one number that matters."""
        lines = ["Stages:"]
        for stage in self.stages:
            lines.append(f"  {stage}")

        confident = self.total_correlations - len(self.flagged)
        if self.total_correlations:
            lines.append(
                f"  correlations: {self.total_correlations} total, "
                f"{confident} verified, {len(self.flagged)} needing review"
            )
        return "\n".join(lines)


    def _gaps(self) -> str:
        lines = ["Gaps:"]
        for gap in sorted(self.gaps, key=lambda g: (g.severity is not Severity.BLOCKING, g.field)):
            marker = "BLOCKING" if gap.severity is Severity.BLOCKING else "warning "
            lines.append(f"  [{marker}] {gap.field}")
            for wrapped in _wrap(gap.message, WIDTH - 6):
                lines.append(f"      {wrapped}")
        return "\n".join(lines)

    def _notices(self) -> str:
        lines = []
        if self.warnings:
            lines.append("Warnings:")
            for warning in self.warnings:
                lines.extend(_bullet(warning))
        if self.config_warnings:
            lines.append("Configuration:")
            for warning in self.config_warnings:
                lines.extend(_bullet(warning))
        if self.notes:
            lines.append("Notes:")
            for note in self.notes:
                lines.extend(_bullet(note))
        return "\n".join(lines)

    def _artifacts(self) -> str:
        lines = ["Written:"]
        for path in self.artifacts:
            lines.append(f"  {path}")
        return "\n".join(lines)


def _bullet(text: str) -> list[str]:
    wrapped = _wrap(text, WIDTH - 6)
    return [f"  ! {wrapped[0]}"] + [f"    {line}" for line in wrapped[1:]]


def _wrap(text: str, width: int) -> list[str]:
    words = " ".join(text.split()).split(" ")
    lines: list[str] = []
    current = ""
    for word in words:
        if current and len(current) + 1 + len(word) > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines or [""]


def collect_flagged(ir: TestPlanIR) -> list[FlaggedExtract]:
    """Every extractor a human still has to check."""
    flagged: list[FlaggedExtract] = []
    for flow in ir.flows:
        for step in flow.steps:
            for extract in step.extracts:
                if extract.needs_review or extract.confidence is Confidence.INFERRED:
                    flagged.append(
                        FlaggedExtract(
                            flow_id=flow.id,
                            step_index=step.index,
                            step_name=step.name,
                            var=extract.var,
                            confidence=extract.confidence.value,
                            evidence=extract.evidence,
                        )
                    )
    return flagged


def count_correlations(ir: TestPlanIR) -> int:
    return sum(len(step.extracts) for flow in ir.flows for step in flow.steps)


def summarise(ir: TestPlanIR, **kwargs) -> RunSummary:
    """Build a summary from an IR, filling in the correlation counts."""
    summary = RunSummary(application=ir.application.name, **kwargs)
    summary.total_correlations = count_correlations(ir)
    summary.flagged = collect_flagged(ir)
    summary.probe_performed = ir.provenance.probe.performed
    summary.probe_degraded = ir.provenance.probe.degraded
    summary.skipped_flows = list(ir.provenance.probe.skipped_flows)
    if not summary.gaps:
        summary.gaps = list(ir.gaps)
    return summary


def exit_code_for(summary: RunSummary) -> int:
    """Blocking gaps fail the run; needing review does not - it is a caution, not an error."""
    return 1 if blocking(summary.gaps) else 0
