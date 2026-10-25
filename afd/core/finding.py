"""Finding: the common result object every detector returns.

Forensic concept
----------------
A detector never says "this file was timestomped". It says "this looks like
timestomping, with LOW / MEDIUM / HIGH confidence, because of these reasons". The
examiner then decides. So each Finding carries:

  * confidence  - how sure we are that the *action* happened (not who did it or why)
  * score       - the points behind that confidence, so it can be explained and tuned
  * reasons     - the indicators that fired, in plain English
  * benign_notes- innocent explanations that were considered (installers, reboots...)
  * evidence    - the raw values (timestamps, record IDs) so the finding can be checked
  * event_time  - where the finding belongs on the Stage 5 timeline, and
    time_meaning - what that time stands for (it is not always "when it happened")

mitre is the MITRE ATT&CK technique ID, so the report can cite a standard reference.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum


class Confidence(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


def confidence_from_score(score: int, medium_at: int, high_at: int) -> Confidence:
    """Map a point score to a confidence level using the configured thresholds."""
    if score >= high_at:
        return Confidence.HIGH
    if score >= medium_at:
        return Confidence.MEDIUM
    return Confidence.LOW


@dataclass
class Finding:
    module: str                 # "timestomp", "log_wiping", ...
    technique: str              # short name, e.g. "Timestomping"
    mitre: str                  # e.g. "T1070.006"
    title: str                  # one line for the dashboard
    confidence: Confidence
    score: int
    subject: str                # the file path or log the finding is about
    artifact: str               # where the evidence lives, e.g. "$MFT entry 4711"
    reasons: list[str] = field(default_factory=list)
    benign_notes: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    event_time: datetime | None = None
    time_meaning: str = ""
    id: str = ""

    def to_dict(self) -> dict:
        """JSON-friendly form (used by the CSV/JSON export and the report)."""
        return {
            "id": self.id,
            "module": self.module,
            "technique": self.technique,
            "mitre": self.mitre,
            "title": self.title,
            "confidence": self.confidence.name,
            "score": self.score,
            "subject": self.subject,
            "artifact": self.artifact,
            "reasons": self.reasons,
            "benign_notes": self.benign_notes,
            "evidence": self.evidence,
            "event_time": self.event_time.isoformat() if self.event_time else None,
            "time_meaning": self.time_meaning,
        }


_ID_PREFIX = {"timestomp": "TS", "log_wiping": "LW", "file_wiping": "FW",
              "freespace": "FS", "hidden_files": "HF", "tool_traces": "TT"}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Highest confidence first, then earliest event time (undated ones last)."""
    far_future = datetime.max.replace(tzinfo=None)

    def key(f: Finding):
        t = f.event_time.replace(tzinfo=None) if f.event_time else far_future
        return (-int(f.confidence), -f.score, t)

    return sorted(findings, key=key)


def assign_ids(findings: list[Finding]) -> list[Finding]:
    """Give each finding a stable readable id such as TS-0001 (in the given order)."""
    counters: dict[str, int] = {}
    for f in findings:
        prefix = _ID_PREFIX.get(f.module, f.module[:2].upper())
        counters[prefix] = counters.get(prefix, 0) + 1
        f.id = f"{prefix}-{counters[prefix]:04d}"
    return findings
