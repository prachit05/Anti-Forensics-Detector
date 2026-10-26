"""Unified Timeline Builder for Anti-Forensics Detector.

Forensic concept
----------------
Anti-forensic actions do not happen in isolation. A perpetrator follows a sequence:
  1. Launch or install an anti-forensic tool (e.g. 14:10 SDelete or NewFileTime launched).
  2. Perform file destruction or timestomping (e.g. 14:12 files wiped or timestamps altered).
  3. Clean evidence of the act (e.g. 14:15 Security event log cleared via wevtutil or Event 1102).
  4. Wipe unallocated space (e.g. 14:20 cipher /w or sdelete -z executed).

When viewed as disconnected alerts, individual findings might be overlooked or deemed
ambiguous. However, when sequenced chronologically on a unified timeline:
  - Temporal proximity is strong circumstantial support that the actions belong together.
  - The sequence of the cover-up becomes much easier for an examiner to read and explain.
  - "Episodes" or "tampering clusters" group actions that occurred within a tight window
    (e.g. within 30 minutes of each other).

Honest limits
-------------
- Not every finding has an exact timestamp (e.g. unallocated free-space wiping cannot
  reliably pinpoint the exact second it was performed without prefetch/event corroboration).
  Undated findings are retained in a dedicated contextual section.
- Timestamps from timestomped files may reflect either the fake date or the MFT change date.
  The timeline builder explicitly marks the 'time_meaning' so the examiner understands what
  the timestamp represents.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import pandas as pd

from afd.core.finding import Confidence, Finding


@dataclass
class TimelineEntry:
    time: datetime
    finding_id: str
    module: str
    technique: str
    title: str
    confidence: Confidence
    subject: str
    artifact: str
    time_meaning: str
    phase: str
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "time": self.time.isoformat(),
            "finding_id": self.finding_id,
            "module": self.module,
            "technique": self.technique,
            "title": self.title,
            "confidence": self.confidence.name,
            "subject": self.subject,
            "artifact": self.artifact,
            "time_meaning": self.time_meaning,
            "phase": self.phase,
            "reasons": self.reasons,
        }


@dataclass
class TimelineEpisode:
    episode_id: int
    start_time: datetime
    end_time: datetime
    event_count: int
    modules_involved: list[str]
    entries: list[TimelineEntry] = field(default_factory=list)
    narrative: str = ""

    def duration_minutes(self) -> float:
        return max(0.0, (self.end_time - self.start_time).total_seconds() / 60.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "episode_id": self.episode_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_minutes": round(self.duration_minutes(), 1),
            "event_count": self.event_count,
            "modules_involved": self.modules_involved,
            "narrative": self.narrative,
            "entries": [e.to_dict() for e in self.entries],
        }


@dataclass
class Timeline:
    entries: list[TimelineEntry] = field(default_factory=list)
    episodes: list[TimelineEpisode] = field(default_factory=list)
    undated_findings: list[Finding] = field(default_factory=list)

    def to_dataframe(self) -> pd.DataFrame:
        """Export timeline entries as a pandas DataFrame."""
        if not self.entries:
            return pd.DataFrame(columns=[
                "time", "finding_id", "module", "technique", "title",
                "confidence", "phase", "subject", "artifact", "time_meaning",
            ])
        rows = [e.to_dict() for e in self.entries]
        df = pd.DataFrame(rows)
        df["time"] = pd.to_datetime(df["time"])
        return df.sort_values("time").reset_index(drop=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_entries": len(self.entries),
            "total_episodes": len(self.episodes),
            "total_undated": len(self.undated_findings),
            "entries": [e.to_dict() for e in self.entries],
            "episodes": [ep.to_dict() for ep in self.episodes],
            "undated_findings": [f.to_dict() for f in self.undated_findings],
        }

    def narrative_summary(self) -> list[str]:
        """Generate a human-readable forensic story of the cover-up."""
        lines = []
        if not self.entries:
            return ["No dated anti-forensics events identified on the timeline."]

        lines.append(
            f"Forensic timeline reconstructs {len(self.entries)} event(s) across "
            f"{len(self.episodes)} distinct activity episode(s)."
        )

        for ep in self.episodes:
            start_str = ep.start_time.strftime("%Y-%m-%d %H:%M:%S UTC")
            end_str = ep.end_time.strftime("%H:%M:%S UTC")
            dur = f"{ep.duration_minutes():.1f} min" if ep.duration_minutes() > 0 else "instantaneous"
            lines.append(
                f"\n--- Episode {ep.episode_id}: {start_str} to {end_str} (Duration: {dur}, {ep.event_count} events) ---"
            )
            for entry in ep.entries:
                t_str = entry.time.strftime("%H:%M:%S")
                lines.append(f"  [{t_str}] [{entry.confidence.name:6}] {entry.phase}: {entry.title} ({entry.subject})")
            if ep.narrative:
                lines.append(f"  Summary: {ep.narrative}")

        if self.undated_findings:
            lines.append(
                f"\n--- Contextual / Undated Findings ({len(self.undated_findings)} item(s)) ---"
            )
            for uf in self.undated_findings:
                lines.append(f"  - [{uf.confidence.name:6}] {uf.title} ({uf.artifact})")

        return lines


def _assign_phase(module: str, technique: str, title: str) -> str:
    """Categorize finding into an intuitive incident-response / cover-up phase."""
    m = module.lower()
    t = technique.lower()
    tit = title.lower()

    if m == "tool_traces":
        if "exec" in t or "runmru" in t or "executed" in tit:
            return "Tool Execution"
        if "installed" in t or "software" in tit:
            return "Tool Installation"
        return "Tool Artifact"
    if m == "file_wiping":
        return "File Destruction"
    if m == "log_wiping":
        return "Log Manipulation"
    if m == "timestomp":
        return "Metadata Tampering"
    if m == "freespace":
        return "Free Space Sanitization"
    if m == "hidden_files":
        return "Data Concealment"
    return "Anti-Forensics Activity"


def _generate_episode_narrative(entries: list[TimelineEntry]) -> str:
    """Synthesize a short plain-English narrative for an episode."""
    modules = set(e.module for e in entries)

    desc_parts = []
    run = sorted({e.subject for e in entries if e.phase == "Tool Execution"})
    present = sorted({e.subject for e in entries if e.module == "tool_traces" and e.phase != "Tool Execution"})
    if run:
        desc_parts.append(f"anti-forensic tool run ({', '.join(run)})")
    if present:
        desc_parts.append(f"anti-forensic tool present or installed ({', '.join(present)})")

    if "timestomp" in modules:
        desc_parts.append("file timestamps were manipulated (timestomped)")

    if "file_wiping" in modules:
        desc_parts.append("files were securely deleted/overwritten")

    if "log_wiping" in modules:
        desc_parts.append("Windows event logs were cleared or altered")

    if "hidden_files" in modules:
        desc_parts.append("data was hidden in an ADS or disguised file")

    if not desc_parts:
        return f"{len(entries)} anti-forensics activity events observed."

    # Listed by kind, not strictly by time: the entry table above gives the exact order.
    return "Likely activity in this episode: " + "; ".join(desc_parts) + "."


def build_timeline(
    findings: list[Finding],
    episode_gap_minutes: float = 30.0,
    min_confidence: Confidence = Confidence.LOW,
) -> Timeline:
    """Construct a unified chronological timeline and partition it into activity episodes.

    Parameters:
        findings: list of Finding objects from detectors
        episode_gap_minutes: time gap in minutes that triggers a new activity episode
        min_confidence: leave out weaker findings. A clean Windows install produces
            100,000+ LOW findings, which would bury the cover-up story.
    """
    dated: list[TimelineEntry] = []
    undated: list[Finding] = []

    for f in findings:
        if f.confidence < min_confidence:
            continue
        if f.event_time is None:
            undated.append(f)
            continue

        # Ensure datetime is timezone-aware UTC
        t = f.event_time
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        else:
            t = t.astimezone(timezone.utc)

        phase = _assign_phase(f.module, f.technique, f.title)

        dated.append(TimelineEntry(
            time=t,
            finding_id=f.id,
            module=f.module,
            technique=f.technique,
            title=f.title,
            confidence=f.confidence,
            subject=f.subject,
            artifact=f.artifact,
            time_meaning=f.time_meaning or "event timestamp",
            phase=phase,
            reasons=list(f.reasons),
        ))

    # Sort dated entries strictly in chronological order
    dated.sort(key=lambda e: (e.time, -int(e.confidence)))

    # Group into episodes
    episodes: list[TimelineEpisode] = []
    if dated:
        gap = timedelta(minutes=episode_gap_minutes)
        current_entries = [dated[0]]
        episode_id = 1

        for entry in dated[1:]:
            prev_time = current_entries[-1].time
            if (entry.time - prev_time) <= gap:
                current_entries.append(entry)
            else:
                # Close out previous episode
                episodes.append(TimelineEpisode(
                    episode_id=episode_id,
                    start_time=current_entries[0].time,
                    end_time=current_entries[-1].time,
                    event_count=len(current_entries),
                    modules_involved=list(set(e.module for e in current_entries)),
                    entries=current_entries,
                    narrative=_generate_episode_narrative(current_entries),
                ))
                episode_id += 1
                current_entries = [entry]

        # Final episode
        if current_entries:
            episodes.append(TimelineEpisode(
                episode_id=episode_id,
                start_time=current_entries[0].time,
                end_time=current_entries[-1].time,
                event_count=len(current_entries),
                modules_involved=list(set(e.module for e in current_entries)),
                entries=current_entries,
                narrative=_generate_episode_narrative(current_entries),
            ))

    return Timeline(entries=dated, episodes=episodes, undated_findings=undated)
