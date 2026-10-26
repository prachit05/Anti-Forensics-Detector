"""Collect everything a report needs into one plain dict (shared by the HTML and PDF writers).

Forensic concept
----------------
A forensic report must let another examiner check and repeat the work. So it records:
  * what was examined: evidence paths with MD5 / SHA-256, and whether a re-hash still matches
  * how: tool version, options, which modules ran and which were skipped (and why)
  * what was found: each finding with its confidence, reasons, innocent explanations
    considered, and the raw values it rests on
  * when: the reconstructed timeline
  * the chain-of-custody log of every action the tool took
  * the limits of the method

The *conclusion* is the examiner's judgement, so the tool never writes it. It is taken
from the examiner's own text (dashboard box or --conclusion file); if none is given the
report shows a placeholder.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone

from afd.analysis import build_timeline
from afd.core.case import Case
from afd.core.finding import Confidence
from afd.pipeline import TOOL_VERSION

CONCLUSION_PLACEHOLDER = "[Not written. The examiner must add the conclusion before this report is used.]"

# Fixed method limits, printed in every report (see each detector's docstring for detail).
LIMITATIONS = [
    "Findings mean the action is likely, not proven. Every finding lists the innocent "
    "explanations that were considered.",
    "Detection depends on the artifacts that survive. A careful attacker can also remove the "
    "traces of the cleaning tool itself (prefetch, UserAssist, its own files).",
    "Timestomping: an attacker who also changes $FILE_NAME (for example by moving the file) or "
    "moves dates forward is not detected. Copies with preserved dates can look like timestomping.",
    "Log wiping: editing that keeps record IDs contiguous is not detected. Gaps next to a "
    "restart, sleep or clock change are not reported.",
    "Free-space analysis samples unallocated space and needs a full disk image. SSD TRIM and "
    "freshly formatted disks can also show large zero regions.",
    "Scope is Windows and NTFS. Other file systems (FAT, ext4, APFS) are not analysed.",
    "All times are UTC as stored in the artifacts. A wrong system clock on the source machine "
    "shifts them.",
]


def _fmt_time(value) -> str:
    if not value:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _evidence_rows(evidence: dict) -> list[tuple[str, str]]:
    """Flatten a finding's evidence dict into (key, text) rows."""
    rows = []
    for key, value in evidence.items():
        text = value if isinstance(value, str) else json.dumps(value, default=str)
        rows.append((str(key), text))
    return rows


def _auto_summary(findings, timeline, modules) -> list[str]:
    """Counts only: what the tool found, not what it means."""
    counts = Counter(f.confidence.name for f in findings)
    lines = [f"{len(findings)} finding(s) in total: {counts.get('HIGH', 0)} HIGH, "
             f"{counts.get('MEDIUM', 0)} MEDIUM, {counts.get('LOW', 0)} LOW."]
    ran = [m["label"] for m in modules if m.get("status") == "ran"]
    skipped = [m["label"] for m in modules if m.get("status") != "ran"]
    if ran:
        lines.append(f"Modules run: {', '.join(ran)}.")
    if skipped:
        lines.append(f"Modules not run: {', '.join(skipped)} (reasons in the Method section).")
    campaigns = [f for f in findings if f.module == "analysis"]
    if campaigns:
        lines.append(f"{len(campaigns)} cluster(s) of three or more different techniques within the "
                     "campaign window were found (see findings marked 'analysis').")
    if timeline.episodes:
        first, last = timeline.episodes[0].start_time, timeline.episodes[-1].end_time
        lines.append(f"Dated findings form {len(timeline.episodes)} episode(s) between "
                     f"{_fmt_time(first)} and {_fmt_time(last)}.")
    return lines


def build_context(
    result,
    case: Case | None = None,
    min_confidence: Confidence = Confidence.MEDIUM,
    examiner_conclusion: str = "",
    verification: list[dict] | None = None,
) -> dict:
    """Return the report data. `result` is an afd.pipeline.AnalysisResult.

    min_confidence: findings below it are counted but not listed (the CSV/JSON export keeps all).
    verification:   output of Case.verify_evidence() if the examiner re-hashed before reporting.
    """
    findings = list(result.findings)
    shown = [f for f in findings if f.confidence >= min_confidence]
    timeline = build_timeline(shown)          # the report timeline follows the same filter

    by_module: dict[str, Counter] = {}
    for f in findings:
        by_module.setdefault(f.module, Counter())[f.confidence.name] += 1

    return {
        "title": f"Anti-Forensics Analysis: {result.case_name}",
        "case_name": result.case_name,
        "examiner": result.examiner,
        "source": result.source,
        "options": result.options,
        "started": _fmt_time(result.started_utc),
        "finished": _fmt_time(result.finished_utc),
        "generated": _fmt_time(datetime.now(timezone.utc)),
        "tool_version": TOOL_VERSION,
        "artifacts": result.artifacts,
        "evidence": result.evidence,
        "verification": verification,
        "modules": result.modules,
        "module_counts": {m: dict(c) for m, c in sorted(by_module.items())},
        "counts": {c.name: sum(f.confidence == c for f in findings) for c in reversed(Confidence)},
        "min_confidence": min_confidence.name,
        "omitted": len(findings) - len(shown),
        "auto_summary": _auto_summary(findings, result.timeline, result.modules),
        "findings": [
            {**f.to_dict(), "time_text": _fmt_time(f.event_time), "evidence_rows": _evidence_rows(f.evidence)}
            for f in shown
        ],
        "episodes": [
            {
                "id": ep.episode_id,
                "start": _fmt_time(ep.start_time),
                "end": _fmt_time(ep.end_time),
                "duration": f"{ep.duration_minutes():.1f} min",
                "narrative": ep.narrative,
                "entries": [
                    {"time": e.time.strftime("%H:%M:%S"), "id": e.finding_id, "confidence": e.confidence.name,
                     "phase": e.phase, "title": e.title, "time_meaning": e.time_meaning}
                    for e in ep.entries
                ],
            }
            for ep in timeline.episodes
        ],
        "undated": [{"id": f.id, "confidence": f.confidence.name, "title": f.title, "artifact": f.artifact}
                    for f in timeline.undated_findings],
        "conclusion": examiner_conclusion.strip() or CONCLUSION_PLACEHOLDER,
        "conclusion_missing": not examiner_conclusion.strip(),
        "limitations": LIMITATIONS,
        "custody_log": case.read_log() if case else [],
    }
