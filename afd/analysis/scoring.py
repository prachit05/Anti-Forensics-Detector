"""Confidence scoring and multi-artifact correlation engine.

Forensic concept
----------------
Isolated forensic artifacts often have alternative, innocent explanations:
  - Timestomping indicator 'si_before_fn' can occasionally happen during file extraction.
  - SDelete or CCleaner installation could be residual from past IT maintenance.
  - Event log gaps can happen during system reboots or power loss.

However, the forensic principle of *multi-source corroboration* states that when independent
artifacts from different OS subsystems agree with each other within the same timeframe,
an innocent explanation becomes much less likely:

1. Direct Tool-to-Action Correlation:
   - Tool Execution (Prefetch / UserAssist / RunMRU) + File Destruction (MFT deleted entries):
     e.g., SDelete executed at 14:15, and at 14:18 MFT entries show 'ZZZZZZZZ.ZZZ' mangling.
     The tool trace shows the capability was used; the MFT trace shows the act.
   - Tool Execution + Timestomping:
     e.g., NewFileTime launched at 11:20, and files show $SI altered at 11:22.
   - Tool Execution + Log Clearing:
     e.g., Wevtutil command in RunMRU/Prefetch + Event 1102 logged at 15:30.
   Only *execution* traces raise an action's confidence. A tool binary that merely sits on
   disk, or an install record, is added as context but changes nothing: having a tool is
   not using it.
   A pair is only linked when at least one side is MEDIUM or above (two weak signals that
   happen to be close in time do not make a strong one), and findings already explained
   as an installer / setup burst are never raised. A built-in tool (wevtutil, cipher),
   LOW on its own, is raised to MEDIUM when its matching action is found.

2. Coordinated Anti-Forensics Campaign:
   - When 3 or more distinct anti-forensic techniques occur in close succession
     (e.g. Timestomping + Log Clearing + File Wiping within 2 hours), this suggests
     a deliberate, multi-stage cover-up.
   - Only findings at campaign_min_confidence (default MEDIUM) or above, from the
     rule-based detectors, count. LOW findings are mostly ordinary system activity
     (Windows setup and updates produce thousands of them in an hour), and ML outliers
     only support other evidence.

3. Undated free-space wiping is linked to any recorded run of a free-space wiper,
   because a wiped region has no timestamp of its own.

Honest limits
-------------
- Corroboration relies on available artifacts. If the attacker also wiped the prefetch folder
  or if event logs were cleared completely before logging could occur, correlation links
  may be partial.
- Correlation never asserts legal culpability or user identity beyond the recorded Windows
  user account; it reports technical corroboration.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from afd.core.config import detector_settings, merge_config
from afd.core.finding import Confidence, Finding, assign_ids, sort_findings

DEFAULT_CONFIG = {
    "correlation_window_minutes": 30.0,
    "campaign_window_hours": 2.0,
    "min_campaign_techniques": 3,
    "campaign_min_confidence": "MEDIUM",
    "corroboration_score_boost": 2,
}

# Which tool names explain which kind of action
_TOOL_ACTIONS = {
    "file_wiping": ("sdelete", "eraser", "bleachbit", "ccleaner"),
    "timestomp": ("timestomp", "newfiletime", "attributechanger", "setmace"),
    "log_wiping": ("wevtutil", "ccleaner", "bleachbit"),
}

# Detectors whose findings can make up a campaign (ML and the campaigns themselves cannot)
RULE_MODULES = {"timestomp", "log_wiping", "file_wiping", "freespace", "hidden_files", "tool_traces"}

# Indicators meaning "explained by an installer / setup burst": never boosted by a tool nearby
_BULK_INDICATORS = {"bulk_pattern", "volume_burst"}

# Tools that wipe free space (matched against the tool finding's subject)
_FREESPACE_WIPERS = ("sdelete", "cipher", "ccleaner", "eraser", "bleachbit")


def _get_time(f: Finding) -> datetime | None:
    if f.event_time is None:
        return None
    if f.event_time.tzinfo is None:
        return f.event_time.replace(tzinfo=timezone.utc)
    return f.event_time.astimezone(timezone.utc)


def _is_execution_trace(f: Finding) -> bool:
    """Prefetch / UserAssist / RunMRU show the tool was run; MFT presence or an install key do not."""
    t = f.technique.lower()
    return "exec" in t or "runmru" in t


def correlate_findings(
    findings: list[Finding],
    cfg: dict | None = None,
) -> tuple[list[Finding], list[Finding]]:
    """Cross-correlate findings across disparate modules and generate campaign findings.

    Returns:
        (updated_findings: list[Finding] with corroborated scores and reasons,
         campaign_findings: list[Finding] representing multi-vector campaigns)
    """
    cfg = merge_config(DEFAULT_CONFIG, detector_settings("analysis"), cfg or {})
    corr_window = timedelta(minutes=cfg.get("correlation_window_minutes", 30.0))
    camp_window = timedelta(hours=cfg.get("campaign_window_hours", 2.0))
    min_techniques = cfg.get("min_campaign_techniques", 3)
    camp_min_conf = Confidence[str(cfg.get("campaign_min_confidence", "MEDIUM")).upper()]
    boost = cfg.get("corroboration_score_boost", 2)

    # Separate tool traces from the actions they could explain
    tool_findings = [f for f in findings if f.module == "tool_traces" and f.event_time is not None]
    action_findings = [f for f in findings if f.module in _TOOL_ACTIONS and f.event_time is not None]

    corroborated_pairs = set()

    for tool_f in tool_findings:
        t_time = _get_time(tool_f)
        tool_subject = tool_f.subject.lower()
        executed = _is_execution_trace(tool_f)

        for act_f in action_findings:
            a_time = _get_time(act_f)

            # Check temporal window: within corr_window before or after
            time_diff = abs((a_time - t_time).total_seconds())
            if time_diff > corr_window.total_seconds():
                continue

            pair_key = (tool_f.id, act_f.id)
            if pair_key in corroborated_pairs:
                continue
            if not any(name in tool_subject for name in _TOOL_ACTIONS[act_f.module]):
                continue
            if max(tool_f.confidence, act_f.confidence) < Confidence.MEDIUM:
                continue
            if _BULK_INDICATORS & set(act_f.evidence.get("indicators", [])):
                continue
            corroborated_pairs.add(pair_key)

            if not executed:
                # Presence only: note it for the examiner, but do not change the confidence
                act_f.reasons.append(
                    f"Context: {tool_f.title} ({tool_f.artifact}) is dated within {time_diff / 60:.1f} minutes. "
                    "This shows the tool was present, not that it was run."
                )
                continue

            act_f.score += boost
            act_f.reasons.append(
                f"Corroborated: {tool_f.title} ({tool_f.artifact}) is within "
                f"{time_diff / 60:.1f} minutes of this {act_f.technique.lower()} finding."
            )
            if act_f.confidence == Confidence.LOW:
                act_f.confidence = Confidence.MEDIUM
            elif act_f.confidence == Confidence.MEDIUM and act_f.score >= 5:
                act_f.confidence = Confidence.HIGH

            # Also annotate the tool finding; a built-in tool (LOW on its own) that
            # lines up with the matching action is now worth attention
            tool_f.reasons.append(
                f"Corroborated: {act_f.technique} finding {act_f.id or act_f.title} is dated "
                f"{_get_time(act_f):%Y-%m-%d %H:%M:%S} UTC, within the correlation window."
            )
            if tool_f.confidence == Confidence.LOW:
                tool_f.confidence = Confidence.MEDIUM
                tool_f.score += boost

    # Free-space wiping has no time of its own: link it to any recorded wiper run
    wiper_runs = [f for f in tool_findings
                  if any(w in f.subject.lower() for w in _FREESPACE_WIPERS) and _is_execution_trace(f)]
    for fs_f in (f for f in findings if f.module == "freespace"):
        if not wiper_runs:
            break
        names = ", ".join(sorted({w.subject for w in wiper_runs}))
        fs_f.score += boost
        fs_f.reasons.append(f"Corroborated: a free-space wiping tool was run on this system ({names}).")
        if fs_f.confidence == Confidence.LOW:
            fs_f.confidence = Confidence.MEDIUM

    # Detect Coordinated Anti-Forensics Campaigns (from MEDIUM/HIGH rule-based findings only)
    campaign_findings: list[Finding] = []
    dated_findings = [f for f in findings if f.event_time is not None
                      and f.module in RULE_MODULES and f.confidence >= camp_min_conf]
    dated_findings.sort(key=_get_time)

    if len(dated_findings) >= min_techniques:
        start_idx = 0
        while start_idx < len(dated_findings):
            start_f = dated_findings[start_idx]
            s_time = _get_time(start_f)

            window_group = [start_f]
            for j in range(start_idx + 1, len(dated_findings)):
                next_f = dated_findings[j]
                if (_get_time(next_f) - s_time) <= camp_window:
                    window_group.append(next_f)
                else:
                    break

            unique_modules = set(f.module for f in window_group)
            if len(unique_modules) >= min_techniques:
                earliest = min(_get_time(f) for f in window_group)
                latest = max(_get_time(f) for f in window_group)
                dur_min = (latest - earliest).total_seconds() / 60.0

                mod_list_str = ", ".join(sorted(unique_modules))
                camp_reasons = [
                    f"{len(window_group)} {camp_min_conf.name}-or-higher findings across {len(unique_modules)} "
                    f"distinct techniques ({mod_list_str}) within a {dur_min:.1f} minute window.",
                    f"Chronology spans from {earliest.strftime('%H:%M:%S UTC')} to {latest.strftime('%H:%M:%S UTC')}.",
                    "Member findings: " + ", ".join(f.id or f.title for f in window_group) + ".",
                ]

                campaign_findings.append(Finding(
                    module="analysis",
                    technique="Coordinated Anti-Forensics Campaign",
                    mitre="T1070",
                    title=f"Coordinated Anti-Forensics Campaign ({len(unique_modules)} techniques in {dur_min:.0f} mins)",
                    confidence=Confidence.HIGH,
                    score=8,
                    subject="Possible coordinated cover-up",
                    artifact=f"Correlated across: {mod_list_str}",
                    reasons=camp_reasons,
                    benign_notes=[
                        "This cluster is only as strong as its members. Check each member finding: "
                        "maintenance (an administrator running a cleaner and clearing logs) can also "
                        "produce several techniques close together.",
                        "Each member's time has its own meaning (execution, MFT change, event logged), "
                        "so the order within the window is approximate.",
                    ],
                    evidence={
                        "event_count": len(window_group),
                        "techniques": sorted(unique_modules),
                        "member_ids": [f.id for f in window_group],
                        "start_time": earliest.isoformat(),
                        "end_time": latest.isoformat(),
                        "duration_minutes": round(dur_min, 1),
                    },
                    event_time=earliest,
                    time_meaning="time of the earliest member finding",
                ))
                # Skip forward past this window
                start_idx += len(window_group)
            else:
                start_idx += 1

    return assign_ids(sort_findings(findings)), assign_ids(campaign_findings)
