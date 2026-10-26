"""Confidence scoring and multi-artifact correlation engine.

Forensic concept
----------------
Isolated forensic artifacts often have alternative, innocent explanations:
  - Timestomping indicator 'si_before_fn' can occasionally happen during file extraction.
  - SDelete or CCleaner installation could be residual from past IT maintenance.
  - Event log gaps can happen during system reboots or power loss.

However, the forensic principle of *multi-source corroboration* states that when independent
artifacts from different OS subsystems corroborate each other within the same timeframe,
the probability of an innocent explanation drops exponentially:

1. Direct Tool-to-Action Correlation:
   - Tool Execution (Prefetch / UserAssist) + File Destruction (MFT deleted entries):
     e.g., SDelete executed at 14:15, and at 14:18 MFT entries show 'ZZZZZZZZ.ZZZ' mangling.
     The tool trace proves capability/intent, and the MFT trace proves the act.
   - Tool Execution + Timestomping:
     e.g., NewFileTime launched at 11:20, and files show $SI altered at 11:22.
   - Tool Execution + Log Clearing:
     e.g., Wevtutil command in RunMRU/Prefetch + Event 1102 logged at 15:30.

2. Coordinated Anti-Forensics Campaign:
   - When 3 or more distinct anti-forensic techniques occur in close succession
     (e.g. Timestomping + Log Clearing + File Wiping within 2 hours), this represents
     a deliberate, multi-stage cover-up operation.
   - Only MEDIUM or HIGH findings from the rule-based detectors count. LOW findings are,
     by definition, patterns an innocent explanation fits (Windows setup and updates
     produce thousands of them in an hour), and ML outliers only support other evidence.

3. Undated free-space wiping is linked to any recorded run of a free-space wiper,
   because a wiped region has no timestamp of its own.

A pair is only linked when at least one side is MEDIUM or above: two weak signals that
happen to be close in time do not make a strong one.

Honest limits
-------------
- Corroboration relies on available artifacts. If the attacker also wiped the prefetch folder
  or if event logs were cleared completely before logging could occur, correlation links
  may be partial.
- Correlation never asserts legal culpability or user identity beyond the recorded Windows
  user account; it reports strong technical corroboration.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from afd.core.config import detector_settings, merge_config
from afd.core.finding import Confidence, Finding, assign_ids, confidence_from_score, sort_findings

DEFAULT_CONFIG = {
    "correlation_window_minutes": 30.0,
    "campaign_window_hours": 2.0,
    "min_campaign_techniques": 3,
    "corroboration_score_boost": 2,
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
    boost = cfg.get("corroboration_score_boost", 2)

    # Separate tool traces, file wipes, timestomps, and log wipes
    tool_findings = [f for f in findings if f.module == "tool_traces" and f.event_time is not None]
    action_findings = [f for f in findings if f.module in ("file_wiping", "timestomp", "log_wiping") and f.event_time is not None]

    corroborated_pairs = set()

    for tool_f in tool_findings:
        t_time = _get_time(tool_f)
        if not t_time:
            continue
        tool_subject = tool_f.subject.lower()

        for act_f in action_findings:
            a_time = _get_time(act_f)
            if not a_time:
                continue

            # Check temporal window: within corr_window before or after
            time_diff = abs((a_time - t_time).total_seconds())
            if time_diff > corr_window.total_seconds():
                continue

            pair_key = (tool_f.id, act_f.id)
            if pair_key in corroborated_pairs:
                continue
            if max(tool_f.confidence, act_f.confidence) < Confidence.MEDIUM:
                continue
            if _BULK_INDICATORS & set(act_f.evidence.get("indicators", [])):
                continue

            # Assess causal links
            is_match = False
            match_reason = ""

            # SDelete / Eraser -> File Wiping
            if act_f.module == "file_wiping" and ("sdelete" in tool_subject or "eraser" in tool_subject or "bleachbit" in tool_subject):
                is_match = True
                match_reason = (
                    f"Strongly corroborated: {tool_f.title} occurred within "
                    f"{time_diff / 60:.1f} minutes of this file wiping event ({tool_f.artifact})."
                )

            # Timestomp tools -> Timestomping
            elif act_f.module == "timestomp" and ("timestomp" in tool_subject or "newfiletime" in tool_subject or "attributechanger" in tool_subject):
                is_match = True
                match_reason = (
                    f"Strongly corroborated: Timestamp utility '{tool_f.subject}' executed within "
                    f"{time_diff / 60:.1f} minutes of this timestomped file ({tool_f.artifact})."
                )

            # Wevtutil -> Log Wiping
            elif act_f.module == "log_wiping" and "wevtutil" in tool_subject:
                is_match = True
                match_reason = (
                    f"Strongly corroborated: Event log manipulation utility '{tool_f.subject}' "
                    f"ran within {time_diff / 60:.1f} minutes of this log clearing/gap event."
                )

            if is_match:
                corroborated_pairs.add(pair_key)
                # Boost confidence of the action finding
                act_f.score += boost
                act_f.reasons.append(match_reason)
                if act_f.confidence == Confidence.LOW:
                    act_f.confidence = Confidence.MEDIUM
                elif act_f.confidence == Confidence.MEDIUM and act_f.score >= 5:
                    act_f.confidence = Confidence.HIGH

                # Also annotate the tool finding; a built-in tool (LOW on its own) that
                # lines up with the matching action is now worth attention
                tool_f.reasons.append(
                    f"Corroborated: Evidence of resulting {act_f.technique} activity was detected at {act_f.event_time}."
                )
                if tool_f.confidence == Confidence.LOW:
                    tool_f.confidence = Confidence.MEDIUM
                    tool_f.score += boost

    # Free-space wiping has no time of its own: link it to any recorded wiper run
    wiper_runs = [f for f in tool_findings
                  if any(w in f.subject.lower() for w in _FREESPACE_WIPERS)
                  and "execut" in (f.technique + f.title).lower()]
    for fs_f in (f for f in findings if f.module == "freespace"):
        if not wiper_runs:
            break
        names = ", ".join(sorted({w.subject for w in wiper_runs}))
        fs_f.score += boost
        fs_f.reasons.append(f"Corroborated: a free-space wiping tool was run on this system ({names}).")
        if fs_f.confidence == Confidence.LOW:
            fs_f.confidence = Confidence.MEDIUM

    # Detect Coordinated Anti-Forensics Campaigns
    campaign_findings: list[Finding] = []
    dated_findings = [f for f in findings if f.event_time is not None
                      and f.module in RULE_MODULES and f.confidence >= Confidence.MEDIUM]
    dated_findings.sort(key=lambda f: _get_time(f) or datetime.min.replace(tzinfo=timezone.utc))

    if len(dated_findings) >= min_techniques:
        start_idx = 0
        while start_idx < len(dated_findings):
            start_f = dated_findings[start_idx]
            s_time = _get_time(start_f)
            if not s_time:
                start_idx += 1
                continue

            window_group = [start_f]
            for j in range(start_idx + 1, len(dated_findings)):
                next_f = dated_findings[j]
                n_time = _get_time(next_f)
                if n_time and (n_time - s_time) <= camp_window:
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
                    f"Detected {len(window_group)} anti-forensic events across {len(unique_modules)} distinct "
                    f"techniques ({mod_list_str}) within a {dur_min:.1f} minute window.",
                    f"Chronology spans from {earliest.strftime('%H:%M:%S UTC')} to {latest.strftime('%H:%M:%S UTC')}.",
                ]

                campaign_findings.append(Finding(
                    module="analysis",
                    technique="Coordinated Anti-Forensics Campaign",
                    mitre="T1070",
                    title=f"Coordinated Anti-Forensics Campaign ({len(unique_modules)} techniques in {dur_min:.0f} mins)",
                    confidence=Confidence.HIGH,
                    score=8,
                    subject="System-wide incident cover-up",
                    artifact=f"Correlated across: {mod_list_str}",
                    reasons=camp_reasons,
                    benign_notes=["Only MEDIUM/HIGH findings were counted, so routine setup and update "
                                  "activity is unlikely to explain this. An administrator performing "
                                  "several clean-up tasks in one session would still look similar."],
                    evidence={
                        "event_count": len(window_group),
                        "techniques": list(unique_modules),
                        "start_time": earliest.isoformat(),
                        "end_time": latest.isoformat(),
                        "duration_minutes": round(dur_min, 1),
                    },
                    event_time=earliest,
                    time_meaning="campaign inception timestamp",
                ))
                # Skip forward past this window
                start_idx += len(window_group)
            else:
                start_idx += 1

    return assign_ids(sort_findings(findings)), assign_ids(campaign_findings)
