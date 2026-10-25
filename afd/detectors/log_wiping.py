"""Event-log wiping detector (MITRE ATT&CK T1070.001, Clear Windows Event Logs).

Forensic concept
----------------
Attackers clear or edit the Windows event logs to remove the record of what they did.
Windows leaves several traces that this detector looks for:

  1. Clear events    Event 1102 (Security log) and Event 104 (System log, names the
                     cleared channel) are written by the OS itself, with the account
                     that did it. This is direct evidence that a clear happened.
  2. Record-ID gaps  Every event gets an EventRecordID that rises by 1 and is never
                     reused. Missing IDs *inside* the log mean individual records were
                     deleted (log-editing tools do this to hide only certain events).
  3. Silence         A busy log that suddenly has hours with no events at all.
  4. Header mismatch The file header says the next record is N, but the newest record
                     present is lower: records at the end are missing or unreadable.
  5. History missing The log was never full (so nothing was overwritten by wrap-around)
                     yet starts at record >1, or starts much later than the System log.

Honest limits: "confidence" here means how sure we are that the *action* happened, not
who did it or why. Administrators clear logs legitimately, machines are switched off,
and clocks get corrected. So gaps are checked against restart, sleep and clock-change
events from the System log, and a gap that one of those explains is not reported.
If no System log is supplied, those explanations are unavailable and the finding says so.
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from afd.core.config import detector_settings, merge_config
from afd.core.finding import Confidence, Finding, assign_ids, sort_findings

DEFAULT_CONFIG = {
    "time_gap_hours": 6.0,
    "sparse_gap_factor": 50,
    "anchor_window_minutes": 5.0,
    "min_missing_records": 1,
    "late_start_days": 1.0,
    "peer_log": "System.evtx",
}

# Events that legitimately explain silence in a log (provider name lower-cased, event id)
ANCHOR_EVENTS = {
    ("microsoft-windows-kernel-general", 1): "system clock changed",
    ("microsoft-windows-kernel-general", 12): "operating system started",
    ("microsoft-windows-kernel-general", 13): "operating system shut down",
    ("eventlog", 6005): "event log service started (boot)",
    ("eventlog", 6006): "event log service stopped (shutdown)",
    ("microsoft-windows-kernel-power", 42): "system entered sleep",
    ("microsoft-windows-kernel-power", 107): "system resumed from sleep",
    ("microsoft-windows-power-troubleshooter", 1): "system resumed from sleep",
}

NS_PER_SECOND = 1_000_000_000


# ---------------------------------------------------------------- helpers

def _log_name(info: dict, df: pd.DataFrame) -> str:
    if info.get("file"):
        return str(info["file"])
    if len(df) and "log_file" in df.columns:
        return str(df["log_file"].iloc[0])
    return "unknown.evtx"


def _stem(name: str) -> str:
    return Path(name).stem.lower()


def _channel_to_stem(channel: str) -> str:
    """'Microsoft-Windows-PowerShell/Operational' -> file stem 'microsoft-windows-powershell%4operational'."""
    return channel.replace("/", "%4").lower()


def _ns(ts: pd.Timestamp) -> int:
    return int(ts.value)


def _series_ns(times: pd.Series) -> np.ndarray:
    """A UTC datetime column as int64 nanoseconds since 1970 (NaT -> iNaT), whatever
    resolution pandas stored it in."""
    naive = times.dt.tz_convert("UTC").dt.tz_localize(None)
    return naive.astype("datetime64[ns]").astype("int64").to_numpy()


def _ts(ns: int) -> pd.Timestamp:
    return pd.Timestamp(int(ns), tz="UTC")


def _collect_anchors(logs: list[tuple[pd.DataFrame, dict]]) -> np.ndarray:
    """Sorted array (ns since epoch) of restart / sleep / clock-change event times."""
    times = []
    for df, _info in logs:
        if df.empty:
            continue
        provider = df["provider"].fillna("").str.lower()
        for (prov, eid) in ANCHOR_EVENTS:
            hit = df[(provider == prov) & (df["event_id"] == eid)]
            times.extend(_ns(t) for t in hit["time_created"].dropna())
    return np.array(sorted(times), dtype="int64")


def _near_anchor(anchors: np.ndarray, t: pd.Timestamp, window_ns: int) -> bool:
    if anchors.size == 0 or pd.isna(t):
        return False
    v = _ns(t)
    i = np.searchsorted(anchors, v - window_ns, "left")
    return i < anchors.size and anchors[i] <= v + window_ns


def _fmt(t) -> str:
    return "unknown" if pd.isna(t) else t.strftime("%Y-%m-%d %H:%M:%S UTC")


def _hours(ns: int) -> str:
    h = ns / NS_PER_SECOND / 3600
    return f"{h:.1f} hours" if h < 48 else f"{h / 24:.1f} days"


def _find_log(logs, channel: str):
    want = _channel_to_stem(channel)
    for df, info in logs:
        if _stem(_log_name(info, df)) == want:
            return df, info
    return None


# ---------------------------------------------------------------- individual checks

def _clear_events(logs) -> tuple[list[Finding], set[str]]:
    """Checks 1: Event 1102 / 104. Also returns the stems of logs known to be cleared."""
    findings, cleared = [], set()
    for df, info in logs:
        if df.empty:
            continue
        name = _log_name(info, df)
        provider = df["provider"].fillna("").str.lower()
        hits = df[df["event_id"].isin([1102, 104]) & provider.str.contains("eventlog")]
        for r in hits.itertuples(index=False):
            data = r.data if isinstance(r.data, dict) else {}
            channel = "Security" if r.event_id == 1102 else (data.get("Channel") or r.channel or "unknown")
            cleared.add(_channel_to_stem(channel))
            who = data.get("SubjectUserName") or "unknown account"
            domain = data.get("SubjectDomainName")
            account = f"{domain}\\{who}" if domain else who

            reasons = [
                f"Windows recorded Event {r.event_id} at {_fmt(r.time_created)}: the "
                f"{channel} log was cleared by {account}.",
            ]
            evidence = {
                "event_id": int(r.event_id), "record_id": int(r.record_id),
                "cleared_log": channel, "account": account,
                "sid": data.get("SubjectUserSid") or r.user_sid,
                "logon_id": data.get("SubjectLogonId"), "computer": r.computer,
                "recorded_in": name, "backup_path": data.get("BackupPath"),
            }
            # Correlate with the cleared log itself, if we were given it
            target = _find_log(logs, channel)
            if target is not None and not target[0].empty:
                tdf, _ = target
                oldest = tdf["time_created"].min()
                evidence["oldest_event_in_cleared_log"] = _fmt(oldest)
                if oldest >= r.time_created - pd.Timedelta(seconds=60):
                    reasons.append(f"The supplied {channel} log contains nothing older than the "
                                   f"clear time (oldest event {_fmt(oldest)}), which matches: "
                                   f"its earlier history is gone.")
                else:
                    reasons.append(f"The supplied {channel} log still has events from before the "
                                   f"clear (oldest {_fmt(oldest)}); it may be a copy taken earlier "
                                   f"or the clear may have been of a different log instance.")
            findings.append(Finding(
                module="log_wiping", technique="Clear Windows Event Logs", mitre="T1070.001",
                title=f"{channel} event log cleared by {account}",
                confidence=Confidence.HIGH, score=10, subject=channel,
                artifact=f"{name} record {r.record_id}", reasons=reasons,
                benign_notes=["Windows writes this event itself, so the clear happened. "
                              "Administrators also clear logs for routine maintenance; "
                              "this does not show intent."],
                evidence=evidence, event_time=r.time_created.to_pydatetime(),
                time_meaning="when the log was cleared"))
    return findings, cleared


def _record_gaps(df, info, name, anchors, cfg, have_system) -> tuple[list[Finding], set[int]]:
    """Check 2: IDs missing inside the log. Returns findings and the 'before' IDs they cover."""
    findings, covered = [], set()
    if df.empty:
        return findings, covered
    unique = df.drop_duplicates("record_id").sort_values("record_id")
    ids = unique["record_id"].to_numpy()
    times = _series_ns(unique["time_created"])
    diffs = np.diff(ids)
    parse_errors = int(info.get("parse_errors", 0) or 0)
    total_missing = int(np.maximum(diffs - 1, 0).sum())
    gap_ns_limit = int(cfg["time_gap_hours"] * 3600 * NS_PER_SECOND)

    for i in np.nonzero(diffs - 1 >= cfg["min_missing_records"])[0]:
        missing = int(diffs[i] - 1)
        before_id, after_id = int(ids[i]), int(ids[i + 1])
        t0, t1 = _ts(times[i]), _ts(times[i + 1])
        score = 3
        reasons = [f"{name} jumps from record {before_id} to {after_id}: {missing} record(s) "
                   f"are missing from inside the log (between {_fmt(t0)} and {_fmt(t1)}). "
                   f"Record IDs are never reused, so these were deleted."]
        benign = []
        span_ns = int((t1 - t0).value) if not (pd.isna(t0) or pd.isna(t1)) else 0
        if span_ns >= gap_ns_limit and not _near_anchor(anchors, t0, int(cfg["anchor_window_minutes"] * 60 * NS_PER_SECOND)) \
                and not _near_anchor(anchors, t1, int(cfg["anchor_window_minutes"] * 60 * NS_PER_SECOND)):
            score += 2
            reasons.append(f"The same spot also has {_hours(span_ns)} with no events at all, "
                           f"which fits records having been removed.")
            covered.add(before_id)
        if parse_errors >= total_missing and parse_errors > 0:
            score -= 2
            benign.append(f"{parse_errors} record(s) in this file failed to parse; the missing IDs "
                          f"may be unreadable rather than deleted.")
        if not have_system:
            benign.append("No System log was supplied, so restarts could not be ruled out.")
        confidence = Confidence.HIGH if score >= 5 else Confidence.MEDIUM if score >= 3 else Confidence.LOW
        findings.append(Finding(
            module="log_wiping", technique="Selective event deletion", mitre="T1070.001",
            title=f"{missing} event record(s) missing inside {name}",
            confidence=confidence, score=score, subject=name,
            artifact=f"{name} records {before_id}-{after_id}", reasons=reasons, benign_notes=benign,
            evidence={"log": name, "record_before_gap": before_id, "record_after_gap": after_id,
                      "missing_records": missing, "time_before_gap": _fmt(t0),
                      "time_after_gap": _fmt(t1), "parse_errors_in_file": parse_errors},
            event_time=t0.to_pydatetime() if not pd.isna(t0) else None,
            time_meaning="last intact event before the deleted records"))
    return findings, covered


def _time_gaps(df, info, name, anchors, cfg, covered, have_system) -> list[Finding]:
    """Check 3: long silence in a log that is normally busy and not explained by a restart."""
    if len(df) < 20:
        return []
    ordered = df.sort_values("record_id")
    ids = ordered["record_id"].to_numpy()
    t = _series_ns(ordered["time_created"])
    diffs = np.diff(t)
    positive = diffs[diffs > 0]
    if positive.size == 0:
        return []
    median = float(np.median(positive))
    limit = max(cfg["time_gap_hours"] * 3600 * NS_PER_SECOND, cfg["sparse_gap_factor"] * median)
    window = int(cfg["anchor_window_minutes"] * 60 * NS_PER_SECOND)

    findings = []
    for i in np.nonzero(diffs >= limit)[0]:
        if int(ids[i]) in covered:                 # already reported with the record-ID gap
            continue
        t0, t1 = _ts(t[i]), _ts(t[i + 1])
        if _near_anchor(anchors, t0, window) or _near_anchor(anchors, t1, window):
            continue                               # restart, sleep or clock change explains it
        benign = ["The machine may simply have been idle or powered off without logging a "
                  "shutdown event (a crash or a paused virtual machine)."]
        if not have_system:
            benign.append("No System log was supplied, so restarts could not be ruled out.")
        findings.append(Finding(
            module="log_wiping", technique="Gap in event log", mitre="T1070.001",
            title=f"{_hours(int(diffs[i]))} with no events in {name}",
            confidence=Confidence.LOW, score=2, subject=name,
            artifact=f"{name} records {int(ids[i])}-{int(ids[i + 1])}",
            reasons=[f"{name} normally logs an event every {median / NS_PER_SECOND:.0f} s or so "
                     f"but is silent from {_fmt(t0)} to {_fmt(t1)}, with no restart, sleep or "
                     f"clock-change event nearby to explain it."],
            benign_notes=benign,
            evidence={"log": name, "silent_from": _fmt(t0), "silent_to": _fmt(t1),
                      "median_spacing_seconds": round(median / NS_PER_SECOND, 1)},
            event_time=t0.to_pydatetime(), time_meaning="last event before the silence"))
    return findings


def _header_mismatch(df, info, name) -> list[Finding]:
    """Check 4: file header promises more records than the file holds."""
    nxt = info.get("next_record_number")
    if nxt is None:
        return []
    newest = int(df["record_id"].max()) if not df.empty else 0
    if nxt <= newest + 1:
        return []
    missing = int(nxt - newest - 1)
    parse_errors = int(info.get("parse_errors", 0) or 0)
    score = 3 - (2 if parse_errors >= missing else 0)
    benign = []
    if parse_errors:
        benign.append(f"{parse_errors} record(s) failed to parse and may account for the difference.")
    what = "is empty" if df.empty else f"ends at record {newest}"
    return [Finding(
        module="log_wiping", technique="Missing newest records", mitre="T1070.001",
        title=f"{name} header expects more records than the file holds",
        confidence=Confidence.MEDIUM if score >= 3 else Confidence.LOW, score=score,
        subject=name, artifact=f"{name} file header",
        reasons=[f"The file header says the next record would be {nxt}, but the log {what}. "
                 f"{missing} record(s) at the end were removed or cannot be read."],
        benign_notes=benign,
        evidence={"log": name, "header_next_record": int(nxt), "newest_record_present": newest,
                  "parse_errors": parse_errors},
        event_time=df["time_created"].max().to_pydatetime() if not df.empty else None,
        time_meaning="newest event still present")]


def _history_missing(df, info, name, peer_first, cfg) -> list[Finding]:
    """Check 5: log never filled up, yet its early history is gone."""
    if df.empty or info.get("is_full"):
        return []
    first_id = int(df["record_id"].min())
    first_time = df["time_created"].min()
    score, reasons = 0, []
    if first_id > 1:
        score += 2
        reasons.append(f"The oldest record present is {first_id}, not 1, although the log was "
                       f"never full, so nothing was overwritten by wrap-around.")
    if peer_first is not None and not pd.isna(peer_first):
        late = (first_time - peer_first).total_seconds() / 86400
        if late >= cfg["late_start_days"]:
            score += 2
            reasons.append(f"The log's first event is {_fmt(first_time)}, {late:.1f} days after the "
                           f"System log's first event ({_fmt(peer_first)}).")
    if score == 0:
        return []
    return [Finding(
        module="log_wiping", technique="Log history missing", mitre="T1070.001",
        title=f"{name} is missing its early history",
        confidence=Confidence.MEDIUM if score >= 4 else Confidence.LOW, score=score,
        subject=name, artifact=f"{name}", reasons=reasons,
        benign_notes=["Logs can also be archived and restarted by policy, or reset when a "
                      "machine is rebuilt from an image."],
        evidence={"log": name, "oldest_record_id": first_id, "first_event": _fmt(first_time),
                  "peer_first_event": _fmt(peer_first) if peer_first is not None else None},
        event_time=first_time.to_pydatetime(), time_meaning="first event the log still holds")]


# ---------------------------------------------------------------- the detector

def detect(logs: list[tuple[pd.DataFrame, dict]], cfg: dict | None = None) -> list[Finding]:
    """Run all log-wiping checks.

    logs: a list of (DataFrame, info) pairs exactly as returned by
    evtx_parser.load_evtx(). Supply the System log as well as the one you care about:
    its restart / sleep / clock events are what separate a real gap from a power-off.
    """
    cfg = merge_config(DEFAULT_CONFIG, detector_settings("log_wiping"), cfg or {})
    logs = [(df, info) for df, info in logs if df is not None]
    if not logs:
        return []

    peer_stem = _stem(cfg["peer_log"])
    peer = next(((df, i) for df, i in logs if _stem(_log_name(i, df)) == peer_stem), None)
    have_system = peer is not None
    peer_first = peer[0]["time_created"].min() if have_system and not peer[0].empty else None
    anchors = _collect_anchors(logs)

    findings, cleared = _clear_events(logs)
    for df, info in logs:
        name = _log_name(info, df)
        gaps, covered = _record_gaps(df, info, name, anchors, cfg, have_system)
        findings += gaps
        findings += _time_gaps(df, info, name, anchors, cfg, covered, have_system)
        findings += _header_mismatch(df, info, name)
        stem = _stem(name)
        # A log already shown to be cleared needs no second "history missing" finding.
        # The peer (System) log is the yardstick, so it is not compared with itself.
        if stem not in cleared:
            findings += _history_missing(df, info, name,
                                         None if stem == peer_stem else peer_first, cfg)
    return assign_ids(sort_findings(findings))
