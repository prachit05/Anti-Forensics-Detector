"""Tests for the log-wiping detector, using DataFrames shaped like evtx_parser.load_evtx()."""
import pandas as pd

from afd.core.finding import Confidence
from afd.detectors import log_wiping

START = pd.Timestamp("2026-10-20 08:00:00", tz="UTC")
COLUMNS = ["record_id", "time_created", "event_id", "provider", "channel",
           "computer", "level", "user_sid", "data", "log_file"]


def make_log(file, ids, times, extra=(), channel=None, provider="Some-Provider", **info):
    """Build (df, info). `extra` rows are dicts: record_id, time, event_id, provider, data."""
    rows = [dict(record_id=i, time_created=t, event_id=4624, provider=provider,
                 channel=channel or Path_stem(file), computer="WIN11-AFD", level="4",
                 user_sid="S-1-5-18", data={}, log_file=file) for i, t in zip(ids, times)]
    for e in extra:
        rows.append(dict(record_id=e["record_id"], time_created=e["time"], event_id=e["event_id"],
                         provider=e["provider"], channel=e.get("channel") or Path_stem(file),
                         computer="WIN11-AFD", level="4", user_sid="S-1-5-18",
                         data=e.get("data", {}), log_file=file))
    df = pd.DataFrame(rows, columns=COLUMNS)
    df["time_created"] = pd.to_datetime(df["time_created"], utc=True)
    df = df.sort_values("record_id").reset_index(drop=True)
    meta = {"file": file, "records": len(df), "parse_errors": 0, "is_full": False,
            "is_dirty": False, "next_record_number": int(df.record_id.max()) + 1 if len(df) else 1}
    meta.update(info)
    return df, meta


def Path_stem(file):
    return file.rsplit(".", 1)[0]


def minutes(n, start=START):
    return [start + pd.Timedelta(minutes=i) for i in range(n)]


def boot(record_id, t):
    return dict(record_id=record_id, time=t, event_id=12, provider="Microsoft-Windows-Kernel-General")


def clean_system(n=300):
    return make_log("System.evtx", range(1, n + 1), minutes(n))


# ---------------------------------------------------------------- clean

def test_clean_logs_raise_nothing():
    assert log_wiping.detect([clean_system(), make_log("Security.evtx", range(1, 301), minutes(300))]) == []


# ---------------------------------------------------------------- clear events

def test_security_log_clear_event_1102():
    clear_time = START + pd.Timedelta(hours=3)
    sec = make_log("Security.evtx", [], [], extra=[dict(
        record_id=1, time=clear_time, event_id=1102, provider="Microsoft-Windows-Eventlog",
        channel="Security",
        data={"SubjectUserName": "analyst", "SubjectDomainName": "WIN11-AFD",
              "SubjectUserSid": "S-1-5-21-1-2-3-1001", "SubjectLogonId": "0x3e7"})])
    # more events after the clear
    more = make_log("Security.evtx", range(2, 40), minutes(38, clear_time + pd.Timedelta(minutes=1)))[0]
    df = pd.concat([sec[0], more]).reset_index(drop=True)
    findings = log_wiping.detect([clean_system(), (df, sec[1] | {"records": len(df)})])
    f = next(x for x in findings if x.technique == "Clear Windows Event Logs")
    assert f.confidence == Confidence.HIGH and f.mitre == "T1070.001"
    assert f.evidence["account"] == "WIN11-AFD\\analyst"
    assert f.evidence["cleared_log"] == "Security"
    assert f.event_time == clear_time.to_pydatetime()
    assert "nothing older than the clear time" in " ".join(f.reasons)
    assert f.benign_notes                                     # states that this does not show intent


def test_event_104_names_the_cleared_channel():
    t = START + pd.Timedelta(hours=1)
    system = make_log("System.evtx", range(1, 301), minutes(300), extra=[dict(
        record_id=301, time=t, event_id=104, provider="Microsoft-Windows-Eventlog", channel="System",
        data={"SubjectUserName": "bob", "SubjectDomainName": "CORP", "Channel": "Application"})])
    system[1]["next_record_number"] = 302
    f = next(x for x in log_wiping.detect([system]) if x.technique == "Clear Windows Event Logs")
    assert f.evidence["cleared_log"] == "Application" and f.evidence["account"] == "CORP\\bob"


def test_cleared_log_is_not_also_reported_as_missing_history():
    t = START + pd.Timedelta(days=3)
    sec = make_log("Security.evtx", range(5, 60), minutes(55, t), extra=[dict(
        record_id=4, time=t - pd.Timedelta(minutes=1), event_id=1102,
        provider="Microsoft-Windows-Eventlog", channel="Security",
        data={"SubjectUserName": "x", "SubjectDomainName": "y"})])
    findings = log_wiping.detect([clean_system(), sec])
    assert {f.technique for f in findings} == {"Clear Windows Event Logs"}


# ---------------------------------------------------------------- record-ID gaps

def test_missing_records_inside_log_are_medium():
    ids = list(range(1, 101)) + list(range(111, 201))
    log = make_log("Security.evtx", ids, minutes(len(ids)))
    f = next(x for x in log_wiping.detect([clean_system(), log]) if x.technique == "Selective event deletion")
    assert f.evidence["missing_records"] == 10 and f.confidence == Confidence.MEDIUM
    assert f.evidence["record_before_gap"] == 100 and f.evidence["record_after_gap"] == 111


def test_record_gap_plus_matching_silence_is_high():
    t1 = minutes(100)
    t2 = minutes(90, START + pd.Timedelta(hours=9))        # 7+ hours later, no restart in the System log
    ids = list(range(1, 101)) + list(range(111, 201))
    log = make_log("Security.evtx", ids, t1 + t2)
    findings = log_wiping.detect([clean_system(100), log])
    gap = next(x for x in findings if x.technique == "Selective event deletion")
    assert gap.confidence == Confidence.HIGH
    assert not any(x.technique == "Gap in event log" for x in findings)   # not reported twice


def test_unreadable_records_lower_the_record_gap():
    ids = list(range(1, 101)) + list(range(111, 201))
    log = make_log("Security.evtx", ids, minutes(len(ids)), parse_errors=10)
    f = next(x for x in log_wiping.detect([clean_system(), log]) if x.technique == "Selective event deletion")
    assert f.confidence == Confidence.LOW
    assert any("failed to parse" in n for n in f.benign_notes)


# ---------------------------------------------------------------- silence

def silent_log(extra_system=()):
    first = minutes(200)
    later = minutes(200, START + pd.Timedelta(hours=12))
    ids = range(1, 401)
    security = make_log("Security.evtx", ids, first + later)
    system = make_log("System.evtx", range(1, 301), minutes(300), extra=list(extra_system))
    return security, system


def test_unexplained_silence_is_low():
    security, system = silent_log()
    f = next(x for x in log_wiping.detect([system, security]) if x.technique == "Gap in event log")
    assert f.confidence == Confidence.LOW and "hours" in f.title


def test_silence_explained_by_a_restart_is_not_reported():
    reboot = boot(9999, START + pd.Timedelta(hours=12, minutes=1))
    security, system = silent_log([reboot])
    assert [x for x in log_wiping.detect([system, security]) if x.technique == "Gap in event log"] == []


def test_silence_explained_by_a_clock_correction_is_not_reported():
    """The setup-time clock fix: a forward jump looks like hours of silence."""
    clock = dict(record_id=9998, time=START + pd.Timedelta(hours=11, minutes=58), event_id=1,
                 provider="Microsoft-Windows-Kernel-General")
    security, system = silent_log([clock])
    assert [x for x in log_wiping.detect([system, security]) if x.technique == "Gap in event log"] == []


def test_missing_system_log_is_stated():
    security, _ = silent_log()
    f = next(x for x in log_wiping.detect([security]) if x.technique == "Gap in event log")
    assert any("No System log was supplied" in n for n in f.benign_notes)


# ---------------------------------------------------------------- header and history

def test_header_expects_more_records_than_present():
    log = make_log("Security.evtx", range(1, 101), minutes(100), next_record_number=160)
    f = next(x for x in log_wiping.detect([clean_system(), log]) if x.technique == "Missing newest records")
    assert f.evidence["newest_record_present"] == 100 and f.confidence == Confidence.MEDIUM


def test_stale_header_is_not_a_finding():
    """A header lagging behind (dirty file) means *fewer*, never more, records than present."""
    log = make_log("Security.evtx", range(1, 101), minutes(100), next_record_number=50, is_dirty=True)
    assert log_wiping.detect([clean_system(), log]) == []


def test_log_that_starts_late_and_not_at_record_one():
    late = START + pd.Timedelta(days=4)
    log = make_log("Security.evtx", range(801, 900), minutes(99, late))
    f = next(x for x in log_wiping.detect([clean_system(), log]) if x.technique == "Log history missing")
    assert f.confidence == Confidence.MEDIUM
    assert "never full" in " ".join(f.reasons) and "days after the System log" in " ".join(f.reasons)


def test_full_log_that_wrapped_around_is_normal():
    log = make_log("Security.evtx", range(801, 900), minutes(99, START), is_full=True)
    assert log_wiping.detect([clean_system(), log]) == []


def test_findings_serialise_and_get_ids():
    import json
    ids = list(range(1, 101)) + list(range(111, 201))
    findings = log_wiping.detect([clean_system(), make_log("Security.evtx", ids, minutes(len(ids)))])
    json.dumps([f.to_dict() for f in findings])
    assert findings[0].id == "LW-0001"
