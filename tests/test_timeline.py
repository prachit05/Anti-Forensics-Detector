"""Tests for unified timeline builder and episode clusterer."""
from datetime import datetime, timezone
import pytest

from afd.analysis import build_timeline
from afd.core.finding import Confidence, Finding


def make_finding(fid, module, technique, title, dt, time_meaning="timestamp"):
    return Finding(
        id=fid,
        module=module,
        technique=technique,
        mitre="T1070",
        title=title,
        confidence=Confidence.HIGH,
        score=6,
        subject="test_subject",
        artifact="test_artifact",
        reasons=["test reason"],
        event_time=dt,
        time_meaning=time_meaning,
    )


def test_timeline_chronological_ordering():
    t1 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 24, 10, 15, 0, tzinfo=timezone.utc)
    t3 = datetime(2026, 10, 24, 10, 30, 0, tzinfo=timezone.utc)

    # Supply out of order
    findings = [
        make_finding("F3", "log_wiping", "Log Clear", "Log cleared", t3),
        make_finding("F1", "tool_traces", "Tool Execution", "SDelete run", t1),
        make_finding("F2", "file_wiping", "File Wiping", "File wiped", t2),
    ]

    tl = build_timeline(findings)
    assert len(tl.entries) == 3
    assert [e.finding_id for e in tl.entries] == ["F1", "F2", "F3"]
    assert tl.entries[0].time == t1
    assert tl.entries[2].time == t3


def test_undated_findings_segregation():
    t1 = datetime(2026, 10, 24, 11, 0, 0, tzinfo=timezone.utc)
    findings = [
        make_finding("F1", "tool_traces", "Tool Run", "CCleaner", t1),
        make_finding("F2", "freespace", "Free Space Wipe", "0xFF Wipe", None),
    ]

    tl = build_timeline(findings)
    assert len(tl.entries) == 1
    assert len(tl.undated_findings) == 1
    assert tl.undated_findings[0].id == "F2"


def test_episode_clustering_single_episode():
    # 3 events within 10 minutes of each other
    t0 = datetime(2026, 10, 24, 14, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 24, 14, 5, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 24, 14, 9, 0, tzinfo=timezone.utc)

    findings = [
        make_finding("F1", "tool_traces", "Tool Exec", "SDelete", t0),
        make_finding("F2", "file_wiping", "Wiped", "Wiped file", t1),
        make_finding("F3", "log_wiping", "Log Clear", "Cleared log", t2),
    ]

    tl = build_timeline(findings, episode_gap_minutes=30.0)
    assert len(tl.episodes) == 1
    ep = tl.episodes[0]
    assert ep.episode_id == 1
    assert ep.event_count == 3
    assert ep.start_time == t0
    assert ep.end_time == t2
    assert "SDelete" in ep.narrative or "launched" in ep.narrative


def test_episode_clustering_multiple_episodes():
    # 2 events at 10:00, 10:05; and another event at 13:00 (3 hours later)
    t0 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 24, 10, 5, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 24, 13, 0, 0, tzinfo=timezone.utc)

    findings = [
        make_finding("F1", "tool_traces", "Tool Exec", "Timestomp", t0),
        make_finding("F2", "timestomp", "Stomped", "Stomped file", t1),
        make_finding("F3", "log_wiping", "Log Clear", "Cleared log", t2),
    ]

    tl = build_timeline(findings, episode_gap_minutes=30.0)
    assert len(tl.episodes) == 2
    assert tl.episodes[0].event_count == 2
    assert tl.episodes[1].event_count == 1


def test_timeline_to_dataframe():
    t0 = datetime(2026, 10, 24, 12, 0, 0, tzinfo=timezone.utc)
    findings = [make_finding("F1", "tool_traces", "Tool", "CCleaner", t0)]
    tl = build_timeline(findings)
    df = tl.to_dataframe()
    assert len(df) == 1
    assert "phase" in df.columns
    assert "finding_id" in df.columns
    assert df["finding_id"].iloc[0] == "F1"


def test_timeline_narrative_summary():
    t0 = datetime(2026, 10, 24, 12, 0, 0, tzinfo=timezone.utc)
    findings = [make_finding("F1", "tool_traces", "Tool", "SDelete", t0)]
    tl = build_timeline(findings)
    summary = tl.narrative_summary()
    assert len(summary) >= 2
    assert any("Episode 1" in s for s in summary)
