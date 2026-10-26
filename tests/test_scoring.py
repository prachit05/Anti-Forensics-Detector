"""Tests for multi-artifact correlation and confidence scoring."""
from datetime import datetime, timezone
import pytest

from afd.analysis.scoring import correlate_findings
from afd.core.finding import Confidence, Finding


def make_finding(fid, module, technique, title, subject, dt, conf=Confidence.MEDIUM, score=4):
    return Finding(
        id=fid,
        module=module,
        technique=technique,
        mitre="T1070",
        title=title,
        confidence=conf,
        score=score,
        subject=subject,
        artifact="test_artifact",
        reasons=["initial reason"],
        event_time=dt,
        time_meaning="test timestamp",
    )


def test_sdelete_tool_correlates_with_file_wiping():
    t0 = datetime(2026, 10, 24, 14, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 24, 14, 5, 0, tzinfo=timezone.utc)

    findings = [
        make_finding("TT-0001", "tool_traces", "Tool Execution", "SDelete ran", "sdelete.exe", t0, Confidence.HIGH, 6),
        make_finding("FW-0001", "file_wiping", "File Wiping", "Wiped file", "secret.docx", t1, Confidence.MEDIUM, 4),
    ]

    updated, campaigns = correlate_findings(findings)
    fw = next(f for f in updated if f.id == "FW-0001")
    assert fw.score > 4
    assert fw.confidence == Confidence.HIGH
    assert any("Corroborated" in r for r in fw.reasons)


def test_timestomp_tool_correlates_with_timestomped_file():
    t0 = datetime(2026, 10, 24, 11, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 24, 11, 3, 0, tzinfo=timezone.utc)

    findings = [
        make_finding("TT-0001", "tool_traces", "Tool Execution", "NewFileTime", "newfiletime.exe", t0, Confidence.HIGH, 6),
        make_finding("TS-0001", "timestomp", "Timestomping", "Timestomped file", "evil.dll", t1, Confidence.LOW, 3),
    ]

    updated, campaigns = correlate_findings(findings)
    ts = next(f for f in updated if f.id == "TS-0001")
    assert ts.score > 3
    assert ts.confidence in (Confidence.MEDIUM, Confidence.HIGH)
    assert any("Corroborated" in r for r in ts.reasons)


def test_distant_events_do_not_correlate():
    # SDelete ran 5 hours earlier
    t0 = datetime(2026, 10, 24, 9, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 24, 14, 0, 0, tzinfo=timezone.utc)

    findings = [
        make_finding("TT-0001", "tool_traces", "Tool Execution", "SDelete", "sdelete.exe", t0, Confidence.HIGH, 6),
        make_finding("FW-0001", "file_wiping", "File Wiping", "Wiped file", "secret.docx", t1, Confidence.MEDIUM, 4),
    ]

    updated, campaigns = correlate_findings(findings)
    fw = next(f for f in updated if f.id == "FW-0001")
    assert fw.score == 4
    assert fw.confidence == Confidence.MEDIUM


def test_coordinated_campaign_detection():
    # 3 distinct techniques in 30 minutes: Tool run + File wipe + Log clear
    t0 = datetime(2026, 10, 24, 14, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 24, 14, 10, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 24, 14, 25, 0, tzinfo=timezone.utc)

    findings = [
        make_finding("TT-0001", "tool_traces", "Tool Exec", "SDelete", "sdelete.exe", t0),
        make_finding("FW-0001", "file_wiping", "File Wipe", "Wiped doc", "doc.txt", t1),
        make_finding("LW-0001", "log_wiping", "Log Clear", "Cleared Security", "Security.evtx", t2),
    ]

    updated, campaigns = correlate_findings(findings)
    assert len(campaigns) == 1
    camp = campaigns[0]
    assert camp.confidence == Confidence.HIGH
    assert "Coordinated Anti-Forensics Campaign" in camp.title
    assert "event_count" in camp.evidence
    assert camp.evidence["event_count"] == 3


def test_tool_presence_adds_context_but_no_boost():
    """A binary on disk is not proof it ran: no confidence change, only a context note."""
    t0 = datetime(2026, 10, 24, 14, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 24, 14, 5, 0, tzinfo=timezone.utc)
    findings = [
        make_finding("TT-0001", "tool_traces", "Tool Binary Present: Secure Deletion", "sdelete on disk",
                     r"\Users\x\sdelete.exe", t0, Confidence.LOW, 2),
        make_finding("FW-0001", "file_wiping", "File Wiping", "Wiped file", "secret.docx", t1, Confidence.MEDIUM, 4),
    ]
    updated, _ = correlate_findings(findings)
    fw = next(f for f in updated if f.id == "FW-0001")
    assert fw.score == 4 and fw.confidence == Confidence.MEDIUM
    assert any(r.startswith("Context:") for r in fw.reasons)


def test_low_findings_do_not_form_a_campaign():
    """Installers, updates and built-in tools give LOW findings close together on clean systems."""
    t0 = datetime(2026, 10, 24, 14, 0, 0, tzinfo=timezone.utc)
    findings = [
        make_finding("TT-0001", "tool_traces", "Tool Binary Present", "cipher", "cipher.exe", t0, Confidence.LOW, 2),
        make_finding("TS-0001", "timestomp", "Timestomping", "update file", "a.dll", t0, Confidence.LOW, 3),
        make_finding("HF-0001", "hidden_files", "ADS", "odd stream", "b.txt", t0, Confidence.LOW, 2),
    ]
    _, campaigns = correlate_findings(findings)
    assert campaigns == []
