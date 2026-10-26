"""Regression tests for false positives seen on the clean Windows 11 test image.

Each test reproduces one pattern that a clean system produced, and checks that it no
longer reaches MEDIUM/HIGH, plus a control showing real tampering is still caught.
"""
from datetime import datetime, timedelta, timezone

import pandas as pd

from afd.analysis.ml_anomaly import detect_mft_anomalies
from afd.analysis.scoring import correlate_findings
from afd.analysis.timeline import build_timeline
from afd.core.finding import Confidence, Finding
from afd.detectors import freespace, hidden_files, tool_traces
from afd.parsers.mft_parser import load_mft
from tests.mft_builder import ft, when, write_mft

T0 = datetime(2026, 10, 25, 16, 0, tzinfo=timezone.utc)


def finding(module, minutes=0, conf=Confidence.MEDIUM, subject="x", technique="t",
            title="t", indicators=()):
    return Finding(module=module, technique=technique, mitre="T1070", title=title,
                   confidence=conf, score=int(conf) * 2, subject=subject, artifact="a",
                   evidence={"indicators": list(indicators)},
                   event_time=T0 + timedelta(minutes=minutes))


def prefetch(exe, minutes=0):
    return pd.DataFrame([{"pf_file": f"{exe}-1E154F39.pf", "exe_name": exe, "run_count": 4,
                          "run_index": 0, "run_time": T0 + timedelta(minutes=minutes)}])


# ---------------------------------------------------------------- correlation / campaigns

def test_setup_and_update_burst_is_not_a_campaign():
    """Clean image: 100,000+ LOW findings from 4 modules in one hour became a HIGH campaign."""
    lows = [finding(m, i, Confidence.LOW) for i in range(60)
            for m in ("timestomp", "file_wiping", "tool_traces")]
    ml = [finding("ml_anomaly", i, Confidence.MEDIUM) for i in range(10)]
    _, campaigns = correlate_findings(lows + ml)
    assert campaigns == []


def test_ml_cannot_complete_a_campaign():
    two_rules = [finding("timestomp", 1), finding("file_wiping", 5)]
    _, campaigns = correlate_findings(two_rules + [finding("ml_anomaly", 8)])
    assert campaigns == []


def test_real_multi_technique_cover_up_is_still_a_campaign():
    real = [finding("tool_traces", 0, Confidence.HIGH), finding("timestomp", 5),
            finding("log_wiping", 20, Confidence.HIGH)]
    _, campaigns = correlate_findings(real)
    assert len(campaigns) == 1 and campaigns[0].confidence == Confidence.HIGH


def test_tool_does_not_boost_installer_burst_files():
    tool = finding("tool_traces", 0, Confidence.HIGH, subject="newfiletime.exe")
    burst = finding("timestomp", 3, Confidence.LOW, indicators=["volume_burst"])
    updated, _ = correlate_findings([tool, burst])
    ts = next(f for f in updated if f.module == "timestomp")
    assert ts.confidence == Confidence.LOW


def test_builtin_wevtutil_plus_log_clear_raises_the_tool():
    tool = tool_traces.detect(prefetch_df=prefetch("WEVTUTIL.EXE"))[0]
    clear = finding("log_wiping", 2, Confidence.HIGH)
    updated, _ = correlate_findings([tool, clear])
    t = next(f for f in updated if f.module == "tool_traces")
    assert t.confidence == Confidence.MEDIUM
    assert any("Corroborated" in r for r in t.reasons)


def test_zero_fill_is_raised_by_a_wiper_run():
    zero = Finding(module="freespace", technique="w", mitre="T1070.004", title="zero fill",
                   confidence=Confidence.LOW, score=2, subject="img", artifact="a")
    sdel = tool_traces.detect(prefetch_df=prefetch("SDELETE64.EXE"))[0]
    updated, _ = correlate_findings([zero, sdel])
    fs = next(f for f in updated if f.module == "freespace")
    assert fs.confidence == Confidence.MEDIUM and "SDELETE64.EXE" in fs.reasons[-1]


# ---------------------------------------------------------------- file wiping

def test_hash_named_catalog_file_is_not_a_wiper_name(tmp_path):
    """Clean image: 333 deleted <sha256>.cat files (zeroed) were MEDIUM via 'random name'."""
    from afd.detectors import file_wiping
    t = ft(when())
    sha = "44cef013a3354f7e36f009b5f18a6511b2514f036c2ad6985f53978a8e322f51"
    entries = [dict(entry=40, name="CatRoot", parent=5, is_dir=True, si=(t,) * 4, fn=(t,) * 4),
               dict(entry=50, name=f"{sha}.cat", parent=40, in_use=False, si=(t,) * 4,
                    fn=(t,) * 4, data=bytes(64)),
               dict(entry=51, name="xQ7zK9vW2mJ4.docx", parent=40, in_use=False, si=(t,) * 4,
                    fn=(t,) * 4, data=bytes(64))]
    found = {f.evidence["name"]: f for f in file_wiping.detect(load_mft(write_mft(tmp_path / "$MFT", entries)))}
    assert found[f"{sha}.cat"].confidence == Confidence.LOW
    assert "random_name_entropy" not in found[f"{sha}.cat"].evidence
    assert found["xQ7zK9vW2mJ4.docx"].confidence == Confidence.MEDIUM   # wiper-style name + zeros


def test_structured_servicing_name_is_not_a_wiper_name(tmp_path):
    """Clean image: 28 'Wrapper-<sha256>~31bf3856ad364e35~amd64~~10.0.26100.9444.cat' files."""
    from afd.detectors import file_wiping
    t = ft(when())
    name = ("Wrapper-438C86C7F9529FACED8400E9BCA77D3CE733D63DCCC4F659A90DE1B1912965DD"
            "~31bf3856ad364e35~amd64~~10.0.26100.9441.cat")
    entries = [dict(entry=40, name="Servicing", parent=5, is_dir=True, si=(t,) * 4, fn=(t,) * 4),
               dict(entry=50, name=name, parent=40, in_use=False, si=(t,) * 4, fn=(t,) * 4, data=b"")]
    findings = file_wiping.detect(load_mft(write_mft(tmp_path / "$MFT", entries)))
    assert all(f.confidence == Confidence.LOW for f in findings)


# ---------------------------------------------------------------- tool traces

def test_wevtutil_run_by_windows_is_low():
    """Clean image: Windows ran wevtutil 4 times during setup, reported as HIGH."""
    f = tool_traces.detect(prefetch_df=prefetch("WEVTUTIL.EXE"))[0]
    assert f.confidence == Confidence.LOW and f.evidence["builtin_windows_tool"]


def test_windows_copies_of_builtin_tools_are_ignored():
    rows = [
        (1001, "cipher.exe", r"\Windows\WinSxS\amd64_microsoft-windows-cipher_x\cipher.exe"),
        (1002, "wevtutil.exe", r"\Windows\SoftwareDistribution\Download\pkg\wevtutil.exe"),
        (1004, "cipher.exe", r"\Users\Public\cipher.exe"),        # out of place: reported
    ]
    mft = pd.DataFrame([dict(entry=e, name=n, path=p, si_modified=133e15, si_created=133e15,
                             in_use=True, is_dir=False) for e, n, p in rows])
    findings = tool_traces.detect(mft=mft)
    assert [f.subject for f in findings] == [r"\Users\Public\cipher.exe"]
    assert findings[0].confidence == Confidence.LOW


# ---------------------------------------------------------------- hidden files

def test_ntfs_metadata_streams_are_not_hidden_data(tmp_path):
    """Clean image: $UsnJrnl:$J, $Repair:$Corrupt and $Tops:$T were reported as MEDIUM."""
    t = ft(when())
    ext = dict(entry=11, name="$Extend", parent=5, is_dir=True, si=(t,) * 4, fn=(t,) * 4)
    docs = dict(entry=40, name="Docs", parent=5, is_dir=True, si=(t,) * 4, fn=(t,) * 4)
    usn = dict(entry=60, name="$UsnJrnl", parent=11, si=(t,) * 4, fn=(t,) * 4,
               data=b"hi", ads=[("$J", b"x" * 100)])
    same_in_docs = dict(entry=61, name="notes.txt", parent=40, si=(t,) * 4, fn=(t,) * 4,
                        data=b"hi", ads=[("$J", b"x" * 100)])
    findings = hidden_files.detect(load_mft(write_mft(tmp_path / "$MFT", [ext, docs, usn, same_in_docs])))
    assert [f.subject for f in findings] == ["\\Docs\\notes.txt:$J"]


# ---------------------------------------------------------------- free space

def test_only_fully_unallocated_chunks_are_sampled():
    # 8 clusters of 1 KB, 2 clusters per 2 KB chunk; clusters 0 and 5 are in use
    bitmap = bytes([0b00100001])
    offsets, total_free = freespace.free_chunk_offsets(bitmap, 1024, 2048, 10)
    assert offsets == [1 * 2048, 3 * 2048] and total_free == 2


def test_zero_filled_free_space_alone_is_low():
    """Clean image: half of the sampled free space was zeros (never-written VM disk)."""
    data = b"\x00" * (1048576 * 6) + bytes(range(256)) * 4096 * 4
    findings = freespace.detect_from_buffer(data, cfg={"max_chunks_to_sample": 10})
    zero = [f for f in findings if "Zero-fill" in f.title]
    assert zero and zero[0].confidence == Confidence.LOW


# ---------------------------------------------------------------- ML and timeline

def test_ml_findings_are_supporting_evidence_only(tmp_path):
    old, new = ft(datetime(2020, 1, 1, tzinfo=timezone.utc)), ft(when(), 1234567)
    entries = [dict(entry=40, name="Docs", parent=5, is_dir=True, si=(new,) * 4, fn=(new,) * 4)]
    entries += [dict(entry=50 + i, name=f"f{i}.txt", parent=40, si=(new,) * 4, fn=(new,) * 4)
                for i in range(200)]
    entries += [dict(entry=300, name="odd.exe", parent=40, si=(old, old, new, old), fn=(new,) * 4)]
    findings = detect_mft_anomalies(load_mft(write_mft(tmp_path / "$MFT", entries)),
                                    cfg={"mft_contamination": 0.01})
    assert findings and all(f.confidence == Confidence.LOW for f in findings)


def test_timeline_can_leave_out_low_findings():
    tl = build_timeline([finding("timestomp", 0, Confidence.LOW),
                         finding("log_wiping", 5, Confidence.HIGH)],
                        min_confidence=Confidence.MEDIUM)
    assert [e.module for e in tl.entries] == ["log_wiping"]
