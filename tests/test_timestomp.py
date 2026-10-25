"""Tests for the timestomping detector, run on synthetic MFTs through the real parser."""
from datetime import datetime, timezone

import pytest

from afd.core.finding import Confidence
from afd.detectors import timestomp
from afd.parsers.mft_parser import load_mft

from tests.mft_builder import ft, when, write_mft

OLD = datetime(2019, 3, 4, 10, 0, 0, tzinfo=timezone.utc)
DIR = 40          # an arbitrary folder entry
ROOT = 5


def folder(entry, name, parent=ROOT):
    t = ft(when(), 1234567)
    return dict(entry=entry, name=name, parent=parent, is_dir=True, si=(t, t, t, t), fn=(t, t, t, t))


def normal_file(entry, name, parent, hours=0, sub=7654321):
    """A genuine file: $SI and $FN agree, with 100-ns detail."""
    t = ft(when(hours=hours), sub)
    return dict(entry=entry, name=name, parent=parent, si=(t, t, t, t), fn=(t, t, t, t))


def stomped_file(entry, name, parent, arrive_h=2, stomp_h=3):
    """File that arrived at when(arrive_h) but whose $SI dates were set to 2019 whole seconds;
    the edit itself shows in $SI 'MFT changed' (stomp_h)."""
    old = ft(OLD)
    arrive = ft(when(hours=arrive_h), 3141592)
    return dict(entry=entry, name=name, parent=parent,
                si=(old, old, ft(when(hours=stomp_h), 5550001), old), fn=(arrive, arrive, arrive, arrive))


def run(tmp_path, entries, **kw):
    mft = write_mft(tmp_path / "$MFT", entries)
    return timestomp.detect(load_mft(mft), **kw)


def test_clean_files_raise_nothing(tmp_path):
    entries = [folder(DIR, "Docs")] + [normal_file(50 + i, f"f{i}.txt", DIR, hours=i) for i in range(5)]
    assert run(tmp_path, entries) == []


def test_copied_file_with_preserved_modified_date_is_not_flagged(tmp_path):
    """A normal copy keeps the old *modified* date but gets a new created date."""
    arrive = ft(when(hours=1), 4444444)
    old = ft(OLD, 1234567)
    entries = [folder(DIR, "Docs"),
               dict(entry=50, name="copied.docx", parent=DIR, si=(arrive, old, arrive, arrive),
                    fn=(arrive, arrive, arrive, arrive))]
    assert run(tmp_path, entries) == []


def test_stomped_file_in_temp_is_high_confidence(tmp_path):
    entries = [folder(DIR, "Windows"), folder(41, "Temp", parent=DIR),
               stomped_file(50, "evil.exe", parent=41)]
    findings = run(tmp_path, entries)
    assert len(findings) == 1
    f = findings[0]
    assert f.confidence == Confidence.HIGH
    assert f.mitre == "T1070.006"
    assert "\\Windows\\Temp\\evil.exe" in f.subject
    assert {"si_created_before_fn_created", "zero_subsecond_precision",
            "mft_changed_after_arrival", "suspicious_location"} <= set(f.evidence["indicators"])
    # the finding is placed on the timeline at the moment the dates were edited
    assert f.event_time == when(hours=3).replace(microsecond=555000)
    assert f.time_meaning.startswith("$SI 'MFT changed'")


def test_si_before_fn_alone_is_only_low(tmp_path):
    """Dates with 100-ns detail, no edit trace: could be a copy that kept all dates."""
    old = ft(OLD, 1234567)
    arrive = ft(when(hours=2), 3141592)
    entries = [folder(DIR, "Docs"),
               dict(entry=50, name="report.docx", parent=DIR, si=(old, old, arrive, old),
                    fn=(arrive, arrive, arrive, arrive))]
    findings = run(tmp_path, entries)
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.LOW
    assert findings[0].benign_notes             # the innocent explanation is stated


def test_installer_burst_is_downgraded_to_low(tmp_path):
    """Notepad++-style install: many files, whole-second 2023 dates, arriving together."""
    entries = [folder(DIR, "Program Files"), folder(41, "Notepad++", parent=DIR)]
    old = ft(datetime(2023, 5, 1, 9, 30, 0, tzinfo=timezone.utc))
    for i in range(12):
        arrive = ft(when(hours=2, seconds=i), 1000000 + i)
        entries.append(dict(entry=50 + i, name=f"plugin{i}.dll", parent=41,
                            si=(old, old, arrive, old), fn=(arrive, arrive, arrive, arrive)))
    findings = run(tmp_path, entries)
    assert len(findings) == 12
    assert all(f.confidence == Confidence.LOW for f in findings)
    notes = " ".join(findings[0].benign_notes)
    assert "installer or archive extraction" in notes
    assert "Program Files" in notes


def test_same_pattern_outside_a_burst_is_not_downgraded(tmp_path):
    """One stomped file in Program Files, with an edit trace, still deserves attention."""
    entries = [folder(DIR, "Program Files"), folder(41, "Tool", parent=DIR),
               stomped_file(50, "svc.exe", parent=41)]
    findings = run(tmp_path, entries)
    assert findings[0].confidence >= Confidence.MEDIUM


def test_future_date_is_flagged(tmp_path):
    future = ft(datetime(2031, 1, 1, tzinfo=timezone.utc), 111)
    t = ft(when(hours=1), 222)
    entries = [folder(DIR, "Docs"),
               dict(entry=50, name="odd.txt", parent=DIR, si=(future, future, t, t), fn=(t, t, t, t)),
               normal_file(51, "ok.txt", DIR)]
    findings = run(tmp_path, entries)
    assert [f.subject for f in findings] == ["\\Docs\\odd.txt"]
    assert "si_date_in_future" in findings[0].evidence["indicators"]
    assert findings[0].confidence >= Confidence.MEDIUM


def test_reference_time_overrides_newest_fn_date(tmp_path):
    """A Nov 1 date is fine if the volume was active until mid-Nov, but impossible if the
    image was acquired on Oct 25."""
    t = ft(when(hours=1), 222)
    nov1 = ft(datetime(2026, 11, 1, tzinfo=timezone.utc), 5)
    entries = [folder(DIR, "Docs"),
               dict(entry=50, name="a.txt", parent=DIR, si=(nov1, nov1, t, t), fn=(t, t, t, t)),
               normal_file(51, "b.txt", DIR, hours=24 * 20)]
    assert run(tmp_path, entries) == []
    flagged = run(tmp_path, entries, reference_time=datetime(2026, 10, 25, tzinfo=timezone.utc))
    # with Oct 25 as "now", both the Nov 1 and the mid-Nov file are impossible
    assert {f.subject for f in flagged} == {"\\Docs\\a.txt", "\\Docs\\b.txt"}


def test_zeroed_dates_are_flagged(tmp_path):
    t = ft(when(hours=1), 222)
    entries = [folder(DIR, "Docs"),
               dict(entry=50, name="blank.txt", parent=DIR, si=(0, 0, t, t), fn=(t, t, t, t))]
    findings = run(tmp_path, entries)
    assert len(findings) == 1 and "si_dates_zeroed" in findings[0].evidence["indicators"]


def test_donor_dates_copied_from_system_file(tmp_path):
    donor_c, donor_m = ft(datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc), 4242), \
                       ft(datetime(2024, 1, 2, 3, 4, 6, tzinfo=timezone.utc), 4343)
    arrive = ft(when(hours=2), 3141592)
    entries = [folder(DIR, "Windows"), folder(41, "System32", parent=DIR), folder(42, "Users"),
               dict(entry=50, name="kernel32.dll", parent=41,
                    si=(donor_c, donor_m, donor_c, donor_c), fn=(donor_c, donor_m, donor_c, donor_c)),
               dict(entry=51, name="payload.exe", parent=42,
                    si=(donor_c, donor_m, arrive, donor_c), fn=(arrive, arrive, arrive, arrive))]
    findings = run(tmp_path, entries)
    assert len(findings) == 1
    assert "dates_match_system_file" in findings[0].evidence["indicators"]
    assert "kernel32.dll" in " ".join(findings[0].reasons)


def test_deleted_file_is_still_analysed_and_marked(tmp_path):
    f = stomped_file(50, "gone.exe", parent=DIR)
    f["in_use"] = False
    findings = run(tmp_path, [folder(DIR, "Docs"), f])
    assert len(findings) == 1 and findings[0].evidence["deleted"] is True


def test_findings_serialise_to_json(tmp_path):
    import json
    findings = run(tmp_path, [folder(DIR, "Docs"), stomped_file(50, "x.exe", DIR)])
    out = json.dumps([f.to_dict() for f in findings])
    assert '"confidence"' in out and findings[0].id == "TS-0001"


def setup_burst(n_folders=20, per_folder=3):
    """Windows-setup-style arrival: files spread over many small folders within minutes,
    carrying old image dates (with sub-seconds) and no later edit."""
    entries = [folder(DIR, "Windows")]
    old = ft(datetime(2025, 3, 1, 8, 0, 0, tzinfo=timezone.utc), 1234567)
    n = 60
    for d in range(n_folders):
        entries.append(folder(100 + d, f"comp{d}", parent=DIR))
        for k in range(per_folder):
            arrive = ft(when(hours=2, seconds=d * 5 + k), 2000000 + k)
            entries.append(dict(entry=n, name=f"f{k}.dll", parent=100 + d,
                                si=(old, old, arrive, old), fn=(arrive, arrive, arrive, arrive)))
            n += 1
    return entries


def test_folders_are_skipped_by_default(tmp_path):
    old = ft(OLD, 1234567)
    arrive = ft(when(hours=2), 3141592)
    later = ft(when(hours=5), 2718281)
    stomped_dir = dict(entry=50, name="Themes", parent=DIR, is_dir=True,
                       si=(old, old, later, old), fn=(arrive, arrive, arrive, arrive))
    entries = [folder(DIR, "Windows"), stomped_dir]
    assert run(tmp_path, entries) == []
    flagged = run(tmp_path, entries, cfg={"include_directories": True})
    assert len(flagged) == 1 and flagged[0].evidence["is_directory"] is True


def test_setup_burst_across_many_folders_is_low(tmp_path):
    """Per-folder bulk (8 files) never fires here; the volume-wide burst must."""
    findings = run(tmp_path, setup_burst())
    assert len(findings) == 60
    assert all(f.confidence == Confidence.LOW for f in findings)
    assert all("volume_burst" in f.evidence["indicators"] for f in findings)
    assert "Windows setup" in " ".join(findings[0].benign_notes)


def test_burst_with_edit_trace_is_not_downgraded(tmp_path):
    """A dropped toolkit stomped afterwards arrives in a burst too, but its $SI
    'MFT changed' shows the later edit, so the burst rule must not hide it."""
    entries = setup_burst()
    for e in entries:
        if not e.get("is_dir"):
            c, m, _, a = e["si"]
            e["si"] = (c, m, ft(when(hours=4), 9999999), a)
    findings = run(tmp_path, entries)
    assert findings and not any("volume_burst" in f.evidence["indicators"] for f in findings)
    assert all(f.confidence >= Confidence.MEDIUM for f in findings)


def test_deleted_update_burst_is_low_despite_change_time(tmp_path):
    """Windows Update cleanup: deleted hard-linked files whose 'MFT changed' moved when
    the link was removed. On deleted records that trace must not block the burst rule."""
    entries = setup_burst()
    for e in entries:
        if not e.get("is_dir"):
            c, m, _, a = e["si"]
            e["si"] = (c, m, ft(when(hours=4), 9999999), a)
            e["in_use"] = False
    findings = run(tmp_path, entries)
    assert len(findings) == 60
    assert all(f.confidence == Confidence.LOW for f in findings)
