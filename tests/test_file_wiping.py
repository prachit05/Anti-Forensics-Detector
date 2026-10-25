"""Tests for the secure file wiping detector."""
from datetime import datetime, timezone
import pytest

from afd.core.finding import Confidence
from afd.detectors import file_wiping
from afd.parsers.mft_parser import load_mft
from tests.mft_builder import ft, when, write_mft

ROOT = 5
DIR = 40


def normal_active(entry, name, parent=DIR, data=b"Important company document content"):
    t = ft(when())
    return dict(entry=entry, name=name, parent=parent, in_use=True, is_dir=False,
                si=(t, t, t, t), fn=(t, t, t, t), data=data)


def normal_deleted(entry, name, parent=DIR, data=b"Just some deleted memo content"):
    t = ft(when())
    return dict(entry=entry, name=name, parent=parent, in_use=False, is_dir=False,
                si=(t, t, t, t), fn=(t, t, t, t), data=data)


def sdelete_deleted(entry, name="ZZZZZZZZ.ZZZ", parent=DIR, data=b""):
    t = ft(when())
    return dict(entry=entry, name=name, parent=parent, in_use=False, is_dir=False,
                si=(t, t, t, t), fn=(t, t, t, t), data=data)


def zero_filled_deleted(entry, name="secret.txt", parent=DIR):
    t = ft(when())
    return dict(entry=entry, name=name, parent=parent, in_use=False, is_dir=False,
                si=(t, t, t, t), fn=(t, t, t, t), data=b"\x00" * 64)


def pattern_filled_deleted(entry, name="passwords.kdbx", parent=DIR, byte_val=0xFF):
    t = ft(when())
    return dict(entry=entry, name=name, parent=parent, in_use=False, is_dir=False,
                si=(t, t, t, t), fn=(t, t, t, t), data=bytes([byte_val]) * 64)


def run(tmp_path, entries):
    mft_file = write_mft(tmp_path / "$MFT", entries)
    return file_wiping.detect(load_mft(mft_file))


def test_active_files_are_ignored(tmp_path):
    entries = [normal_active(50, "report.docx"), normal_active(51, "image.png")]
    findings = run(tmp_path, entries)
    assert len(findings) == 0


def test_normal_deleted_file_with_text_not_flagged(tmp_path):
    entries = [normal_deleted(50, "old_notes.txt")]
    findings = run(tmp_path, entries)
    assert len(findings) == 0


def test_sdelete_mangled_name_detected(tmp_path):
    entries = [sdelete_deleted(50, "ZZZZZZZZ.ZZZ")]
    findings = run(tmp_path, entries)
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.HIGH
    assert "SDelete" in findings[0].title
    assert "sdelete_pattern" in findings[0].evidence


def test_sdelete_single_letter_mangled_variant(tmp_path):
    entries = [sdelete_deleted(50, "AAAAAAAA.AAA")]
    findings = run(tmp_path, entries)
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.HIGH


def test_resident_zero_fill_detected(tmp_path):
    entries = [zero_filled_deleted(50, "wiped_file.txt")]
    findings = run(tmp_path, entries)
    assert len(findings) == 1
    assert findings[0].confidence in (Confidence.MEDIUM, Confidence.HIGH)
    assert "0x00_zero_fill" in findings[0].evidence.get("resident_pattern", "")


def test_resident_ff_fill_detected(tmp_path):
    entries = [pattern_filled_deleted(50, "wiped_secrets.doc", byte_val=0xFF)]
    findings = run(tmp_path, entries)
    assert len(findings) == 1
    assert "repeating_byte" in findings[0].evidence.get("resident_pattern", "")


def test_benign_temp_guid_downgraded(tmp_path):
    guid_name = "12345678-1234-1234-1234-123456789abc.tmp"
    t = ft(when())
    entries = [dict(entry=50, name=guid_name, parent=DIR, in_use=False, is_dir=False,
                    si=(t, t, t, t), fn=(t, t, t, t), data=b"temp installer data")]
    findings = run(tmp_path, entries)
    # Should not produce a false positive finding
    assert len(findings) == 0
