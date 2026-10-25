"""Tests for hidden and disguised files detector."""
from datetime import datetime, timezone
import pytest

from afd.core.finding import Confidence
from afd.detectors import hidden_files
from afd.parsers.mft_parser import load_mft
from tests.mft_builder import ft, when, write_mft

ROOT = 5
DIR = 40


def file_with_ads(entry, name, ads_list, data=b"hello host file", parent=DIR):
    t = ft(when())
    return dict(entry=entry, name=name, parent=parent, in_use=True, is_dir=False,
                si=(t, t, t, t), fn=(t, t, t, t), data=data, ads=ads_list)


def file_with_data(entry, name, data, parent=DIR):
    t = ft(when())
    return dict(entry=entry, name=name, parent=parent, in_use=True, is_dir=False,
                si=(t, t, t, t), fn=(t, t, t, t), data=data)


def run(tmp_path, entries):
    mft_file = write_mft(tmp_path / "$MFT", entries)
    return hidden_files.detect(load_mft(mft_file))


def test_clean_file_no_findings(tmp_path):
    entries = [file_with_data(50, "normal.txt", b"Just normal text contents")]
    assert len(run(tmp_path, entries)) == 0


def test_benign_zone_identifier_ads_not_flagged(tmp_path):
    motw = b"[ZoneTransfer]\r\nZoneId=3\r\n"
    entries = [file_with_ads(50, "download.zip", [("Zone.Identifier", motw)])]
    findings = run(tmp_path, entries)
    assert len(findings) == 0


def test_script_ads_detected(tmp_path):
    ps1_code = b"Write-Host 'malicious script in ADS'"
    entries = [file_with_ads(50, "notes.txt", [("evil.ps1", ps1_code)])]
    findings = run(tmp_path, entries)
    assert len(findings) == 1
    assert "evil.ps1" in findings[0].title
    assert findings[0].confidence in (Confidence.MEDIUM, Confidence.HIGH)


def test_pe_executable_header_mismatch_detected(tmp_path):
    # PE binary starting with MZ header disguised as JPG
    pe_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff" + b"\x00" * 50
    entries = [file_with_data(50, "family_vacation.jpg", pe_header)]
    findings = run(tmp_path, entries)
    assert len(findings) == 1
    assert findings[0].confidence == Confidence.HIGH
    assert "Disguised file header mismatch" in findings[0].title
    assert "family_vacation.jpg" in findings[0].subject


def test_legitimate_pe_extension_not_flagged(tmp_path):
    pe_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff" + b"\x00" * 50
    entries = [file_with_data(50, "legitimate_tool.exe", pe_header)]
    findings = run(tmp_path, entries)
    assert len(findings) == 0


def test_zip_header_disguised_as_txt_detected(tmp_path):
    zip_header = b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"\x00" * 50
    entries = [file_with_data(50, "passwords.txt", zip_header)]
    findings = run(tmp_path, entries)
    assert len(findings) == 1
    assert "ZIP" in findings[0].reasons[0]
