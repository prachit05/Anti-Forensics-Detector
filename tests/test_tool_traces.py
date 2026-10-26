"""Tests for anti-forensic tool traces detector."""
from datetime import datetime, timezone
import pandas as pd
import pytest

from afd.core.finding import Confidence
from afd.detectors import tool_traces
from afd.parsers.registry_parser import InstalledProgram, RunMRUEntry, UserAssistEntry


def test_empty_inputs_produce_no_findings():
    findings = tool_traces.detect()
    assert findings == []


def test_clean_prefetch_produces_no_findings():
    clean_df = pd.DataFrame([
        {
            "pf_file": "NOTEPAD.EXE-1A2B3C4D.pf",
            "exe_name": "NOTEPAD.EXE",
            "run_count": 10,
            "run_index": 0,
            "run_time": datetime(2026, 10, 24, 12, 0, 0, tzinfo=timezone.utc),
        },
        {
            "pf_file": "CHROME.EXE-5E6F7A8B.pf",
            "exe_name": "CHROME.EXE",
            "run_count": 42,
            "run_index": 0,
            "run_time": datetime(2026, 10, 24, 12, 30, 0, tzinfo=timezone.utc),
        },
    ])
    findings = tool_traces.detect(prefetch_df=clean_df)
    assert len(findings) == 0


def test_sdelete_and_ccleaner_detected_in_prefetch():
    suspicious_df = pd.DataFrame([
        {
            "pf_file": "SDELETE64.EXE-99887766.pf",
            "exe_name": "SDELETE64.EXE",
            "run_count": 2,
            "run_index": 0,
            "run_time": datetime(2026, 10, 24, 14, 15, 0, tzinfo=timezone.utc),
        },
        {
            "pf_file": "CCLEANER64.EXE-11223344.pf",
            "exe_name": "CCLEANER64.EXE",
            "run_count": 5,
            "run_index": 0,
            "run_time": datetime(2026, 10, 24, 14, 20, 0, tzinfo=timezone.utc),
        },
    ])
    findings = tool_traces.detect(prefetch_df=suspicious_df)
    assert len(findings) == 2
    assert all(f.confidence == Confidence.HIGH for f in findings)
    assert any("SDELETE64.EXE" in f.title for f in findings)
    assert any("CCLEANER64.EXE" in f.title for f in findings)


def test_userassist_tool_trace_detected():
    reg_data = {
        "userassist": [
            UserAssistEntry(
                path=r"C:\Users\Admin\Downloads\NewFileTime.exe",
                raw_name="P:\\Hfrey\\Nqzva\\Qbjaybnqf\\ArjSvyrGvzr.rkr",
                run_count=3,
                last_run=datetime(2026, 10, 24, 15, 0, 0, tzinfo=timezone.utc),
                last_run_raw=133000000000000000,
                user="Admin",
                guid="{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}",
            )
        ],
        "installed_programs": [],
        "run_mru": [],
    }
    findings = tool_traces.detect(registry_data=reg_data)
    assert len(findings) == 1
    assert "NewFileTime.exe" in findings[0].title
    assert findings[0].confidence == Confidence.HIGH


def test_installed_eraser_detected_in_registry():
    reg_data = {
        "userassist": [],
        "installed_programs": [
            InstalledProgram(
                key_name="Eraser_is1",
                display_name="Eraser 6.2.0",
                display_version="6.2.0.2993",
                publisher="The Eraser Project",
                install_date="20261020",
                install_location=r"C:\Program Files\Eraser",
                uninstall_string=r"C:\Program Files\Eraser\unins000.exe",
                last_written=datetime(2026, 10, 20, 8, 0, 0, tzinfo=timezone.utc),
            )
        ],
        "run_mru": [],
    }
    findings = tool_traces.detect(registry_data=reg_data)
    assert len(findings) == 1
    assert "Eraser" in findings[0].title
    assert findings[0].confidence in (Confidence.MEDIUM, Confidence.HIGH)


def test_run_mru_command_detected():
    reg_data = {
        "userassist": [],
        "installed_programs": [],
        "run_mru": [
            RunMRUEntry(
                order="a",
                command="wevtutil cl Security",
                last_written=datetime(2026, 10, 24, 16, 0, 0, tzinfo=timezone.utc),
                user="Admin",
            )
        ],
    }
    findings = tool_traces.detect(registry_data=reg_data)
    assert len(findings) == 1
    assert "wevtutil" in findings[0].title
    assert findings[0].confidence in (Confidence.MEDIUM, Confidence.HIGH)


def test_mft_tool_binary_detected():
    mft_df = pd.DataFrame([
        {
            "entry": 100,
            "name": "sdelete.exe",
            "path": r"\Windows\System32\sdelete.exe",
            "si_modified": 133000000000000000,
            "si_created": 133000000000000000,
            "in_use": True,
            "is_dir": False,
        }
    ])
    findings = tool_traces.detect(mft=mft_df)
    assert len(findings) == 1
    assert "sdelete.exe" in findings[0].title


def _mft_row(entry, name, path):
    return {"entry": entry, "name": name, "path": path, "si_modified": 133000000000000000,
            "si_created": 133000000000000000, "in_use": True, "is_dir": False}


def test_builtin_tools_in_windows_folder_are_not_reported():
    """Every Windows install has cipher.exe and wevtutil.exe in System32 (and WinSxS)."""
    mft_df = pd.DataFrame([
        _mft_row(100, "cipher.exe", r"\Windows\System32\cipher.exe"),
        _mft_row(101, "wevtutil.exe", r"\Windows\System32\wevtutil.exe"),
        _mft_row(102, "wevtutil.exe", r"\Windows\WinSxS\amd64_wevtutil_31bf\wevtutil.exe"),
    ])
    assert tool_traces.detect(mft=mft_df) == []


def test_builtin_tool_copied_elsewhere_is_reported():
    mft_df = pd.DataFrame([_mft_row(100, "cipher.exe", r"\Users\Public\cipher.exe")])
    assert len(tool_traces.detect(mft=mft_df)) == 1


def test_builtin_tool_execution_is_discounted():
    df = pd.DataFrame([{"pf_file": "WEVTUTIL.EXE-1234ABCD.pf", "exe_name": "WEVTUTIL.EXE", "run_count": 1,
                        "run_index": 0, "run_time": datetime(2026, 10, 24, 14, 0, 0, tzinfo=timezone.utc)}])
    [f] = tool_traces.detect(prefetch_df=df)
    # LOW, not MEDIUM: on the clean Windows 11 test image Windows itself ran wevtutil 4 times
    # during setup. It is raised to MEDIUM by the correlation when a log clear is found nearby.
    assert f.confidence == Confidence.LOW
    assert any("Built-in Windows tool" in n for n in f.benign_notes)
