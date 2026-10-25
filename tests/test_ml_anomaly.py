"""Tests for machine learning anomaly detector (Isolation Forest)."""
from datetime import datetime, timedelta, timezone
import pandas as pd
import pytest

from afd.analysis.ml_anomaly import detect_log_anomalies, detect_mft_anomalies
from afd.core.finding import Confidence


def test_detect_log_anomalies_flags_massive_gap():
    # 80 events every 10 seconds, then 1 event 12 hours later, then 20 events
    base_time = datetime(2026, 10, 24, 8, 0, 0, tzinfo=timezone.utc)
    records = []

    for i in range(80):
        records.append({
            "record_id": i + 1,
            "time_created": base_time + timedelta(seconds=i * 10),
            "event_id": 4624,
            "provider": "Microsoft-Windows-Security-Auditing",
            "log_file": "Security.evtx",
        })

    # The anomaly: 12-hour gap and jumped record ID
    gap_time = base_time + timedelta(seconds=800) + timedelta(hours=12)
    records.append({
        "record_id": 500,
        "time_created": gap_time,
        "event_id": 1102,
        "provider": "Microsoft-Windows-Eventlog",
        "log_file": "Security.evtx",
    })

    for i in range(20):
        records.append({
            "record_id": 501 + i,
            "time_created": gap_time + timedelta(seconds=(i + 1) * 10),
            "event_id": 4624,
            "provider": "Microsoft-Windows-Security-Auditing",
            "log_file": "Security.evtx",
        })

    df = pd.DataFrame(records)
    info = {"file": "Security.evtx", "records": len(df)}

    findings = detect_log_anomalies([(df, info)], cfg={"log_contamination": 0.05, "min_records_for_ml": 50})
    assert len(findings) >= 1
    assert any("Security.evtx" in f.title for f in findings)
    assert any("outlier score" in r for f in findings for r in f.reasons)


def test_detect_mft_anomalies_flags_outlier_record():
    # 80 normal files where SI == FN
    t0_ticks = 133000000000000000  # FILETIME
    rows = []
    for i in range(80):
        rows.append({
            "entry": 50 + i,
            "name": f"file_{i}.txt",
            "path": f"\\Users\\Test\\file_{i}.txt",
            "is_dir": False,
            "si_created": t0_ticks + i * 10_000_000,
            "fn_created": t0_ticks + i * 10_000_000,
            "si_modified": t0_ticks + i * 10_000_000,
            "fn_modified": t0_ticks + i * 10_000_000,
        })

    # Outlier file: 10-year timestamp delta and zeroed subseconds
    outlier_ticks = t0_ticks - (10 * 365 * 86400 * 10_000_000)
    rows.append({
        "entry": 200,
        "name": "timestomped_target.exe",
        "path": "\\Users\\Test\\timestomped_target.exe",
        "is_dir": False,
        "si_created": outlier_ticks,
        "fn_created": t0_ticks + 500 * 10_000_000,
        "si_modified": outlier_ticks,
        "fn_modified": t0_ticks + 500 * 10_000_000,
    })

    df = pd.DataFrame(rows)
    findings = detect_mft_anomalies(df, cfg={"mft_contamination": 0.05, "min_records_for_ml": 50})
    assert len(findings) >= 1
    assert any("timestomped_target.exe" in f.title for f in findings)
    assert any("Isolation Forest" in f.reasons[0] for f in findings)


def test_ml_gracefully_skips_small_dataset():
    # Only 5 records (less than min_records_for_ml=50)
    df = pd.DataFrame([{"record_id": i, "time_created": datetime.now(timezone.utc)} for i in range(5)])
    findings = detect_log_anomalies([(df, {"file": "Test.evtx"})], cfg={"min_records_for_ml": 50})
    assert findings == []
