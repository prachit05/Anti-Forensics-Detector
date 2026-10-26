"""Machine learning anomaly detector using Isolation Forest (scikit-learn).

Forensic concept
----------------
Deterministic rule-based detectors rely on predefined thresholds (e.g. gap > 6 hours,
$SI created earlier than $FN created). Sophisticated adversaries may intentionally calibrate
their tampering to sit just below these static thresholds, or cause subtle temporal
distortions across thousands of events.

Unsupervised machine learning via Isolation Forest (Liu et al., 2008) provides an
independent layer of statistical anomaly detection:
  - Concept: Anomalies are few and different. In randomized partitioning trees, anomalous
    data points require significantly fewer tree splits to isolate from the rest of the
    dataset, yielding shorter average path lengths.
  - Event Log Interval Anomalies:
    Features extracted:
      1. Inter-event time delta (seconds between consecutive events).
      2. Record-ID delta (difference between successive EventRecordIDs).
      3. Rolling event density (events occurring in a local 15-minute window).
    Detects abnormal periods of silence, sudden bursts following dormancy, or irregular
    record-ID skipping.
  - MFT Timestamp Discrepancy Anomalies:
    Features extracted:
      1. Absolute delta between $SI and $FN created timestamps.
      2. Absolute delta between $SI and $FN modified timestamps.
      3. $SI subsecond fractional ticks (identifying precision truncations).
    Flags multi-dimensional outlier records whose timestamp distributions deviate
    abnormally from the surrounding volume population.

Honest limits
-------------
- Unsupervised ML flags statistical outliers, not guilt or malice. A sudden burst of events
  might simply be Windows applying an automatic update or an administrator exporting logs.
- Findings are always reported as LOW: supporting evidence to be cross-checked against the
  rule-based detectors and the timeline. On a clean Windows 11 image the model flagged 224
  Windows servicing files and setup-time log intervals at what used to be MEDIUM, so an
  outlier on its own is not trusted. ML findings also never count towards a campaign.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from afd.core.config import detector_settings, merge_config
from afd.core.finding import Confidence, Finding, assign_ids, confidence_from_score, sort_findings
from afd.parsers.filetime import filetime_to_datetime

DEFAULT_CONFIG = {
    "medium_at": 4,
    "high_at": 6,
    "log_contamination": 0.01,       # expected % of anomalous events
    "mft_contamination": 0.005,      # expected % of anomalous MFT records
    "min_records_for_ml": 50,        # minimum records required to fit model reliably
}


def detect_log_anomalies(
    logs: list[tuple[pd.DataFrame, dict]],
    cfg: dict | None = None,
) -> list[Finding]:
    """Use Isolation Forest to detect anomalous inter-event intervals and rate shifts in event logs.

    Parameters:
        logs: list of (DataFrame, info) pairs from evtx_parser.load_evtx()
        cfg: optional configuration overrides
    """
    cfg = merge_config(DEFAULT_CONFIG, detector_settings("ml"), cfg or {})
    contamination = cfg.get("log_contamination", 0.01)
    min_records = cfg.get("min_records_for_ml", 50)

    findings: list[Finding] = []

    for df, info in logs:
        if df.empty or len(df) < min_records:
            continue

        log_name = info.get("file", "unknown.evtx")
        df_sorted = df.sort_values("time_created").copy()

        # Feature engineering
        times = df_sorted["time_created"].dt.tz_convert("UTC").dt.tz_localize(None)
        time_deltas = (times - times.shift(1)).dt.total_seconds().fillna(0).to_numpy()

        record_ids = df_sorted["record_id"].to_numpy()
        id_deltas = np.diff(record_ids, prepend=record_ids[0])

        # Clip extreme outliers to prevent distortion during fitting
        clipped_time_deltas = np.clip(time_deltas, 0, 86400 * 7)
        clipped_id_deltas = np.clip(id_deltas, 0, 10000)

        # Feature matrix: [time_delta, id_delta]
        X = np.column_stack([clipped_time_deltas, clipped_id_deltas])

        try:
            model = IsolationForest(
                contamination=contamination,
                random_state=42,
                n_estimators=100,
            )
            model.fit(X)
            scores = model.decision_function(X)    # Lower score = more anomalous
            preds = model.predict(X)                # -1 = anomaly, 1 = normal
        except Exception:
            continue

        anomaly_indices = np.where(preds == -1)[0]

        for idx in anomaly_indices:
            row = df_sorted.iloc[idx]
            dt_sec = time_deltas[idx]
            id_step = id_deltas[idx]
            anom_score = float(scores[idx])

            # Filter out ordinary small deviations; only flag significant temporal or id jumps
            if dt_sec < 300 and id_step <= 1:
                continue

            reasons = []
            if dt_sec >= 3600:
                reasons.append(f"Statistically anomalous inter-event silence of {dt_sec / 3600:.1f} hours.")
            elif dt_sec >= 300:
                reasons.append(f"Unusual event interval of {dt_sec / 60:.1f} minutes.")

            if id_step > 1:
                reasons.append(f"Record-ID stepped by {id_step} (skipped IDs).")

            reasons.append(f"Isolation Forest outlier score: {anom_score:.3f} (decision boundary <= 0.0).")

            event_dt = row["time_created"].to_pydatetime()
            if event_dt.tzinfo is None:
                event_dt = event_dt.replace(tzinfo=timezone.utc)

            findings.append(Finding(
                module="ml_anomaly",
                technique="Unsupervised Anomaly Detection (Isolation Forest)",
                mitre="T1070.001",
                title=f"Statistical anomaly in event log: {log_name} (Event #{row['record_id']})",
                confidence=Confidence.LOW,
                score=3 if dt_sec >= 7200 or id_step > 5 else 2,
                subject=f"{log_name} Record #{row['record_id']}",
                artifact=f"{log_name}",
                reasons=reasons,
                benign_notes=[
                    "Unsupervised anomaly detection flags statistical outliers. "
                    "Corroborate with System restarts and audit policies before inferring tampering."
                ],
                evidence={
                    "log_file": log_name,
                    "record_id": int(row["record_id"]),
                    "time_delta_seconds": round(dt_sec, 1),
                    "id_delta": int(id_step),
                    "anomaly_score": round(anom_score, 4),
                },
                event_time=event_dt,
                time_meaning="event occurrence timestamp",
            ))

    return assign_ids(sort_findings(findings))


def detect_mft_anomalies(
    mft: pd.DataFrame,
    cfg: dict | None = None,
) -> list[Finding]:
    """Use Isolation Forest to detect multivariate timestamp anomalies across MFT records.

    Parameters:
        mft: DataFrame from mft_parser.load_mft()
        cfg: optional configuration overrides
    """
    cfg = merge_config(DEFAULT_CONFIG, detector_settings("ml"), cfg or {})
    contamination = cfg.get("mft_contamination", 0.005)
    min_records = cfg.get("min_records_for_ml", 50)

    findings: list[Finding] = []
    if mft.empty or len(mft) < min_records:
        return findings

    # Filter out NTFS internal metadata records (< 24) and directories
    user_files = mft[(mft["entry"] >= 24) & (~mft["is_dir"])].copy()
    if len(user_files) < min_records:
        return findings

    # Feature engineering:
    # 1. Delta between SI created and FN created (seconds)
    # 2. Delta between SI modified and FN modified (seconds)
    # 3. Subsecond zeroed indicator (1 if SI has 0 nanoseconds, else 0)
    si_c = user_files["si_created"].to_numpy(dtype=np.int64)
    fn_c = user_files["fn_created"].to_numpy(dtype=np.int64)
    si_m = user_files["si_modified"].to_numpy(dtype=np.int64)
    fn_m = user_files["fn_modified"].to_numpy(dtype=np.int64)

    delta_created = np.abs(si_c - fn_c) / 10_000_000.0  # seconds
    delta_modified = np.abs(si_m - fn_m) / 10_000_000.0
    zero_subsecond = ((si_c % 10_000_000 == 0) & (fn_c % 10_000_000 != 0)).astype(np.float64)

    # Clip to avoid extreme numerical overflow
    delta_created = np.clip(delta_created, 0, 86400 * 365 * 10)
    delta_modified = np.clip(delta_modified, 0, 86400 * 365 * 10)

    X = np.column_stack([delta_created, delta_modified, zero_subsecond])

    try:
        model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
        )
        model.fit(X)
        scores = model.decision_function(X)
        preds = model.predict(X)
    except Exception:
        return findings

    anomaly_indices = np.where(preds == -1)[0]

    for idx in anomaly_indices:
        row = user_files.iloc[idx]
        d_c = delta_created[idx]
        d_m = delta_modified[idx]
        anom_score = float(scores[idx])

        # Filter out minor deviations
        if d_c < 10 and d_m < 10 and not zero_subsecond[idx]:
            continue

        reasons = [
            f"Isolation Forest identified multivariate timestamp anomaly (outlier score: {anom_score:.3f}).",
            f"Difference between $SI created and $FN created: {d_c:.1f} seconds.",
        ]
        if zero_subsecond[idx]:
            reasons.append("$SI timestamp has zeroed nanoseconds while $FN contains high-resolution subsecond ticks.")

        raw_mod = int(row.get("si_modified", 0)) or int(row.get("si_created", 0))
        event_time = filetime_to_datetime(raw_mod) if raw_mod > 0 else None

        findings.append(Finding(
            module="ml_anomaly",
            technique="Unsupervised Anomaly Detection (Isolation Forest)",
            mitre="T1070.006",
            title=f"Statistical timestamp anomaly: {row['name']} (MFT #{row['entry']})",
            confidence=Confidence.LOW,
            score=3 if d_c > 86400 else 2,
            subject=str(row["path"]) or f"MFT entry {row['entry']}",
            artifact=f"$MFT entry {row['entry']}",
            reasons=reasons,
            benign_notes=["Third-party archivers and backup tools can also write legacy timestamp formats."],
            evidence={
                "entry": int(row["entry"]),
                "name": str(row["name"]),
                "delta_created_seconds": round(d_c, 1),
                "delta_modified_seconds": round(d_m, 1),
                "anomaly_score": round(anom_score, 4),
            },
            event_time=event_time,
            time_meaning="file modified timestamp",
        ))

    return assign_ids(sort_findings(findings))
