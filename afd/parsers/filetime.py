"""Windows FILETIME helpers.

A FILETIME is a 64-bit count of 100-nanosecond "ticks" since 1601-01-01 00:00 UTC.
NTFS, the registry, prefetch and event logs all use it.

We keep the raw tick value as well as a converted datetime, because:
  * Python datetimes only hold microseconds (10 ticks), so the last digit is lost.
  * Timestomping tools often write whole seconds, so ticks % 10_000_000 == 0
    ("zeroed sub-seconds") is a useful clue that conversion would hide.
"""
from datetime import datetime, timedelta, timezone

import pandas as pd

EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
EPOCH_DIFF = 116_444_736_000_000_000   # ticks between 1601-01-01 and 1970-01-01
TICKS_PER_SECOND = 10_000_000

# pandas datetime64[ns] can only hold years 1677..2262; outside that we return NaT
_PD_MIN = pd.Timestamp.min.value // 100 + EPOCH_DIFF + 1
_PD_MAX = pd.Timestamp.max.value // 100 + EPOCH_DIFF - 1


def filetime_to_datetime(ticks: int) -> datetime | None:
    """Convert ticks to a UTC datetime (microsecond precision). 0 or invalid -> None."""
    if not ticks:
        return None
    try:
        return EPOCH_1601 + timedelta(microseconds=ticks // 10)
    except OverflowError:
        return None


def filetime_to_iso(ticks: int) -> str:
    """Full-precision text form, e.g. 2026-10-25T11:42:07.1234567Z."""
    dt = filetime_to_datetime(ticks)
    if dt is None:
        return ""
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{ticks % TICKS_PER_SECOND:07d}Z"


def ticks_to_datetime_series(ticks: pd.Series) -> pd.Series:
    """Vectorised conversion of a column of ticks to datetime64 (UTC), NaT if out of range."""
    s = ticks.fillna(0).astype("int64")
    valid = (s > _PD_MIN) & (s < _PD_MAX)
    ns = (s.where(valid, EPOCH_DIFF) - EPOCH_DIFF) * 100
    return pd.to_datetime(ns, unit="ns", utc=True).where(valid)
