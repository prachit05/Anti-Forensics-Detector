"""Timestomping detector (MITRE ATT&CK T1070.006).

Forensic concept
----------------
Every NTFS file keeps its dates twice (see mft_parser):

  $STANDARD_INFORMATION ($SI)  what Explorer shows. Ordinary user-mode calls such as
                               SetFileTime() can overwrite it, so timestomping tools
                               (Timestomp, PowerShell, Metasploit, ...) edit this one.
  $FILE_NAME ($FN)             written by the kernel when the file is created, renamed
                               or moved. User-mode programs cannot change it directly.

So $FN is a hard-to-fake witness of when the file arrived on this volume. A file
cannot have been *created* before it arrived, so:

  CORE indicators (a finding needs at least one)
    si_before_fn   $SI created is earlier than $FN created.
    si_zeroed      $SI created and modified are both zero (some tools wipe them).
    future         a $SI date is later than anything else on the volume.

  SUPPORTING indicators (only add points to a finding that has a core indicator)
    zero_subsecond         $SI created and modified are whole seconds while $FN has
                           fractions. Genuine NTFS dates carry 100-ns detail; a tool
                           that takes a date as text writes whole seconds.
    changed_after_arrival  $SI "MFT changed" is long after the file arrived although
                           its write time is before it. SetFileTime cannot set the
                           change time, so it shows *when the dates were edited*.
    donor_match            $SI created+modified are identical to a Windows system file.
                           Some tools copy dates from a donor such as kernel32.dll.
    suspicious_path        the file sits in Temp, Public, the Recycle Bin and similar.

  CONTEXT that lowers the score (innocent explanations)
    bulk_pattern   many flagged files in one folder arrived within seconds of each
                   other. Installers and archive extraction write original (often
                   whole-second) dates onto many files and look exactly like this.
    benign_path    the file is under Program Files, WinSxS and similar.
    volume_burst   many flagged files *anywhere* arrived within a few minutes and none
                   show an "edited after arrival" trace (Windows setup, updates).

  Folders are skipped by default (include_directories): their "MFT changed" time moves
  whenever a file is added, so they look edited all the time.

Honest limits
-------------
  * Copying or extracting with preserved dates can trigger si_before_fn on its own,
    which is why that indicator alone is only LOW.
  * A careful attacker can also edit $FN (e.g. by moving the file twice) or stomp
    a file *forward*. This detector does not catch those.
  * Output means "likely", never proof.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import numpy as np
import pandas as pd

from afd.core.config import detector_settings, merge_config
from afd.core.finding import Finding, assign_ids, confidence_from_score, sort_findings
from afd.parsers.filetime import EPOCH_1601, TICKS_PER_SECOND, filetime_to_datetime, filetime_to_iso
from afd.parsers.mft_parser import TIME_FIELDS

DEFAULT_CONFIG = {
    "tolerance_seconds": 2.0,
    "mft_change_tolerance_seconds": 60.0,
    "future_margin_days": 1.0,
    "first_user_entry": 24,
    "medium_at": 4,
    "high_at": 6,
    "weights": {
        "si_before_fn": 3, "si_zeroed": 3, "future": 4,
        "zero_subsecond": 2, "changed_after_arrival": 1, "donor_match": 2,
        "suspicious_path": 1, "bulk_pattern": -3, "benign_path": -1,
    },
    "bulk_min_files": 8,
    "bulk_window_seconds": 120,
    "volume_burst_min_files": 50,
    "volume_burst_window_seconds": 300,
    "include_directories": False,
    "benign_path_prefixes": [
        "\\program files\\", "\\program files (x86)\\", "\\windows\\winsxs\\",
        "\\windows\\servicing\\", "\\windows\\installer\\",
        "\\windows\\softwaredistribution\\", "\\windows\\system32\\driverstore\\",
        "\\programdata\\package cache\\", "\\programdata\\microsoft\\",
    ],
    "suspicious_path_fragments": [
        "\\windows\\temp\\", "\\users\\public\\", "\\appdata\\local\\temp\\", "\\$recycle.bin\\",
    ],
    "donor_path_prefixes": [
        "\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\",
    ],
}

T = TICKS_PER_SECOND


# ---------------------------------------------------------------- small helpers

def _ticks(df: pd.DataFrame, col: str) -> pd.Series:
    """A timestamp column as int64 ticks (garbage values above int64 are clipped)."""
    s = pd.to_numeric(df[col], errors="coerce").fillna(0)
    return s.clip(lower=0, upper=2**63 - 1).astype("int64")


def _datetime_to_ticks(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=EPOCH_1601.tzinfo)
    return ((dt - EPOCH_1601) // timedelta(microseconds=1)) * 10


def _human(seconds: float) -> str:
    s = abs(seconds)
    if s < 120:
        return f"{s:.0f} seconds"
    if s < 7200:
        return f"{s / 60:.0f} minutes"
    if s < 172800:
        return f"{s / 3600:.1f} hours"
    if s < 60 * 86400:
        return f"{s / 86400:.0f} days"
    return f"{s / 86400 / 365.25:.1f} years"


def _bulk_flags(parent: pd.Series, arrival: pd.Series, window_s: float, min_files: int) -> np.ndarray:
    """True for rows that have >= min_files flagged siblings (same folder) whose $FN
    created time is within +-window_s. Siblings are counted including the row itself."""
    flags = np.zeros(len(parent), dtype=bool)
    frame = pd.DataFrame({"p": parent.fillna(-1).to_numpy(), "t": arrival.to_numpy(),
                          "i": np.arange(len(parent))})
    win = int(window_s * T)
    for _, group in frame.groupby("p"):
        if len(group) < min_files:
            continue
        t = group["t"].to_numpy()
        ordered = np.sort(t)
        count = np.searchsorted(ordered, t + win, "right") - np.searchsorted(ordered, t - win, "left")
        flags[group["i"].to_numpy()[count >= min_files]] = True
    return flags


def _burst_flags(arrival: pd.Series, window_s: float, min_files: int) -> np.ndarray:
    """True for rows where >= min_files flagged files *anywhere on the volume* arrived
    within +-window_s. Windows setup and installers spread thousands of files over many
    folders in a few minutes, which the per-folder check above cannot see."""
    t = arrival.to_numpy()
    ordered = np.sort(t)
    win = int(window_s * T)
    count = np.searchsorted(ordered, t + win, "right") - np.searchsorted(ordered, t - win, "left")
    return count >= min_files


def _find_donors(mft: pd.DataFrame, si_c: pd.Series, si_m: pd.Series,
                 work: pd.DataFrame, prefixes: list[str]) -> dict[int, tuple[int, str]]:
    """For each candidate outside the system folders, find a *different* system file
    with identical $SI created AND modified ticks. Returns {entry: (donor_entry, path)}."""
    if not prefixes:
        return {}
    pref = tuple(p.lower() for p in prefixes)
    pool_mask = mft["path"].fillna("").str.lower().str.startswith(pref) & (si_c > 0)
    pool = pd.DataFrame({"entry": mft["entry"], "path": mft["path"],
                         "si_created": si_c, "si_modified": si_m})[pool_mask]
    if pool.empty:
        return {}
    outside = ~work["path"].fillna("").str.lower().str.startswith(pref)
    cand = work.loc[outside, ["entry", "si_c", "si_m"]].rename(
        columns={"si_c": "si_created", "si_m": "si_modified"})
    cand = cand[cand["si_created"] > 0]
    merged = cand.merge(pool, on=["si_created", "si_modified"], suffixes=("", "_donor"))
    merged = merged[merged["entry"] != merged["entry_donor"]].drop_duplicates("entry")
    return {int(e): (int(d), p) for e, d, p in merged[["entry", "entry_donor", "path"]].itertuples(index=False)}


# ---------------------------------------------------------------- the detector

def detect(mft: pd.DataFrame, cfg: dict | None = None,
           reference_time: datetime | None = None) -> list[Finding]:
    """Run the timestomping checks on a DataFrame from mft_parser.load_mft().

    reference_time: when the image was acquired (UTC). If None, the newest $FN date
    on the volume is used as "now" for the future-date check.
    """
    cfg = merge_config(DEFAULT_CONFIG, detector_settings("timestomp"), cfg or {})
    w = cfg["weights"]
    if mft is None or mft.empty:
        return []

    tol = int(cfg["tolerance_seconds"] * T)
    tol_change = int(cfg["mft_change_tolerance_seconds"] * T)

    si = {t: _ticks(mft, f"si_{t}") for t in TIME_FIELDS}
    fn = {t: _ticks(mft, f"fn_{t}") for t in TIME_FIELDS}
    si_c, si_m, si_mc = si["created"], si["modified"], si["mft_modified"]
    fn_c, fn_mc = fn["created"], fn["mft_modified"]

    user = mft["entry"] >= cfg["first_user_entry"]
    if not cfg["include_directories"]:
        # A folder's $SI "MFT changed" moves every time a file is added to it, and setup
        # stamps folders with image build dates, so folders are almost all false positives.
        user &= ~mft["is_dir"].astype(bool)
    has_fn = fn_c > 0

    # ----- core indicators
    core_a = user & has_fn & (si_c > 0) & (si_c < fn_c - tol)
    core_zero = user & mft["in_use"].astype(bool) & has_fn & (si_c == 0) & (si_m == 0)

    if reference_time is not None:
        ref = _datetime_to_ticks(reference_time)
    else:
        ref = int(max(fn_c[user].max(), fn_mc[user].max())) if user.any() else 0
    future_limit = ref + int(cfg["future_margin_days"] * 86400 * T)
    si_newest = np.maximum.reduce([s.to_numpy() for s in si.values()])
    core_future = user & (ref > 0) & pd.Series(si_newest > future_limit, index=mft.index)

    candidates = core_a | core_zero | core_future
    if not candidates.any():
        return []

    # ----- supporting indicators (computed for all rows, used for candidates only)
    zero_sub = (si_c > 0) & (si_c % T == 0) & (si_m % T == 0) & (fn_c % T != 0)
    changed_after = (si_mc > fn_c + tol_change) & (si_m < fn_c - tol)

    work = mft.loc[candidates, ["entry", "seq", "in_use", "is_dir", "path", "parent_entry"]].copy()
    work["path"] = work["path"].fillna("")
    work["deleted"] = ~work["in_use"].astype(bool)
    for name, ser in {"si_c": si_c, "si_m": si_m, "si_mc": si_mc, "si_a": si["accessed"],
                      "fn_c": fn_c, "fn_m": fn["modified"], "fn_mc": fn_mc, "fn_a": fn["accessed"]}.items():
        work[name] = ser[candidates].to_numpy()
    work["core_a"] = core_a[candidates].to_numpy()
    work["core_zero"] = core_zero[candidates].to_numpy()
    work["core_future"] = core_future[candidates].to_numpy()
    work["zero_sub"] = zero_sub[candidates].to_numpy()
    work["changed_after"] = changed_after[candidates].to_numpy()
    work["bulk"] = _bulk_flags(work["parent_entry"], work["fn_c"],
                               cfg["bulk_window_seconds"], cfg["bulk_min_files"])
    # Installers write dates as they create files, so they leave no "edited after arrival"
    # trace. A burst that does carry that trace is not explained by installation.
    # Exception: on a deleted record the trace is unreliable, because removing a hard link
    # (Windows servicing links WinSxS and System32), renaming or deleting also moves it.
    edit_trace = work["changed_after"] & ~work["deleted"]
    work["burst"] = _burst_flags(work["fn_c"], cfg["volume_burst_window_seconds"],
                                 cfg["volume_burst_min_files"]) & ~edit_trace
    donors = _find_donors(mft, si_c, si_m, work, cfg["donor_path_prefixes"])

    benign_prefixes = tuple(p.lower() for p in cfg["benign_path_prefixes"])
    suspicious = tuple(p.lower() for p in cfg["suspicious_path_fragments"])

    findings: list[Finding] = []
    for r in work.itertuples(index=False):
        path_l = r.path.lower()
        score, reasons, benign, indicators = 0, [], [], []

        if r.core_a:
            score += w["si_before_fn"]
            indicators.append("si_created_before_fn_created")
            gap = (r.fn_c - r.si_c) / T
            reasons.append(
                f"$SI created ({filetime_to_iso(r.si_c)}) is {_human(gap)} earlier than "
                f"$FN created ({filetime_to_iso(r.fn_c)}). The file claims to be older than "
                f"its arrival on this volume.")
            benign.append("Copying or extracting a file with its original dates preserved "
                          "gives the same pattern.")
        if r.core_zero:
            score += w["si_zeroed"]
            indicators.append("si_dates_zeroed")
            reasons.append("$SI created and modified dates are both zero, which normal "
                           "file activity never produces.")
        if r.core_future:
            score += w["future"]
            indicators.append("si_date_in_future")
            reasons.append(
                f"A $SI date ({filetime_to_iso(max(r.si_c, r.si_m, r.si_mc, r.si_a))}) is later "
                f"than the newest activity on the volume ({filetime_to_iso(ref)}).")
            benign.append("A wrong system clock at the time of writing can cause this.")
        if r.zero_sub:
            score += w["zero_subsecond"]
            indicators.append("zero_subsecond_precision")
            reasons.append("$SI created and modified are whole seconds (.0000000) while "
                           "$FN created has sub-second detail.")
            benign.append("Archives, installers and FAT/exFAT sources store whole seconds, "
                          "so extracted files look like this.")
        if r.changed_after:
            score += w["changed_after_arrival"]
            indicators.append("mft_changed_after_arrival")
            reasons.append(
                f"$SI 'MFT changed' ({filetime_to_iso(r.si_mc)}) is {_human((r.si_mc - r.fn_c) / T)} "
                f"after the file arrived, while its write time is before arrival. This suggests "
                f"the dates were edited after the file was created.")
        if r.entry in donors:
            donor_entry, donor_path = donors[r.entry]
            score += w["donor_match"]
            indicators.append("dates_match_system_file")
            reasons.append(f"$SI created and modified are identical to a system file "
                           f"({donor_path}, entry {donor_entry}). Some tools copy dates from "
                           f"a donor such as kernel32.dll.")
        if any(frag in path_l + "\\" for frag in suspicious):
            score += w["suspicious_path"]
            indicators.append("suspicious_location")
            reasons.append("The file is in a location commonly used to stage malware.")

        if r.bulk:
            score += w["bulk_pattern"]
            indicators.append("bulk_pattern")
            benign.append(
                f"At least {cfg['bulk_min_files']} similar files in the same folder arrived within "
                f"{cfg['bulk_window_seconds']} seconds of each other. This is typical of an "
                f"installer or archive extraction, so the score was lowered.")
        elif r.burst:
            score += w["bulk_pattern"]
            indicators.append("volume_burst")
            benign.append(
                f"At least {cfg['volume_burst_min_files']} similar files across the volume arrived "
                f"within {cfg['volume_burst_window_seconds']} seconds of each other, with no sign "
                f"of their dates being edited later. This is typical of Windows setup, updates or "
                f"a software install, so the score was lowered.")
        if path_l.startswith(benign_prefixes):
            score += w["benign_path"]
            indicators.append("trusted_location")
            benign.append("The file is in a software-install location (Program Files, WinSxS, ...), "
                          "so the score was lowered.")

        confidence = confidence_from_score(score, cfg["medium_at"], cfg["high_at"])

        if r.changed_after:
            event_ticks, meaning = r.si_mc, "$SI 'MFT changed': likely when the dates were edited"
        else:
            event_ticks, meaning = r.fn_c, "$FN created: when the file arrived on this volume"

        evidence = {
            "entry": int(r.entry), "sequence": int(r.seq), "deleted": bool(r.deleted),
            "is_directory": bool(r.is_dir), "indicators": indicators,
            **{f"si_{t}": filetime_to_iso(v) for t, v in
               zip(TIME_FIELDS, (r.si_c, r.si_m, r.si_mc, r.si_a))},
            **{f"fn_{t}": filetime_to_iso(v) for t, v in
               zip(TIME_FIELDS, (r.fn_c, r.fn_m, r.fn_mc, r.fn_a))},
        }
        if r.deleted:
            benign.append("The file is deleted; only its leftover MFT record was analysed.")
        title_name = r.path or f"(entry {r.entry})"
        findings.append(Finding(
            module="timestomp", technique="Timestomping", mitre="T1070.006",
            title=f"Possible timestomping: {title_name}",
            confidence=confidence, score=score, subject=title_name,
            artifact=f"$MFT entry {r.entry}", reasons=reasons, benign_notes=benign,
            evidence=evidence, event_time=filetime_to_datetime(event_ticks),
            time_meaning=meaning))

    return assign_ids(sort_findings(findings))
