"""File wiping and secure deletion detector (MITRE ATT&CK T1070.004).

Forensic concept
----------------
Standard Windows deletion does not destroy data. When a file is deleted:
  1. The MFT record's in-use flag is cleared (0x01 -> 0x00).
  2. The clusters are marked unallocated in $Bitmap.
  The original file name, timestamps, and resident/non-resident data remain in the
  MFT entry until the record is reallocated. Forensic examiners routinely recover
  these "deleted" files.

Anti-forensic secure deletion tools (SDelete, Eraser, BCWipe, etc.) counter this by:
  1. Content Overwrite: Overwriting the file's data clusters with fixed patterns
     (all 0x00, all 0xFF, repeating bytes 0x55/0xAA, or pseudorandom data).
     For resident files (files <= ~700 bytes whose data resides directly inside the
     MFT $DATA attribute), this overwriting leaves the MFT record's resident content
     filled with uniform bytes before deletion.
  2. Name Mangling: Sysinternals SDelete renames the file multiple times through
     the alphabet (e.g. AAAAAAAA.AAA -> ... -> ZZZZZZZZ.ZZZ) to wipe the original
     filename from the directory index and MFT $FILE_NAME attribute before deletion.
     Other wipers use random alphanumeric strings.
  3. File Truncation: Secure wipers typically truncate the file size to 0 bytes
     after wiping the content.

Honest limits
-------------
- If a secure deletion tool only wipes non-resident clusters and the file record
  is later reallocated by NTFS for a new file, the original wiping trace in the
  MFT is lost.
- Zero-length deleted files can occur naturally when temporary files or locks are
  created and quickly closed without data written.
- Genuine installers use randomized names for temporary unpack directories or files;
  known temp patterns are downgraded to prevent false positives.
- A finding indicates "likely secure file deletion", never absolute proof.
"""
from __future__ import annotations

import math
import re
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

from afd.core.config import detector_settings, merge_config
from afd.core.finding import Confidence, Finding, assign_ids, confidence_from_score, sort_findings
from afd.parsers.filetime import filetime_to_datetime, filetime_to_iso

DEFAULT_CONFIG = {
    "medium_at": 4,
    "high_at": 6,
    "weights": {
        "sdelete_mangled_name": 5,
        "resident_zero_fill": 4,
        "resident_uniform_byte": 4,
        "random_mangled_name": 3,
        "zero_size_deleted": 1,
        "benign_temp_name": -2,
    },
    "min_resident_check_bytes": 8,
}

# Regex for SDelete style mangled names: 1 to 26 identical repeated letters + extension
# e.g., "AAAAAAA.AAA", "ZZZZZZZZ.ZZZ", "BBBBBBBB"
_SDELETE_RE = re.compile(r"^([a-zA-Z])\1{2,}(\.([a-zA-Z])\3*)?$")

# Common benign temp file patterns (e.g., GUIDs, Chrome crashpad, Windows update)
_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_HEX_TMP_RE = re.compile(r"^(~|tmp|temp|[0-9a-fA-F]{6,}\.tmp)$", re.IGNORECASE)


def _char_entropy(s: str) -> float:
    """Calculate Shannon entropy of characters in a string."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)


def _is_sdelete_name(name: str) -> bool:
    """Check if the filename matches SDelete's character-mangling signature."""
    if not name or name in (".", ".."):
        return False
    # SDelete typically renames files to repeated single characters like "ZZZZZZZZ.ZZZ" or "AAAAAAAA.AAA"
    if _SDELETE_RE.match(name):
        return True
    return False


def _is_random_mangled_name(name: str) -> bool:
    """Check if a deleted filename looks like an Eraser-style randomized string."""
    stem = Path(name).stem
    if len(stem) < 8:
        return False
    if _GUID_RE.match(stem) or _HEX_TMP_RE.match(name):
        return False
    # If the name has high character entropy and lacks vowels or looks like random alphanumeric
    entropy = _char_entropy(stem)
    vowels = sum(c.lower() in "aeiou" for c in stem)
    vowel_ratio = vowels / len(stem)
    if entropy >= 3.2 and (vowel_ratio < 0.12 or vowel_ratio > 0.7):
        return True
    return False


def _check_resident_pattern(head: bytes, min_bytes: int) -> tuple[str | None, str]:
    """Inspect resident content for wipe patterns (all zeros, all 0xFF, or repeating byte)."""
    if not head or len(head) < min_bytes:
        return None, ""

    # All zeros
    if all(b == 0 for b in head):
        return "zero_fill", f"Resident stream ({len(head)} bytes) is completely zeroed (0x00 overwrite)"

    # All 0xFF
    first = head[0]
    if all(b == first for b in head):
        if first == 0xFF:
            return "uniform_byte", f"Resident stream ({len(head)} bytes) is overwritten with 0xFF"
        return "uniform_byte", f"Resident stream ({len(head)} bytes) is overwritten with repeated 0x{first:02X}"

    return None, ""


def detect(mft: pd.DataFrame, cfg: dict | None = None) -> list[Finding]:
    """Detect secure file deletion and wiping indicators across deleted MFT entries.

    Parameters:
        mft: pandas DataFrame loaded via mft_parser.load_mft()
        cfg: optional configuration overrides
    """
    cfg = merge_config(DEFAULT_CONFIG, detector_settings("file_wiping"), cfg or {})
    weights = cfg["weights"]
    min_bytes = cfg.get("min_resident_check_bytes", 8)

    if mft.empty:
        return []

    # Focus on deleted entries (in_use == False) that are not directories
    # Also skip system entries (< 24)
    deleted_mask = (~mft["in_use"]) & (~mft["is_dir"]) & (mft["entry"] >= 24)
    deleted_df = mft[deleted_mask]

    findings: list[Finding] = []

    for _, row in deleted_df.iterrows():
        score = 0
        reasons: list[str] = []
        benign_notes: list[str] = []
        evidence: dict = {
            "entry": int(row["entry"]),
            "sequence": int(row["seq"]),
            "path": str(row["path"]),
            "name": str(row["name"]),
            "size": int(row["size"]),
            "resident": bool(row["resident"]) if pd.notna(row["resident"]) else False,
        }

        name = str(row["name"])
        head = row["head"] if isinstance(row["head"], (bytes, bytearray)) else b""
        size = int(row["size"]) if pd.notna(row["size"]) else 0

        # Indicator 1: SDelete filename mangling pattern
        if _is_sdelete_name(name):
            score += weights["sdelete_mangled_name"]
            reasons.append(
                f"Filename '{name}' matches Sysinternals SDelete mangling pattern "
                "(file renamed repeatedly with identical letters before deletion to wipe metadata)."
            )
            evidence["sdelete_pattern"] = True

        # Indicator 2: Eraser style randomized mangled name
        elif _is_random_mangled_name(name):
            score += weights["random_mangled_name"]
            reasons.append(
                f"Filename '{name}' exhibits high entropy and pattern typical of secure file wiper renaming."
            )
            evidence["random_name_entropy"] = round(_char_entropy(Path(name).stem), 2)

        # Indicator 3: Resident content wipe patterns
        if bool(row["resident"]):
            pattern_type, desc = _check_resident_pattern(head, min_bytes)
            if pattern_type == "zero_fill":
                score += weights["resident_zero_fill"]
                reasons.append(desc)
                evidence["resident_pattern"] = "0x00_zero_fill"
            elif pattern_type == "uniform_byte":
                score += weights["resident_uniform_byte"]
                reasons.append(desc)
                evidence["resident_pattern"] = "repeating_byte"

        # Supporting indicator: zero size deleted file
        if size == 0 and score > 0:
            score += weights["zero_size_deleted"]
            reasons.append("File size was truncated to 0 bytes (standard secure deletion final step).")
            evidence["truncated_zero_size"] = True

        # Benign check: known temporary patterns
        if _GUID_RE.match(Path(name).stem) or _HEX_TMP_RE.match(name) or ".tmp" in name.lower():
            score += weights.get("benign_temp_name", -2)
            benign_notes.append("Legitimate installer or OS temp files sometimes use pseudo-random names.")

        if score < cfg["medium_at"] and not reasons:
            continue

        if score <= 0:
            continue

        confidence = confidence_from_score(score, cfg["medium_at"], cfg["high_at"])

        # Determine event time: prefer MFT change time or write time
        raw_mft_mod = int(row["si_mft_modified"]) if pd.notna(row["si_mft_modified"]) else 0
        raw_mod = int(row["si_modified"]) if pd.notna(row["si_modified"]) else 0
        event_raw = raw_mft_mod or raw_mod
        event_time = filetime_to_datetime(event_raw) if event_raw > 0 else None

        title = f"Securely wiped file: {name or f'MFT #{row.entry}'}"
        if "sdelete_pattern" in evidence:
            title = f"SDelete file wiping trace: {name}"

        findings.append(Finding(
            module="file_wiping",
            technique="Secure File Deletion / Wiping",
            mitre="T1070.004",
            title=title,
            confidence=confidence,
            score=score,
            subject=str(row["path"]) or f"MFT entry {row.entry}",
            artifact=f"$MFT entry {row.entry}",
            reasons=reasons,
            benign_notes=benign_notes,
            evidence=evidence,
            event_time=event_time,
            time_meaning="last MFT record modification timestamp",
        ))

    return assign_ids(sort_findings(findings))
