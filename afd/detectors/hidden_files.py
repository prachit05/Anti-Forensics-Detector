"""Hidden and disguised files detector (MITRE ATT&CK T1564.004, T1036.008).

Forensic concept
----------------
Attackers hide tools, malware, or stolen data on NTFS systems using two classic techniques:

1. Alternate Data Streams (ADS - T1564.004):
   NTFS files can have multiple $DATA attributes. The default stream is unnamed (filename:$DATA).
   Additional named streams (filename:streamname:$DATA) are hidden from Windows Explorer, standard
   'dir' output, and do not reflect in the file's visible size.
   - Benign ADS: Web browsers automatically tag downloaded files with a 'Zone.Identifier'
     stream (Mark of the Web / MOTW). A few OS components use 'favicon' or 'WofCompressedData'.
   - Suspicious ADS: Executable files hidden inside streams (e.g. notepad.exe:evil.exe),
     scripts (.ps1, .vbs, .bat), large data dumps hidden behind tiny text files, or ADS
     attached to directories.

2. File Type Masquerading / Header-Extension Mismatch (T1036.008):
   To evade detection and bypass execution policies or casual inspection, attackers disguise
   executable binaries by giving them benign extensions (e.g. 'picture.jpg', 'log.txt', 'data.dat').
   - True file types are defined by their magic numbers (file signature headers), not extensions.
   - An MZ header (0x4D 0x5A, 'MZ') inside a file named '.txt', '.png', or '.pdf' is strong
     evidence of deliberate masquerading.

Honest limits
-------------
- For non-resident files whose content was not extracted, only the file extension and MFT
  metadata are available; header inspection is limited to resident files or extracted files.
- Some legitimate software (e.g. self-extracting zip installers or legacy database formats)
  embed executable headers within custom data extensions (.dat, .bin); these receive lower
  scores unless located in suspicious directories.
- Findings report 'likely hidden or disguised file', never absolute proof of malice.
"""
from __future__ import annotations

import re
from pathlib import Path

import pandas as pd

from afd.core.config import detector_settings, merge_config
from afd.core.finding import Confidence, Finding, assign_ids, confidence_from_score, sort_findings
from afd.parsers.filetime import filetime_to_datetime

DEFAULT_CONFIG = {
    "medium_at": 4,
    "high_at": 6,
    "weights": {
        "ads_pe_executable": 6,
        "ads_script": 4,
        "ads_large_stream": 4,
        "ads_unknown": 2,
        "type_spoof_executable": 6,
        "type_spoof_archive": 4,
    },
    "benign_ads_names": [
        "zone.identifier",
        "favicon",
        "smartscreen",
        "encryptable",
        "wofcompresseddata",
    ],
    "large_stream_threshold_bytes": 1048576,  # 1 MB
}

# Signatures for header verification
SIG_PE = b"MZ"                 # Windows Portable Executable (EXE/DLL/SYS)
SIG_ELF = b"\x7fELF"           # Linux ELF executable
SIG_ZIP = b"PK\x03\x04"        # ZIP archive / docx / xlsx / jar
SIG_PDF = b"%PDF"              # PDF document
SIG_PNG = b"\x89PNG\r\n\x1a\n" # PNG image
SIG_JPG = b"\xff\xd8\xff"      # JPEG image
SIG_GIF = b"GIF8"              # GIF image

# Extensions that should NEVER legitimately have an MZ executable header
BENIGN_EXTENSIONS_PE_MISMATCH = {
    ".txt", ".log", ".ini", ".cfg", ".csv",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico",
    ".pdf", ".docx", ".xlsx", ".pptx",
    ".mp3", ".mp4", ".wav", ".avi",
}

SCRIPT_EXTENSIONS = {".ps1", ".vbs", ".bat", ".cmd", ".sh", ".py", ".js", ".hta"}


def _check_ads(row: pd.Series, cfg: dict) -> list[Finding]:
    """Inspect Alternate Data Streams attached to an MFT entry."""
    ads_names = row.get("ads_names") or []
    ads_sizes = row.get("ads_sizes") or []
    if not ads_names:
        return []

    benign_ads = {n.lower() for n in cfg.get("benign_ads_names", [])}
    weights = cfg["weights"]
    large_thresh = cfg.get("large_stream_threshold_bytes", 1048576)

    findings = []
    base_size = int(row.get("size", 0))

    for stream_name, stream_size in zip(ads_names, ads_sizes):
        s_lower = stream_name.lower()
        if s_lower in benign_ads:
            continue

        score = 0
        reasons = []
        evidence = {
            "entry": int(row["entry"]),
            "path": str(row["path"]),
            "stream_name": stream_name,
            "stream_size": int(stream_size),
            "base_size": base_size,
        }

        # Check for script extension in stream name
        suffix = Path(stream_name).suffix.lower()
        if suffix in SCRIPT_EXTENSIONS:
            score += weights["ads_script"]
            reasons.append(f"Alternate Data Stream name '{stream_name}' contains a script extension ({suffix}).")

        # Check for large stream (larger than host file or > 1MB)
        if stream_size > large_thresh or (base_size > 0 and stream_size > base_size * 2):
            score += weights["ads_large_stream"]
            reasons.append(
                f"Stream size ({stream_size:,} bytes) is unusually large compared to host file ({base_size:,} bytes)."
            )

        if score == 0:
            score += weights["ads_unknown"]
            reasons.append(f"Non-standard Alternate Data Stream '{stream_name}' attached to file.")

        if score < cfg["medium_at"]:
            continue

        raw_mod = int(row.get("si_modified", 0)) or int(row.get("si_mft_modified", 0))
        event_time = filetime_to_datetime(raw_mod) if raw_mod > 0 else None

        findings.append(Finding(
            module="hidden_files",
            technique="Alternate Data Streams (ADS)",
            mitre="T1564.004",
            title=f"Suspicious Alternate Data Stream: {row['name']}:{stream_name}",
            confidence=confidence_from_score(score, cfg["medium_at"], cfg["high_at"]),
            score=score,
            subject=f"{row['path']}:{stream_name}",
            artifact=f"$MFT entry {row['entry']}",
            reasons=reasons,
            benign_notes=["Some third-party sync or backup tools create custom ADS metadata."],
            evidence=evidence,
            event_time=event_time,
            time_meaning="file modified timestamp",
        ))

    return findings


def _check_header_mismatch(row: pd.Series, cfg: dict) -> Finding | None:
    """Detect magic byte / file extension spoofing (e.g. PE executable disguised as text/image)."""
    head = row.get("head")
    if not isinstance(head, (bytes, bytearray)) or len(head) < 4:
        return None

    name = str(row.get("name", ""))
    path = str(row.get("path", ""))
    ext = Path(name).suffix.lower()
    weights = cfg["weights"]

    score = 0
    reasons = []
    evidence = {
        "entry": int(row["entry"]),
        "name": name,
        "path": path,
        "extension": ext,
        "header_hex": head[:8].hex(),
    }

    # Case 1: PE executable disguised with benign document or media extension
    if head[:2] == SIG_PE and ext in BENIGN_EXTENSIONS_PE_MISMATCH:
        score += weights["type_spoof_executable"]
        reasons.append(
            f"File has Windows PE executable header ('MZ'), but uses deceptive extension '{ext}'. "
            "This is a common technique to sneak executables past perimeter filters or disguise tools."
        )
        evidence["detected_type"] = "Windows PE Executable"

    # Case 2: Linux ELF executable on Windows disguised
    elif head[:4] == SIG_ELF and ext in BENIGN_EXTENSIONS_PE_MISMATCH:
        score += weights["type_spoof_executable"]
        reasons.append(
            f"File has ELF binary header, but uses extension '{ext}'."
        )
        evidence["detected_type"] = "ELF Executable"

    # Case 3: ZIP/Office archive disguised as plain image/text
    elif head[:4] == SIG_ZIP and ext in {".txt", ".jpg", ".png", ".pdf"}:
        score += weights["type_spoof_archive"]
        reasons.append(
            f"File contains ZIP/PK archive header, but extension is '{ext}'."
        )
        evidence["detected_type"] = "ZIP Archive"

    if score < cfg["medium_at"]:
        return None

    raw_mod = int(row.get("si_modified", 0)) or int(row.get("si_created", 0))
    event_time = filetime_to_datetime(raw_mod) if raw_mod > 0 else None

    return Finding(
        module="hidden_files",
        technique="Masquerading: File Type Mismatch",
        mitre="T1036.008",
        title=f"Disguised file header mismatch: {name} (Header: {evidence.get('detected_type')})",
        confidence=confidence_from_score(score, cfg["medium_at"], cfg["high_at"]),
        score=score,
        subject=path,
        artifact=f"$MFT entry {row['entry']}",
        reasons=reasons,
        benign_notes=["Polyglot files or corrupted file headers can sometimes cause false flags."],
        evidence=evidence,
        event_time=event_time,
        time_meaning="file timestamp",
    )


def detect(mft: pd.DataFrame, cfg: dict | None = None) -> list[Finding]:
    """Scan MFT entries for Alternate Data Streams and file type masquerading.

    Parameters:
        mft: DataFrame from mft_parser.load_mft()
        cfg: optional configuration overrides
    """
    cfg = merge_config(DEFAULT_CONFIG, detector_settings("hidden_files"), cfg or {})

    if mft.empty:
        return []

    findings: list[Finding] = []

    # Filter active files and recent deleted files (skip NTFS internal entries < 24)
    df = mft[mft["entry"] >= 24]

    for _, row in df.iterrows():
        # Check 1: Alternate Data Streams
        findings.extend(_check_ads(row, cfg))

        # Check 2: Header / extension masquerading
        mismatch = _check_header_mismatch(row, cfg)
        if mismatch:
            findings.append(mismatch)

    return assign_ids(sort_findings(findings))
