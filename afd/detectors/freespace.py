"""Disk and free-space wiping detector (MITRE ATT&CK T1070.004).

Forensic concept
----------------
When files are deleted normally, their clusters in unallocated space remain unchanged.
Forensic examiners routinely carve files (pictures, documents, executables) from this
unallocated space using signatures and file structure.

To defeat file carving, attackers and anti-forensic tools wipe unallocated space:
  - 'cipher /w:<dir>': Windows built-in utility. Performs 3 sequential passes over
    all unallocated space:
      Pass 1: Overwrites with 0x00 (all zeros).
      Pass 2: Overwrites with 0xFF (all ones).
      Pass 3: Overwrites with pseudorandom numbers.
  - 'sdelete -c' / 'sdelete -z': Sysinternals SDelete cleans or zeroes unallocated space.
  - CCleaner / Eraser: Offers 1-pass zeroing or multi-pass wiping of free space.

Physical signatures in unallocated space:
  1. Normal unallocated space: Highly heterogeneous. Contains fragmented file remnants,
     varying entropy (text ~4-5 bits/byte, binaries ~6-7 bits/byte), old MFT records,
     and periodic zero clusters.
  2. Zero-wiped unallocated space: Enormous contiguous runs of pure 0x00 (entropy = 0.0,
     byte uniformity = 100%).
  3. Pattern-wiped space: Contiguous runs of 0xFF or repeated bytes (cipher /w pass 2).
  4. Random-wiped space: Large contiguous blocks with near-maximal Shannon entropy
     (7.95 - 8.00 bits/byte) that lack any valid file headers (no ZIP, PE, JPEG signatures).

Honest limits
-------------
- Analysis requires access to the raw disk image (E01, RAW, DD, fixed VHD) or an
  exported unallocated space stream. If only exported files ($MFT, .evtx) are
  provided, free-space analysis cannot be performed.
- A freshly formatted drive or SSD with TRIM enabled may also show large stretches
  of zeros. Corroboration with tool traces (e.g., sdelete.exe or cipher.exe execution)
  is essential before asserting malicious intent.
"""
from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

import numpy as np

from afd.core.config import detector_settings, merge_config
from afd.core.finding import Confidence, Finding, assign_ids, confidence_from_score, sort_findings
from afd.parsers.image_reader import find_ntfs_volumes, open_image, pick_windows_volume

DEFAULT_CONFIG = {
    "medium_at": 4,
    "high_at": 6,
    "chunk_size_bytes": 1048576,      # 1 MB
    "max_chunks_to_sample": 500,      # up to 500 MB sampled
    "uniform_threshold_pct": 98.0,    # 98% of chunk is single byte
    "high_entropy_threshold": 7.96,   # near maximal entropy (random wipe)
    "min_consecutive_chunks": 3,
    "weights": {
        "massive_zero_fill": 5,
        "uniform_pattern_fill": 5,
        "massive_high_entropy": 4,
    },
}


def calculate_entropy_and_uniformity(data: bytes) -> tuple[float, float, int]:
    """Calculate Shannon entropy (bits/byte), dominant byte percentage, and dominant byte value."""
    if not data:
        return 0.0, 100.0, 0

    counts = Counter(data)
    total = len(data)

    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)

    dominant_byte, dom_count = counts.most_common(1)[0]
    uniformity_pct = (dom_count / total) * 100.0

    return entropy, uniformity_pct, dominant_byte


def analyze_unallocated_stream(
    reader_fn,
    total_size: int,
    cfg: dict,
) -> list[dict]:
    """Analyze a sequential raw data stream in chunks and detect wiped regions."""
    chunk_size = cfg.get("chunk_size_bytes", 1048576)
    max_chunks = cfg.get("max_chunks_to_sample", 500)
    uniform_pct = cfg.get("uniform_threshold_pct", 98.0)
    entropy_thresh = cfg.get("high_entropy_threshold", 7.96)

    chunks_to_check = min(max_chunks, max(1, total_size // chunk_size))
    step = max(1, (total_size // chunk_size) // chunks_to_check)

    results = []
    for i in range(chunks_to_check):
        offset = i * step * chunk_size
        if offset >= total_size:
            break
        chunk = reader_fn(offset, chunk_size)
        if not chunk:
            break
        entropy, uniformity, dom_byte = calculate_entropy_and_uniformity(chunk)
        results.append({
            "offset": offset,
            "size": len(chunk),
            "entropy": round(entropy, 4),
            "uniformity_pct": round(uniformity, 2),
            "dominant_byte": dom_byte,
        })
    return results


def detect_from_image(image_path: Path, cfg: dict | None = None) -> list[Finding]:
    """Inspect disk image unallocated/raw sectors for free-space wiping signatures."""
    cfg = merge_config(DEFAULT_CONFIG, detector_settings("freespace"), cfg or {})
    image_path = Path(image_path)
    if not image_path.is_file():
        return []

    try:
        img = open_image(image_path)
    except Exception:
        return []

    volumes = find_ntfs_volumes(img)
    vol = pick_windows_volume(img, volumes) if volumes else None

    # Determine scanning region (prefer Windows NTFS volume offset and size)
    if vol:
        vol_offset = vol["offset"]
        vol_size = vol["size"]
    else:
        vol_offset = 0
        vol_size = img.get_size()

    def read_func(rel_offset: int, size: int) -> bytes:
        try:
            return img.read(vol_offset + rel_offset, min(size, vol_size - rel_offset))
        except Exception:
            return b""

    sample_results = analyze_unallocated_stream(read_func, vol_size, cfg)
    return _evaluate_samples(sample_results, f"disk image {image_path.name}", cfg)


def detect_from_buffer(data: bytes, source_name: str = "unallocated space dump", cfg: dict | None = None) -> list[Finding]:
    """Inspect a raw memory/disk byte buffer (useful for testing or carved unallocated dumps)."""
    cfg = merge_config(DEFAULT_CONFIG, detector_settings("freespace"), cfg or {})
    chunk_size = cfg.get("chunk_size_bytes", 1048576)

    def read_func(offset: int, size: int) -> bytes:
        return data[offset:offset + size]

    sample_results = analyze_unallocated_stream(read_func, len(data), cfg)
    return _evaluate_samples(sample_results, source_name, cfg)


def _evaluate_samples(samples: list[dict], subject_name: str, cfg: dict) -> list[Finding]:
    """Evaluate chunk metrics and create Findings if wiped signatures are found."""
    if not samples:
        return []

    weights = cfg["weights"]
    uniform_pct_thresh = cfg.get("uniform_threshold_pct", 98.0)
    entropy_thresh = cfg.get("high_entropy_threshold", 7.96)
    min_consecutive = cfg.get("min_consecutive_chunks", 3)

    zero_chunks = [s for s in samples if s["uniformity_pct"] >= uniform_pct_thresh and s["dominant_byte"] == 0x00]
    ff_chunks = [s for s in samples if s["uniformity_pct"] >= uniform_pct_thresh and s["dominant_byte"] == 0xFF]
    other_pattern_chunks = [
        s for s in samples if s["uniformity_pct"] >= uniform_pct_thresh and s["dominant_byte"] not in (0x00, 0xFF)
    ]
    random_chunks = [s for s in samples if s["entropy"] >= entropy_thresh]

    total_sampled = len(samples)
    findings: list[Finding] = []

    # Check 1: Massive zero-fill (sdelete -c / -z, cipher /w pass 1)
    if len(zero_chunks) >= min_consecutive and (len(zero_chunks) / total_sampled) >= 0.4:
        score = weights["massive_zero_fill"]
        pct = (len(zero_chunks) / total_sampled) * 100
        findings.append(Finding(
            module="freespace",
            technique="Disk / Free-Space Wiping",
            mitre="T1070.004",
            title=f"Wiped free-space detected: Zero-fill pass ({pct:.1f}% of sampled regions)",
            confidence=confidence_from_score(score, cfg["medium_at"], cfg["high_at"]),
            score=score,
            subject=subject_name,
            artifact="Unallocated space clusters",
            reasons=[
                f"{len(zero_chunks)} of {total_sampled} sampled chunks ({pct:.1f}%) consist of "
                "pure 0x00 bytes (zero-fill), characteristic of 'sdelete -z' or 'cipher /w' pass 1.",
            ],
            benign_notes=[
                "Freshly formatted partitions, new VM disks, or SSDs with active TRIM "
                "can also contain large zero-filled regions.",
            ],
            evidence={
                "zero_chunks": len(zero_chunks),
                "total_sampled": total_sampled,
                "percentage": round(pct, 1),
            },
            event_time=None,
            time_meaning="Free space wipe leaves no individual event time",
        ))

    # Check 2: Uniform pattern pass (cipher /w pass 2: 0xFF)
    if len(ff_chunks) >= min_consecutive:
        score = weights["uniform_pattern_fill"]
        pct = (len(ff_chunks) / total_sampled) * 100
        findings.append(Finding(
            module="freespace",
            technique="Disk / Free-Space Wiping",
            mitre="T1070.004",
            title=f"Wiped free-space detected: 0xFF overwrite pattern ({len(ff_chunks)} chunks)",
            confidence=confidence_from_score(score, cfg["medium_at"], cfg["high_at"]),
            score=score,
            subject=subject_name,
            artifact="Unallocated space clusters",
            reasons=[
                f"Found {len(ff_chunks)} chunks filled with 0xFF. Normal disk usage never fills free "
                "space with uniform 0xFF; this matches 'cipher /w' pass 2.",
            ],
            benign_notes=["Virtually no benign operating system process writes 0xFF across free space."],
            evidence={"ff_chunks": len(ff_chunks), "total_sampled": total_sampled},
            event_time=None,
            time_meaning="Free space wipe leaves no individual event time",
        ))

    # Check 3: Massive high-entropy pseudorandom pass (cipher /w pass 3, Eraser)
    if len(random_chunks) >= min_consecutive and (len(random_chunks) / total_sampled) >= 0.3:
        score = weights["massive_high_entropy"]
        pct = (len(random_chunks) / total_sampled) * 100
        findings.append(Finding(
            module="freespace",
            technique="Disk / Free-Space Wiping",
            mitre="T1070.004",
            title=f"Wiped free-space detected: Pseudorandom pass ({pct:.1f}% high-entropy)",
            confidence=confidence_from_score(score, cfg["medium_at"], cfg["high_at"]),
            score=score,
            subject=subject_name,
            artifact="Unallocated space clusters",
            reasons=[
                f"{len(random_chunks)} of {total_sampled} chunks have Shannon entropy >= {entropy_thresh} "
                "with no valid file headers, characteristic of random free-space wiping passes.",
            ],
            benign_notes=[
                "Full-disk encryption (BitLocker) or large encrypted container files also exhibit "
                "high entropy, but encrypted volumes have distinctive header structures.",
            ],
            evidence={"random_chunks": len(random_chunks), "total_sampled": total_sampled, "percentage": round(pct, 1)},
            event_time=None,
            time_meaning="Free space wipe leaves no individual event time",
        ))

    return assign_ids(sort_findings(findings))
