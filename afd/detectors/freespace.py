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

Why zero-fill alone is LOW
--------------------------
Space that was never written reads as zeros, and so does space freed on an SSD with TRIM
or on a thin-provisioned VM disk. On the clean Windows 11 test VM, 94% of the sampled
unallocated regions were zero-filled. A zero fill therefore needs corroboration (a free-space
wiper run, linked by the Stage 5 correlation) to reach MEDIUM. A 0xFF fill or random
fill across free space has no such everyday cause and stays MEDIUM or above.

Honest limits
-------------
- Only *unallocated* clusters are sampled: the NTFS $Bitmap file has one bit per cluster
  (1 = in use), and only 1 MB chunks whose clusters are all free are read. Sampling the
  whole volume would mix in allocated compressed files (CAB, ZIP, WinSxS) and look random.
- Zero-filled free space is only LOW on its own: space that was never written (a new VM
  disk, a fresh install, SSD TRIM) also reads as zeros. 'cipher /w' ends with a random pass,
  so after a complete run free space is mostly random, not 0xFF.
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
    "min_consecutive_chunks": 3,      # minimum number of matching chunks before any finding
    "zero_min_fraction": 0.4,         # share of sampled free chunks that must be zero-filled
    "random_min_fraction": 0.6,       # share that must be random (deleted ZIP/CAB remnants are also random)
    "weights": {
        "massive_zero_fill": 2,       # LOW: never-written space is zeros too
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


def free_chunk_offsets(bitmap: bytes, cluster_size: int, chunk_size: int, max_chunks: int) -> tuple[list[int], int]:
    """From the NTFS $Bitmap (bit i = cluster i in use, least significant bit first), return
    byte offsets of up to max_chunks fully unallocated chunks, spread evenly across the volume,
    and the total number of fully unallocated chunks."""
    per_chunk = max(1, chunk_size // cluster_size)
    bits = np.unpackbits(np.frombuffer(bitmap, dtype=np.uint8), bitorder="little")
    n_chunks = len(bits) // per_chunk
    used = bits[: n_chunks * per_chunk].reshape(n_chunks, per_chunk).any(axis=1)
    free = np.flatnonzero(~used)
    if len(free) > max_chunks:
        free = free[np.linspace(0, len(free) - 1, max_chunks).astype(int)]
    return [int(c) * per_chunk * cluster_size for c in free], int((~used).sum())


def _read_bitmap(img, vol_offset: int) -> tuple[bytes, int] | None:
    """Return ($Bitmap contents, cluster size) of the NTFS volume, or None if unreadable."""
    try:
        import pytsk3
        fs = pytsk3.FS_Info(img, offset=vol_offset)
        f = fs.open("/$Bitmap")
        return f.read_random(0, f.info.meta.size), fs.info.block_size
    except Exception:
        return None


def detect_from_image(image_path: Path, cfg: dict | None = None) -> list[Finding]:
    """Sample the unallocated clusters of the Windows volume for free-space wiping signatures."""
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

    chunk = cfg.get("chunk_size_bytes", 1048576)
    bitmap = _read_bitmap(img, vol_offset) if vol else None
    if bitmap is None:
        # No allocation map: sample everything, but allocated data is mixed in, so cap at LOW
        sample_results = analyze_unallocated_stream(read_func, vol_size, cfg)
        return _evaluate_samples(sample_results, f"disk image {image_path.name}", cfg, scope="whole volume")

    offsets, free_total = free_chunk_offsets(bitmap[0], bitmap[1], chunk, cfg.get("max_chunks_to_sample", 500))
    sample_results = []
    for off in offsets:
        data = read_func(off, chunk)
        if not data:
            continue
        entropy, uniformity, dom_byte = calculate_entropy_and_uniformity(data)
        sample_results.append({"offset": off, "size": len(data), "entropy": round(entropy, 4),
                               "uniformity_pct": round(uniformity, 2), "dominant_byte": dom_byte})
    return _evaluate_samples(sample_results, f"disk image {image_path.name}", cfg,
                             scope="unallocated", free_chunks_total=free_total)


def detect_from_buffer(data: bytes, source_name: str = "unallocated space dump", cfg: dict | None = None) -> list[Finding]:
    """Inspect a raw memory/disk byte buffer (useful for testing or carved unallocated dumps)."""
    cfg = merge_config(DEFAULT_CONFIG, detector_settings("freespace"), cfg or {})
    chunk_size = cfg.get("chunk_size_bytes", 1048576)

    def read_func(offset: int, size: int) -> bytes:
        return data[offset:offset + size]

    sample_results = analyze_unallocated_stream(read_func, len(data), cfg)
    return _evaluate_samples(sample_results, source_name, cfg)


def _evaluate_samples(samples: list[dict], subject_name: str, cfg: dict,
                      scope: str = "unallocated", free_chunks_total: int | None = None) -> list[Finding]:
    """Evaluate chunk metrics and create Findings if wiped signatures are found.

    scope: "unallocated" (only free clusters were sampled) or "whole volume" (no $Bitmap:
    allocated files are mixed in, so every finding is capped at LOW)."""
    if not samples:
        return []
    zero_min = cfg.get("zero_min_fraction", 0.4)
    random_min = cfg.get("random_min_fraction", 0.6)

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
    if len(zero_chunks) >= min_consecutive and (len(zero_chunks) / total_sampled) >= zero_min:
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
                "pure 0x00 bytes (zero-fill), consistent with 'sdelete -z'.",
                "Zero-fill alone is weak: look for a wiping tool's execution trace (Module 6).",
            ],
            benign_notes=[
                "Space that was never written, freshly formatted partitions, thin-provisioned VM "
                "disks and SSDs with TRIM all read as zeros, so a zero fill alone is LOW. It is "
                "raised when a free-space wiping tool is also found to have run.",
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
                f"Found {len(ff_chunks)} chunks filled with 0xFF. Normal disk use does not fill free "
                "space with 0xFF; wipers use it as an overwrite pattern ('cipher /w' pass 2, left "
                "behind if the run was stopped before its random pass).",
            ],
            benign_notes=["Some raw flash media read as 0xFF when erased; check the media type."],
            evidence={"ff_chunks": len(ff_chunks), "total_sampled": total_sampled},
            event_time=None,
            time_meaning="Free space wipe leaves no individual event time",
        ))

    # Check 3: Massive high-entropy pseudorandom pass (cipher /w pass 3, Eraser)
    if len(random_chunks) >= min_consecutive and (len(random_chunks) / total_sampled) >= random_min:
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
                f"{len(random_chunks)} of {total_sampled} chunks ({pct:.1f}%) have Shannon entropy "
                f">= {entropy_thresh}, consistent with a random overwrite pass ('cipher /w' pass 3, "
                "Eraser, CCleaner 'Wipe Free Space').",
            ],
            benign_notes=[
                "Deleted compressed files (ZIP, CAB, Windows Update downloads) and encrypted containers "
                "also leave random-looking remnants; only a large share of free space is reported.",
            ],
            evidence={"random_chunks": len(random_chunks), "total_sampled": total_sampled, "percentage": round(pct, 1)},
            event_time=None,
            time_meaning="Free space wipe leaves no individual event time",
        ))

    for f in findings:
        f.evidence["scope"] = scope
        if free_chunks_total is not None:
            f.evidence["free_chunks_total"] = free_chunks_total
        if scope != "unallocated":
            f.score = min(f.score, cfg["medium_at"] - 1)
            f.confidence = confidence_from_score(f.score, cfg["medium_at"], cfg["high_at"])
            f.artifact = "Whole volume sample (allocation map not readable)"
            f.benign_notes.append("Allocated files were sampled too, because the NTFS $Bitmap could not "
                                  "be read; confidence is capped at LOW.")
    return assign_ids(sort_findings(findings))
