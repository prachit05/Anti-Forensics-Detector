"""Run all Anti-Forensics detectors and Stage 5 timeline/correlation on an image or artifact folder.

Detectors:
    1. Timestomping ($SI vs $FN timestamps, nanosecond zeroing, impossible dates)
    2. Log wiping (Event IDs 1102/104, record-ID gaps, unexplained silence)
    3. File wiping & secure deletion (MFT mangled names, resident wipe patterns)
    4. Free-space wiping (Zero-fill, 0xFF pattern, high-entropy unallocated clusters)
    5. Hidden & disguised files (Alternate Data Streams [ADS], type masquerading)
    6. Tool traces (CCleaner, SDelete, Eraser, timestomp in prefetch, registry, MFT)

Stage 5 Analysis:
    - Multi-artifact correlation (boosts confidence when tools & actions coincide)
    - Coordinated campaign detection (identifies multi-vector cover-up operations)
    - Unified timeline construction & episode grouping
    - Optional machine learning anomaly detection (Isolation Forest)

Usage:
    python run_detectors.py <image.vhd|.dd|.E01 | artifact folder> [case_name] [options]

Options:
    --all-logs               parse every .evtx found (default: Security, System, Application)
    --reference-time ISO     when the image was acquired, e.g. 2026-10-25T09:30:00Z
                             (used for the "date in the future" check)
    --min-confidence LEVEL   LOW, MEDIUM (default) or HIGH: hide weaker findings on screen
    --limit N                show at most N findings on screen (default 50; 0 = all)
    --ml                     run unsupervised ML anomaly detector (Isolation Forest)
    --timeline               print chronological timeline narrative on screen

Example:
    python run_detectors.py C:\\forensics\\cases\\stage2_test_clean_v2\\extracted clean_check --timeline
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from afd.analysis import (
    build_timeline,
    correlate_findings,
    detect_log_anomalies,
    detect_mft_anomalies,
)
from afd.core.case import Case
from afd.core.finding import Confidence, assign_ids, sort_findings
from afd.detectors import (
    file_wiping,
    freespace,
    hidden_files,
    log_wiping,
    timestomp,
    tool_traces,
)
from afd.parsers import (
    collector,
    evtx_parser,
    image_reader,
    mft_parser,
    prefetch_parser,
    registry_parser,
)

MAIN_LOGS = ("security.evtx", "system.evtx", "application.evtx")


def parse_args(argv: list[str]) -> dict:
    opts = {
        "source": None,
        "case": None,
        "all_logs": False,
        "reference": None,
        "min_conf": Confidence.MEDIUM,
        "limit": 50,
        "ml": False,
        "show_timeline": False,
    }
    positional, i = [], 1
    while i < len(argv):
        arg = argv[i]
        if arg == "--all-logs":
            opts["all_logs"] = True
        elif arg == "--ml":
            opts["ml"] = True
        elif arg == "--timeline":
            opts["show_timeline"] = True
        elif arg == "--reference-time":
            i += 1
            opts["reference"] = datetime.fromisoformat(argv[i].replace("Z", "+00:00")).astimezone(timezone.utc)
        elif arg == "--min-confidence":
            i += 1
            opts["min_conf"] = Confidence[argv[i].upper()]
        elif arg == "--limit":
            i += 1
            opts["limit"] = int(argv[i])
        else:
            positional.append(arg)
        i += 1
    if positional:
        opts["source"] = Path(positional[0])
        opts["case"] = positional[1] if len(positional) > 1 else None
    return opts


def load_logs(evtx_paths: list[Path], all_logs: bool, case: Case):
    logs = []
    for path in evtx_paths:
        if not all_logs and path.name.lower() not in MAIN_LOGS:
            continue
        start = time.time()
        df, info = evtx_parser.load_evtx(path)
        case.log("evtx_parsed", file=path.name, records=info["records"], parse_errors=info["parse_errors"])
        print(f"  parsed {path.name}: {info['records']:,} records ({time.time() - start:.1f}s)")
        logs.append((df, info))
    return logs


def print_findings(findings) -> None:
    if not findings:
        print("  no findings")
        return
    for f in findings:
        when = f.event_time.strftime("%Y-%m-%d %H:%M:%S") if f.event_time else "no time"
        print(f"\n  [{f.confidence.name:6}] {f.id}  {f.title}")
        print(f"           {f.artifact} | {when} UTC ({f.time_meaning})")
        for reason in f.reasons:
            print(f"           - {reason}")
        for note in f.benign_notes:
            print(f"           ? {note}")


def main() -> int:
    opts = parse_args(sys.argv)
    if opts["source"] is None:
        print(__doc__)
        return 1
    case = Case(opts["case"] or f"case_{time.strftime('%Y%m%d_%H%M%S')}")
    print(f"Case folder: {case.dir}\n")

    print("Collecting evidence:")
    arts = collector.collect(opts["source"], case)
    print(f"  artifacts: {arts.summary()}")

    findings = []
    mft_df = None

    # Load MFT once if available
    if arts.mft:
        print("\nParsing $MFT:")
        start_mft = time.time()
        mft_df = mft_parser.load_mft(arts.mft[0])
        print(f"  loaded {len(mft_df):,} entries ({time.time() - start_mft:.1f}s)")

    # 1. Timestomping
    print("\n[Module 1/6] Timestomping:")
    if mft_df is not None:
        found = timestomp.detect(mft_df, reference_time=opts["reference"])
        case.log("detector_run", detector="timestomp", mft_entries=len(mft_df), findings=len(found))
        print(f"  analysed {len(mft_df):,} entries -> {len(found)} finding(s)")
        findings += found
    else:
        print("  no $MFT found, skipped")

    # 2. Log wiping
    print("\n[Module 2/6] Log wiping:")
    logs = load_logs(arts.evtx, opts["all_logs"], case)
    if logs:
        if not any(info.get("file", "").lower() == "system.evtx" for _, info in logs):
            print("  note: System.evtx not supplied; restarts and clock changes cannot be ruled out")
        found = log_wiping.detect(logs)
        case.log("detector_run", detector="log_wiping", logs=len(logs), findings=len(found))
        print(f"  analysed {len(logs)} log(s) -> {len(found)} finding(s)")
        findings += found
    else:
        print("  no event logs found, skipped")

    # 3. Secure delete and file wiping
    print("\n[Module 3/6] File wiping & secure deletion:")
    if mft_df is not None:
        found = file_wiping.detect(mft_df)
        case.log("detector_run", detector="file_wiping", findings=len(found))
        print(f"  analysed deleted MFT entries -> {len(found)} finding(s)")
        findings += found
    else:
        print("  no $MFT found, skipped")

    # 4. Free space wiping
    print("\n[Module 4/6] Disk / Free-space wiping:")
    source_path = Path(opts["source"])
    if source_path.is_file() and source_path.suffix.lower() in collector.IMAGE_EXTENSIONS:
        found = freespace.detect_from_image(source_path)
        case.log("detector_run", detector="freespace", image=str(source_path), findings=len(found))
        print(f"  analysed disk image unallocated regions -> {len(found)} finding(s)")
        findings += found
    else:
        print("  source is not a disk image; unallocated space analysis skipped (requires image file)")

    # 5. Hidden and disguised files (ADS and header mismatches)
    print("\n[Module 5/6] Hidden and disguised files:")
    if mft_df is not None:
        found = hidden_files.detect(mft_df)
        case.log("detector_run", detector="hidden_files", findings=len(found))
        print(f"  analysed ADS and file headers -> {len(found)} finding(s)")
        findings += found
    else:
        print("  no $MFT found, skipped")

    # 6. Anti-forensic tool traces
    print("\n[Module 6/6] Anti-forensic tool traces:")
    prefetch_df = None
    if arts.prefetch:
        prefetch_folder = arts.prefetch[0].parent
        prefetch_df, pf_errors = prefetch_parser.load_prefetch_dir(prefetch_folder)
        print(f"  loaded {len(prefetch_df)} prefetch execution records")

    reg_data = None
    if arts.registry:
        reg_data = registry_parser.load_registry_artifacts(arts.registry)
        print(
            f"  loaded registry artifacts: {len(reg_data['userassist'])} UserAssist, "
            f"{len(reg_data['installed_programs'])} installed programs, {len(reg_data['run_mru'])} RunMRU"
        )

    found = tool_traces.detect(prefetch_df=prefetch_df, registry_data=reg_data, mft=mft_df)
    case.log("detector_run", detector="tool_traces", findings=len(found))
    print(f"  scanned prefetch, registry and MFT -> {len(found)} finding(s)")
    findings += found

    # Optional: Machine Learning Anomaly Detection
    if opts["ml"]:
        print("\n[Optional ML] Isolation Forest Anomaly Detection:")
        ml_findings = []
        if logs:
            log_anoms = detect_log_anomalies(logs)
            print(f"  scanned event logs via Isolation Forest -> {len(log_anoms)} anomaly finding(s)")
            ml_findings.extend(log_anoms)
        if mft_df is not None:
            mft_anoms = detect_mft_anomalies(mft_df)
            print(f"  scanned MFT timestamps via Isolation Forest -> {len(mft_anoms)} anomaly finding(s)")
            ml_findings.extend(mft_anoms)
        case.log("detector_run", detector="ml_anomaly", findings=len(ml_findings))
        findings += ml_findings

    # Stage 5: Multi-Artifact Correlation and Campaign Detection
    print("\n[Stage 5 Analysis] Multi-artifact correlation & campaign analysis:")
    updated_findings, campaigns = correlate_findings(findings)
    findings = updated_findings + campaigns
    if campaigns:
        print(f"  * ALERT: Identified {len(campaigns)} coordinated anti-forensics campaign(s)!")
        for camp in campaigns:
            print(f"    - [{camp.confidence.name}] {camp.title}")
    else:
        print("  no multi-vector campaign threshold reached; individual findings correlated")

    # Stage 5: Unified Timeline Construction
    timeline = build_timeline(findings)
    print(f"\n[Stage 5 Timeline] Constructed unified chronological timeline:")
    print(f"  dated events: {len(timeline.entries)} | episodes: {len(timeline.episodes)} | undated: {len(timeline.undated_findings)}")

    if opts["show_timeline"]:
        print("\n=== TIMELINE NARRATIVE ===")
        for line in timeline.narrative_summary():
            print(line)
        print("==========================\n")

    # Display Findings Summary
    findings = assign_ids(sort_findings(findings))
    counts = {c.name: sum(f.confidence == c for f in findings) for c in reversed(Confidence)}
    print(f"\nFindings: {len(findings)} total ("
          + ", ".join(f"{n} {name}" for name, n in counts.items()) + ")")
    eligible = [f for f in findings if f.confidence >= opts["min_conf"]]
    shown = eligible[:opts["limit"]] if opts["limit"] else eligible
    print(f"Showing {len(shown)} of {len(eligible)} at {opts['min_conf'].name} or above "
          f"(--min-confidence / --limit change this):")
    print_findings(shown)

    # Save findings.json
    out_findings = case.dir / "findings.json"
    out_findings.write_text(json.dumps([f.to_dict() for f in findings], indent=2), encoding="utf-8")
    case.log("findings_written", file=str(out_findings), count=len(findings))
    print(f"\nFindings file: {out_findings}")

    # Save timeline.json
    out_timeline = case.dir / "timeline.json"
    out_timeline.write_text(json.dumps(timeline.to_dict(), indent=2), encoding="utf-8")
    case.log("timeline_written", file=str(out_timeline), entries=len(timeline.entries))
    print(f"Timeline file: {out_timeline}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
