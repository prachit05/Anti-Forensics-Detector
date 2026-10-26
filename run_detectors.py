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

The work itself is done by afd.pipeline.run_analysis (shared with the dashboard).

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
    --report                 also write report.html and report.pdf to the case folder

Example:
    python run_detectors.py C:\\forensics\\cases\\stage2_test_clean_v2\\extracted clean_check --timeline
"""
from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from afd.analysis import build_timeline
from afd.core.case import Case
from afd.core.finding import Confidence
from afd.pipeline import AnalysisOptions, run_analysis


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
        "report": False,
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
        elif arg == "--report":
            opts["report"] = True
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

    start = time.time()
    result = run_analysis(
        opts["source"], case,
        AnalysisOptions(all_logs=opts["all_logs"], reference_time=opts["reference"], ml=opts["ml"]),
        progress=lambda msg, frac: print(f"[{frac * 100:3.0f}%] {msg}"),
    )
    print(f"\nArtifacts: {result.artifacts}  ({time.time() - start:.1f}s)")

    print("\nModules:")
    for m in result.modules:
        line = f"  {m['label']:34} {m['status']:8}"
        line += f"{m['findings']} finding(s)" if m["status"] == "ran" else ""
        print(line + (f"  ({m['note']})" if m["note"] else ""))

    campaigns = [f for f in result.findings if f.module == "analysis"]
    for camp in campaigns:
        print(f"\n  * ALERT [{camp.confidence.name}] {camp.title}")

    # Rebuilt at the chosen level so episodes contain only what is shown (not LOW setup noise)
    tl = build_timeline([f for f in result.findings if f.confidence >= opts["min_conf"]])
    print(f"\nTimeline ({opts['min_conf'].name} and above): {len(tl.entries)} dated event(s), "
          f"{len(tl.episodes)} episode(s), {len(tl.undated_findings)} undated")
    if opts["show_timeline"]:
        print("\n=== TIMELINE NARRATIVE ===")
        for line in tl.narrative_summary():
            print(line)
        print("==========================")

    findings = result.findings
    counts = {c.name: sum(f.confidence == c for f in findings) for c in reversed(Confidence)}
    print(f"\nFindings: {len(findings)} total ("
          + ", ".join(f"{n} {name}" for name, n in counts.items()) + ")")
    eligible = [f for f in findings if f.confidence >= opts["min_conf"]]
    shown = eligible[:opts["limit"]] if opts["limit"] else eligible
    print(f"Showing {len(shown)} of {len(eligible)} at {opts['min_conf'].name} or above "
          f"(--min-confidence / --limit change this):")
    print_findings(shown)

    print(f"\nFindings file: {case.dir / 'findings.json'}")
    print(f"Timeline file: {case.dir / 'timeline.json'}")

    if opts["report"]:
        from afd.reporting import write_reports
        for path in write_reports(result, case).values():
            print(f"Report: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
