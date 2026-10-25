"""Run the Stage 3 detectors (timestomping, log wiping) on an image or artifact folder.

Usage:
    python run_detectors.py <image.vhd|.dd|.E01 | artifact folder> [case_name] [options]

Options:
    --all-logs               parse every .evtx found (default: Security, System, Application)
    --reference-time ISO     when the image was acquired, e.g. 2026-10-25T09:30:00Z
                             (used for the "date in the future" check)
    --min-confidence LEVEL   LOW, MEDIUM (default) or HIGH: hide weaker findings on screen
    --limit N                show at most N findings on screen (default 50; 0 = all)

findings.json always holds every finding, whatever is shown on screen.

Example:
    python run_detectors.py C:\\forensics\\cases\\stage2_test_clean_v2\\extracted clean_check

Output: a summary on screen, <cases_dir>\\<case_name>\\findings.json, and chain-of-custody
entries for every step. Findings mean "likely", never proof.
"""
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from afd.core.case import Case
from afd.core.finding import Confidence, assign_ids, sort_findings
from afd.detectors import log_wiping, timestomp
from afd.parsers import collector, evtx_parser, mft_parser

MAIN_LOGS = ("security.evtx", "system.evtx", "application.evtx")


def parse_args(argv: list[str]) -> dict:
    opts = {"source": None, "case": None, "all_logs": False, "reference": None,
            "min_conf": Confidence.MEDIUM, "limit": 50}
    positional, i = [], 1
    while i < len(argv):
        arg = argv[i]
        if arg == "--all-logs":
            opts["all_logs"] = True
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

    print("\nTimestomping:")
    if arts.mft:
        mft = mft_parser.load_mft(arts.mft[0])
        found = timestomp.detect(mft, reference_time=opts["reference"])
        case.log("detector_run", detector="timestomp", mft_entries=len(mft), findings=len(found))
        print(f"  analysed {len(mft):,} MFT entries -> {len(found)} finding(s)")
        findings += found
    else:
        print("  no $MFT found, skipped")

    print("\nLog wiping:")
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

    findings = assign_ids(sort_findings(findings))
    counts = {c.name: sum(f.confidence == c for f in findings) for c in reversed(Confidence)}
    print(f"\nFindings: {len(findings)} total ("
          + ", ".join(f"{n} {name}" for name, n in counts.items()) + ")")
    eligible = [f for f in findings if f.confidence >= opts["min_conf"]]
    shown = eligible[:opts["limit"]] if opts["limit"] else eligible
    print(f"Showing {len(shown)} of {len(eligible)} at {opts['min_conf'].name} or above "
          f"(--min-confidence / --limit change this):")
    print_findings(shown)

    out = case.dir / "findings.json"
    out.write_text(json.dumps([f.to_dict() for f in findings], indent=2), encoding="utf-8")
    case.log("findings_written", file=str(out), count=len(findings))
    print(f"\nFindings file: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
