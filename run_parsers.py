"""Run the evidence-handling and parser pipeline on an image or artifact folder.

Usage:
    python run_parsers.py <image.vhd|.dd|.E01 | artifact folder> [case_name]

Example:
    python run_parsers.py C:\\forensics\\evidence\\images\\clean_baseline.vhd demo_case

Steps: open a case -> hash the evidence -> extract artifacts (if an image) ->
parse $MFT, the main event logs and prefetch -> print a summary. Every action
is recorded in <cases_dir>\\<case_name>\\custody_log.jsonl.
"""
import sys
import time
from pathlib import Path

from afd.core.case import Case
from afd.parsers import collector, evtx_parser, image_reader, mft_parser, prefetch_parser
from afd.parsers.filetime import filetime_to_iso

MAIN_LOGS = ("Security.evtx", "System.evtx", "Application.evtx")


def timed(label, fn, *args):
    start = time.time()
    result = fn(*args)
    print(f"  [{time.time() - start:6.1f}s] {label}")
    return result


def show_volumes(source: Path) -> None:
    img = image_reader.open_image(source)
    for v in image_reader.find_ntfs_volumes(img):
        print(f"  NTFS volume: {v['size'] / 2**30:.1f} GB at offset {v['offset']}")
    for v in image_reader.find_bitlocker_volumes(img):
        print(f"  BitLocker volume: {v['size'] / 2**30:.1f} GB at offset {v['offset']}")


def show_mft(path: Path) -> None:
    df = timed("parse $MFT", mft_parser.load_mft, path)
    print(f"  entries {len(df):,} | in use {int(df.in_use.sum()):,} | "
          f"deleted {int((~df.in_use).sum()):,} | fixup errors {int((~df.fixup_ok).sum())} | "
          f"files with ADS {int(df.ads_names.str.len().gt(0).sum())}")
    sample = df[df.in_use & ~df.is_dir & df.path.str.startswith("\\Users\\")].head(5)
    for _, r in sample.iterrows():
        print(f"    {r.path}  (SI created {filetime_to_iso(r.si_created)}, "
              f"FN created {filetime_to_iso(r.fn_created)})")


def show_evtx(paths: list[Path]) -> None:
    for name in MAIN_LOGS:
        path = next((p for p in paths if p.name.lower() == name.lower()), None)
        if path is None:
            print(f"  {name}: not found")
            continue
        df, info = timed(f"parse {name}", evtx_parser.load_evtx, path)
        print(f"  records {info['records']:,} | parse errors {info['parse_errors']} | "
              f"header next record {info.get('next_record_number')} | dirty {info.get('is_dirty')}")
        if len(df):
            print(f"    record IDs {df.record_id.min()}..{df.record_id.max()} | "
                  f"time {df.time_created.min()} .. {df.time_created.max()}")


def show_prefetch(paths: list[Path]) -> None:
    if not paths:
        print("  no prefetch files found")
        return
    df, errors = timed("parse prefetch", prefetch_parser.load_prefetch_dir, paths[0].parent)
    print(f"  files {df.pf_file.nunique()} | errors {len(errors)} | "
          f"versions {df.version.value_counts().to_dict()}")
    latest = df[df.run_index == 0].sort_values("run_time", ascending=False).head(8)
    for _, r in latest.iterrows():
        print(f"    {r.exe_name:28} runs {r.run_count:3}  last {r.run_time}")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    source = Path(sys.argv[1])
    case = Case(sys.argv[2] if len(sys.argv) > 2 else f"case_{time.strftime('%Y%m%d_%H%M%S')}")
    print(f"Case folder: {case.dir}\n")

    if source.is_file():
        print("Volumes:")
        show_volumes(source)
    print("\nCollecting evidence (hashing may take a few minutes for a full image):")
    arts = timed("hash + extract + collect", collector.collect, source, case)
    print(f"  artifacts: {arts.summary()}")
    first = case.evidence[0]
    print(f"  evidence: {first['path']}\n    MD5    {first['md5']}\n    SHA256 {first['sha256']}")

    if arts.mft:
        print("\n$MFT:")
        show_mft(arts.mft[0])
    print("\nEvent logs:")
    show_evtx(arts.evtx)
    print("\nPrefetch:")
    show_prefetch(arts.prefetch)

    lines = sum(1 for _ in open(case.log_file, encoding="utf-8"))
    print(f"\nChain-of-custody log: {case.log_file} ({lines} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
