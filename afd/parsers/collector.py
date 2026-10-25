"""Find and sort input artifacts, from either a folder of exported files or a disk image.

Files are identified by their first bytes (magic numbers), not by name, because
FTK Imager exports keep original names but users often rename copies:

  "FILE"         at 0  -> $MFT record
  "ElfFile\\0"    at 0  -> .evtx event log
  "regf"         at 0  -> registry hive
  "MAM"          at 0  -> compressed prefetch (Win8+)
  "SCCA"         at 4  -> uncompressed prefetch (Win7 and older)
"""
from dataclasses import dataclass, field
from pathlib import Path

from afd.parsers.image_reader import extract_artifacts

# .vhd only works when it is a *fixed* VHD (raw disk + 512-byte footer), e.g. made
# with Convert-VHD -VHDType Fixed. Dynamic VHD/VHDX must be converted first.
IMAGE_EXTENSIONS = {".e01", ".ex01", ".dd", ".raw", ".img", ".001", ".vhd"}


@dataclass
class ArtifactSet:
    mft: list[Path] = field(default_factory=list)
    evtx: list[Path] = field(default_factory=list)
    registry: list[Path] = field(default_factory=list)
    prefetch: list[Path] = field(default_factory=list)
    unknown: list[Path] = field(default_factory=list)

    def summary(self) -> dict:
        return {k: len(v) for k, v in self.__dict__.items()}


def identify(path: Path) -> str:
    """Return the artifact type of a file from its header bytes."""
    with open(path, "rb") as fh:
        head = fh.read(8)
    if head[:4] == b"FILE":
        return "mft"
    if head == b"ElfFile\x00":
        return "evtx"
    if head[:4] == b"regf":
        return "registry"
    if head[:3] == b"MAM" or head[4:8] == b"SCCA":
        return "prefetch"
    return "unknown"


def collect_folder(folder: Path, case=None) -> ArtifactSet:
    """Walk a folder of exported artifacts, hash each one and sort it by type."""
    found = ArtifactSet()
    for path in sorted(Path(folder).rglob("*")):
        # Skip registry transaction logs (.LOG1/.LOG2): same magic, not a full hive
        if not path.is_file() or path.suffix.lower() in (".log1", ".log2"):
            continue
        kind = identify(path)
        getattr(found, kind).append(path)
        if case and kind != "unknown":
            case.add_evidence(path, source=f"artifact:{kind}")
    if case:
        case.log("artifacts_collected", folder=str(folder), **found.summary())
    return found


def collect(source: Path, case) -> ArtifactSet:
    """Accept either a disk image file or a folder of exported artifacts."""
    source = Path(source)
    if source.is_file() and source.suffix.lower() in IMAGE_EXTENSIONS:
        case.add_evidence(source, source="disk_image")
        extract_artifacts(source, case.extracted_dir, case)
        return collect_folder(case.extracted_dir)      # already hashed during extraction
    return collect_folder(source, case)
