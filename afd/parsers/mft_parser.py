"""$MFT parser.

Forensic concept
----------------
The Master File Table ($MFT) is NTFS's index of every file and folder. Each file has
at least one 1024-byte "FILE record" holding attributes:

  0x10 $STANDARD_INFORMATION ($SI)  4 timestamps (Created, Modified, MFT-changed,
                                    Accessed), plus DOS flags (hidden, system...).
                                    User-mode APIs (SetFileTime) can change these,
                                    which is what timestomping tools use.
  0x30 $FILE_NAME ($FN)             Name, parent folder and another 4 timestamps.
                                    Only the kernel updates these, so they are much
                                    harder to fake. $SI vs $FN comparison is the
                                    basis of timestomp detection (Stage 3).
  0x80 $DATA                        File content. An unnamed $DATA is the normal
                                    content; a *named* $DATA is an Alternate Data
                                    Stream (ADS), a classic hiding place (Stage 4).

Fixups: NTFS writes a 2-byte "update sequence number" into the last 2 bytes of each
512-byte sector of a record, and saves the real bytes in an array in the header.
A reader must swap them back. If a sector's last 2 bytes do not match, the record
was torn or tampered with.

A deleted file's record keeps its data until NTFS reuses it; the in-use flag is
simply cleared. So deleted entries are still visible here.
"""
import struct
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from afd.parsers.filetime import filetime_to_iso

RECORD_SIZE = 1024
SECTOR = 512
ROOT_ENTRY = 5          # MFT entry 5 is the root directory "."

ATTR_SI, ATTR_ATTRLIST, ATTR_FN, ATTR_DATA, ATTR_END = 0x10, 0x20, 0x30, 0x80, 0xFFFFFFFF

# $FN namespaces: Win32 is the long name; DOS is the 8.3 short name
NS_POSIX, NS_WIN32, NS_DOS, NS_WIN32_DOS = 0, 1, 2, 3
_NAME_PREFERENCE = {NS_WIN32: 0, NS_WIN32_DOS: 0, NS_POSIX: 1, NS_DOS: 2}

TIME_FIELDS = ("created", "modified", "mft_modified", "accessed")


@dataclass
class FileName:
    """One $FILE_NAME attribute (a file can have several: long name, 8.3 name, hard links)."""
    name: str
    namespace: int
    parent_entry: int
    parent_seq: int
    times: dict                 # raw FILETIME ticks: created, modified, mft_modified, accessed


@dataclass
class DataStream:
    """One $DATA attribute. name == '' is the main content; anything else is an ADS."""
    name: str
    resident: bool
    size: int
    head: bytes = b""           # first bytes of resident content (magic-number checks)
    runs: list = field(default_factory=list)   # [(start_cluster, length)] if non-resident


@dataclass
class MftEntry:
    entry: int
    seq: int
    in_use: bool
    is_dir: bool
    base_entry: int             # non-zero -> this is an extension record of base_entry
    lsn: int                    # $LogFile sequence number of the last change
    hard_links: int
    fixup_ok: bool
    si_times: dict = field(default_factory=dict)
    si_flags: int = 0
    file_names: list = field(default_factory=list)
    streams: list = field(default_factory=list)
    has_attr_list: bool = False

    @property
    def best_name(self) -> FileName | None:
        """Prefer the Win32 long name over the 8.3 DOS name."""
        if not self.file_names:
            return None
        return min(self.file_names, key=lambda f: _NAME_PREFERENCE.get(f.namespace, 3))


# ---------------------------------------------------------------- low-level helpers

def apply_fixups(record: bytearray) -> bool:
    """Restore the real last 2 bytes of each sector. Returns False if a sector is torn."""
    usa_offset, usa_count = struct.unpack_from("<HH", record, 4)
    if usa_offset + usa_count * 2 > len(record):
        return False
    usn = record[usa_offset:usa_offset + 2]
    ok = True
    for i in range(1, usa_count):
        end = i * SECTOR - 2
        if end + 2 > len(record):
            break
        if record[end:end + 2] != usn:
            ok = False
        record[end:end + 2] = record[usa_offset + i * 2:usa_offset + i * 2 + 2]
    return ok


def decode_data_runs(buf: bytes) -> list[tuple[int, int]]:
    """Decode NTFS data runs into (start_cluster, length_in_clusters).

    Each run starts with a header byte: low nibble = size of the length field,
    high nibble = size of the offset field. The offset is signed and relative to
    the previous run. Offset size 0 means a sparse run (no clusters on disk),
    stored here with start_cluster = -1.
    """
    runs, pos, prev = [], 0, 0
    while pos < len(buf) and buf[pos] != 0:
        header = buf[pos]
        len_size, off_size = header & 0x0F, header >> 4
        pos += 1
        length = int.from_bytes(buf[pos:pos + len_size], "little")
        pos += len_size
        if off_size == 0:
            runs.append((-1, length))
            continue
        delta = int.from_bytes(buf[pos:pos + off_size], "little", signed=True)
        pos += off_size
        prev += delta
        runs.append((prev, length))
    return runs


def _split_ref(ref: int) -> tuple[int, int]:
    """A file reference is 48 bits of entry number + 16 bits of sequence number."""
    return ref & 0xFFFFFFFFFFFF, ref >> 48


def _times(buf: bytes, offset: int) -> dict:
    return dict(zip(TIME_FIELDS, struct.unpack_from("<4Q", buf, offset)))


# ---------------------------------------------------------------- record parsing

def parse_record(raw: bytes, entry_number: int) -> MftEntry | None:
    """Parse one FILE record. Returns None for empty/unused slots ('BAAD' or zeros)."""
    if raw[:4] != b"FILE":
        return None
    rec = bytearray(raw)
    fixup_ok = apply_fixups(rec)

    lsn, = struct.unpack_from("<Q", rec, 0x08)
    seq, links, first_attr, flags = struct.unpack_from("<HHHH", rec, 0x10)
    base_ref, = struct.unpack_from("<Q", rec, 0x20)

    e = MftEntry(entry=entry_number, seq=seq, in_use=bool(flags & 0x01),
                 is_dir=bool(flags & 0x02), base_entry=_split_ref(base_ref)[0],
                 lsn=lsn, hard_links=links, fixup_ok=fixup_ok)

    pos = first_attr
    while pos + 16 <= len(rec):
        atype, alen = struct.unpack_from("<II", rec, pos)
        if atype == ATTR_END or alen == 0 or pos + alen > len(rec):
            break
        non_resident = rec[pos + 8]
        name_len, name_off = rec[pos + 9], struct.unpack_from("<H", rec, pos + 10)[0]
        attr_name = rec[pos + name_off:pos + name_off + name_len * 2].decode("utf-16-le", "replace")

        if not non_resident:
            clen, coff = struct.unpack_from("<IH", rec, pos + 0x10)
            content = bytes(rec[pos + coff:pos + coff + clen])
        else:
            content = b""

        if atype == ATTR_SI and len(content) >= 36:
            e.si_times = _times(content, 0)
            e.si_flags, = struct.unpack_from("<I", content, 32)

        elif atype == ATTR_FN and len(content) >= 66:
            parent_entry, parent_seq = _split_ref(struct.unpack_from("<Q", content, 0)[0])
            nlen, ns = content[64], content[65]
            name = content[66:66 + nlen * 2].decode("utf-16-le", "replace")
            e.file_names.append(FileName(name, ns, parent_entry, parent_seq, _times(content, 8)))

        elif atype == ATTR_DATA:
            if non_resident:
                runs_off, = struct.unpack_from("<H", rec, pos + 0x20)
                real_size, = struct.unpack_from("<Q", rec, pos + 0x30)
                runs = decode_data_runs(bytes(rec[pos + runs_off:pos + alen]))
                e.streams.append(DataStream(attr_name, False, real_size, runs=runs))
            else:
                e.streams.append(DataStream(attr_name, True, len(content), head=content[:64]))

        elif atype == ATTR_ATTRLIST:
            # Attributes live in extension records; we merge those in parse_mft()
            e.has_attr_list = True

        pos += alen
    return e


# ---------------------------------------------------------------- whole-file parsing

def iter_records(mft_path: Path):
    """Yield (entry_number, raw_bytes) for every record slot in an exported $MFT."""
    with open(mft_path, "rb") as fh:
        first = fh.read(RECORD_SIZE)
        # Record size is stored at offset 0x1C of every record (normally 1024)
        size = struct.unpack_from("<I", first, 0x1C)[0] if first[:4] == b"FILE" else RECORD_SIZE
        if size not in (1024, 4096):
            size = RECORD_SIZE
        fh.seek(0)
        n = 0
        while chunk := fh.read(size):
            if len(chunk) < size:
                break
            yield n, chunk
            n += 1


def parse_mft(mft_path: Path) -> dict[int, MftEntry]:
    """Parse every record and merge extension records into their base record."""
    entries: dict[int, MftEntry] = {}
    extensions: list[MftEntry] = []
    for n, raw in iter_records(Path(mft_path)):
        e = parse_record(raw, n)
        if e is None:
            continue
        if e.base_entry:
            extensions.append(e)
        else:
            entries[n] = e
    for ext in extensions:
        base = entries.get(ext.base_entry)
        if base:
            base.file_names.extend(ext.file_names)
            base.streams.extend(ext.streams)
    return entries


def build_paths(entries: dict[int, MftEntry]) -> dict[int, str]:
    """Rebuild full paths by walking parent references up to the root (entry 5).

    If a parent entry was reused (its sequence number no longer matches) or is
    missing, the file is an orphan and goes under '$OrphanFiles', like Autopsy does.
    """
    cache: dict[int, str] = {ROOT_ENTRY: ""}

    def resolve(n: int, depth: int = 0) -> str:
        if n in cache:
            return cache[n]
        e = entries.get(n)
        fn = e.best_name if e else None
        if fn is None or depth > 64:          # depth guard stops loops in corrupt MFTs
            return "$OrphanFiles"
        parent = entries.get(fn.parent_entry)
        if fn.parent_entry != ROOT_ENTRY and (parent is None or parent.seq != fn.parent_seq):
            path = f"$OrphanFiles\\{fn.name}"
        else:
            path = f"{resolve(fn.parent_entry, depth + 1)}\\{fn.name}"
        cache[n] = path
        return path

    return {n: resolve(n) for n in entries}


def mft_to_dataframe(entries: dict[int, MftEntry]) -> pd.DataFrame:
    """One row per MFT entry. Timestamps stay as raw ticks (si_*, fn_*) for analysis.

    The fn_* columns come from the preferred $FN (long name). Use the entry objects
    directly if you need every $FN attribute.
    """
    paths = build_paths(entries)
    rows = []
    for n, e in entries.items():
        fn = e.best_name
        main = next((s for s in e.streams if s.name == ""), None)
        ads = [s for s in e.streams if s.name]
        row = {
            "entry": n, "seq": e.seq, "in_use": e.in_use, "is_dir": e.is_dir,
            "path": paths.get(n, ""), "name": fn.name if fn else "",
            "parent_entry": fn.parent_entry if fn else None,
            "fn_count": len(e.file_names),
            "si_flags": e.si_flags, "lsn": e.lsn, "fixup_ok": e.fixup_ok,
            "size": main.size if main else 0,
            "resident": main.resident if main else None,
            "head": main.head if main else b"",
            "runs": main.runs if main else [],
            "ads_names": [s.name for s in ads],
            "ads_sizes": [s.size for s in ads],
        }
        for t in TIME_FIELDS:
            row[f"si_{t}"] = e.si_times.get(t, 0)
            row[f"fn_{t}"] = fn.times.get(t, 0) if fn else 0
        rows.append(row)
    return pd.DataFrame(rows)


def load_mft(mft_path: Path) -> pd.DataFrame:
    """Convenience: parse an exported $MFT file straight to a DataFrame."""
    return mft_to_dataframe(parse_mft(mft_path))


def describe_times(row: pd.Series) -> dict:
    """Human-readable $SI and $FN timestamps for one row (used in evidence text)."""
    return {f"{p}_{t}": filetime_to_iso(int(row[f"{p}_{t}"]))
            for p in ("si", "fn") for t in TIME_FIELDS}
