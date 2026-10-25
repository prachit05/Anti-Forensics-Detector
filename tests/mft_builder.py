"""Build a tiny synthetic $MFT for tests.

It writes real 1024-byte FILE records (header, fixups, $SI, $FN, $DATA) so the tests
run the real mft_parser on them, not a mock. Only used by tests.
"""
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

from afd.parsers.filetime import EPOCH_1601

RECORD = 1024
USN = b"\x01\x00"


def ft(dt: datetime, sub_ticks: int = 0) -> int:
    """datetime -> FILETIME ticks. sub_ticks adds 100-ns detail (0..9_999_999)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    whole = int((dt - EPOCH_1601).total_seconds())
    return whole * 10_000_000 + sub_ticks


def _attr(atype: int, content: bytes, name: str = "") -> bytes:
    """A resident attribute (named or unnamed)."""
    name_bytes = name.encode("utf-16-le") if name else b""
    name_len = len(name)
    name_off = 0x18 if name else 0
    body_off = (0x18 + len(name_bytes) + 7) // 8 * 8
    length = (body_off + len(content) + 7) // 8 * 8
    head = struct.pack("<IIBBHHH", atype, length, 0, name_len, name_off, 0, 0)
    head += struct.pack("<IHBB", len(content), body_off, 0, 0)
    if name:
        head += name_bytes
        head = head.ljust(body_off, b"\x00")
    return (head + content).ljust(length, b"\x00")


def _si(times: tuple, flags: int = 0) -> bytes:
    return struct.pack("<4Q", *times) + struct.pack("<I", flags) + b"\x00" * 12


def _fn(parent: int, parent_seq: int, times: tuple, name: str, namespace: int = 1) -> bytes:
    raw = name.encode("utf-16-le")
    head = struct.pack("<Q", parent | (parent_seq << 48)) + struct.pack("<4Q", *times)
    head += struct.pack("<QQII", 0, 0, 0, 0) + bytes([len(name), namespace])
    return head + raw


def build_record(entry: dict) -> bytes:
    """entry keys: name, parent, si=(c,m,mc,a), fn=(c,m,mc,a), in_use, is_dir, seq, parent_seq, data, ads=[(name, bytes)]."""
    seq = entry.get("seq", 1)
    flags = (1 if entry.get("in_use", True) else 0) | (2 if entry.get("is_dir") else 0)
    attrs = _attr(0x10, _si(entry["si"]))
    attrs += _attr(0x30, _fn(entry["parent"], entry.get("parent_seq", 1), entry["fn"], entry["name"]))
    if not entry.get("is_dir"):
        attrs += _attr(0x80, entry.get("data", b"hello"))
    for sname, sdata in entry.get("ads", []):
        attrs += _attr(0x80, sdata, name=sname)
    attrs += struct.pack("<I", 0xFFFFFFFF) + b"\x00" * 4

    rec = bytearray(RECORD)
    rec[0:4] = b"FILE"
    struct.pack_into("<HH", rec, 4, 0x30, 3)                 # fixup array: offset, count
    struct.pack_into("<HHHH", rec, 0x10, seq, 1, 0x38, flags)
    struct.pack_into("<II", rec, 0x18, 0x38 + len(attrs), RECORD)
    rec[0x38:0x38 + len(attrs)] = attrs
    # fixups: save the real last 2 bytes of each sector, then stamp the update sequence number
    rec[0x30:0x32] = USN
    rec[0x32:0x34] = rec[510:512]
    rec[0x34:0x36] = rec[1022:1024]
    rec[510:512] = USN
    rec[1022:1024] = USN
    return bytes(rec)


def write_mft(path: Path, entries: list[dict]) -> Path:
    """Write an $MFT with each dict at the slot number given by its 'entry' key."""
    top = max(e["entry"] for e in entries) + 1
    slots = [bytes(RECORD)] * top
    # a real $MFT always begins with its own record (entry 0), which is how it is recognised
    t = ft(when())
    slots[0] = build_record(dict(entry=0, name="$MFT", parent=5, si=(t, t, t, t), fn=(t, t, t, t)))
    for e in entries:
        slots[e["entry"]] = build_record(e)
    Path(path).write_bytes(b"".join(slots))
    return Path(path)


def when(**kw) -> datetime:
    """Convenience: 2026-10-24 10:00 UTC plus an offset, e.g. when(hours=2)."""
    return datetime(2026, 10, 24, 10, 0, 0, tzinfo=timezone.utc) + timedelta(**kw)
