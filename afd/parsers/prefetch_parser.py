"""Windows prefetch (.pf) parser.

Forensic concept
----------------
To speed up program start, Windows records which files a program loads during its
first seconds and saves this in C:\\Windows\\Prefetch\\<EXE>-<HASH>.pf. Each file
stores the executable name, run count, the last 8 run times, the files it touched
and the volume it ran from. So it is strong evidence a program *ran*, and when,
even after the program itself was deleted.

Format on Windows 10 (version 30):
  * The whole file is compressed: an 8-byte "MAM\\x04" header (signature plus
    uncompressed size), then XPRESS-Huffman data. Windows' own ntdll.dll has the
    decompressor (RtlDecompressBufferEx), so we call it with ctypes.
  * The decompressed data starts with "SCCA" at offset 4 (version at offset 0).
  * Version 30 has two layouts. Read the metrics array offset at 0x54:
      0x130 -> variant 1: run count at 0xD0
      0x128 -> variant 2: run count at 0xC8
    The last run times (8 x FILETIME, newest first) are at 0x80 in both.

Limits: prefetch can be disabled (registry, or common on SSD-tuned systems) and the
files can be deleted. An absent .pf file is not proof that a program never ran.
"""
import ctypes
import struct
import sys
from pathlib import Path

import pandas as pd

from afd.parsers.filetime import filetime_to_datetime

COMPRESSION_FORMAT_XPRESS_HUFF = 4
HEADER_SIZE = 84


# ---------------------------------------------------------------- decompression

def _ntdll():
    if sys.platform != "win32":
        raise RuntimeError("Compressed (Win8+) prefetch needs Windows to decompress")
    nt = ctypes.windll.ntdll
    nt.RtlGetCompressionWorkSpaceSize.argtypes = [
        ctypes.c_ushort, ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong)]
    nt.RtlDecompressBufferEx.argtypes = [
        ctypes.c_ushort, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p,
        ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p]
    return nt


def decompress_mam(data: bytes) -> bytes:
    """Decompress a 'MAM' prefetch file using Windows' built-in XPRESS-Huffman."""
    if data[:3] != b"MAM":
        return data                          # Win7 and older: not compressed
    usize, = struct.unpack_from("<I", data, 4)
    payload = data[8:]

    nt = _ntdll()
    ws_size, frag_size = ctypes.c_ulong(), ctypes.c_ulong()
    status = nt.RtlGetCompressionWorkSpaceSize(
        COMPRESSION_FORMAT_XPRESS_HUFF, ctypes.byref(ws_size), ctypes.byref(frag_size))
    if status:
        raise RuntimeError(f"RtlGetCompressionWorkSpaceSize failed: 0x{status & 0xFFFFFFFF:08X}")

    workspace = ctypes.create_string_buffer(ws_size.value)
    out = ctypes.create_string_buffer(usize)
    src = ctypes.create_string_buffer(payload, len(payload))
    final = ctypes.c_ulong()
    status = nt.RtlDecompressBufferEx(
        COMPRESSION_FORMAT_XPRESS_HUFF, out, usize, src, len(payload),
        ctypes.byref(final), workspace)
    if status:
        raise RuntimeError(f"RtlDecompressBufferEx failed: 0x{status & 0xFFFFFFFF:08X}")
    return out.raw[:final.value]


# ---------------------------------------------------------------- SCCA parsing

def _utf16_z(buf: bytes) -> str:
    """Decode a UTF-16LE string that ends at the first NUL character."""
    text = buf.decode("utf-16-le", "replace")
    return text.split("\x00", 1)[0]


def parse_scca(data: bytes) -> dict:
    """Parse decompressed prefetch data (versions 26, 30 and 31)."""
    version, sig = struct.unpack_from("<I4s", data, 0)
    if sig != b"SCCA":
        raise ValueError("Not a prefetch file (no SCCA signature)")
    if version not in (26, 30, 31):
        raise ValueError(f"Unsupported prefetch version {version}")

    exe_name = _utf16_z(data[16:76])
    pf_hash, = struct.unpack_from("<I", data, 76)

    (metrics_off, _metrics_n, _trace_off, _trace_n, names_off, names_size,
     vol_off, vol_n, _vol_size) = struct.unpack_from("<9I", data, HEADER_SIZE)

    # Variant 2 of version 30 (and version 31) has an 8-byte shorter file-info block
    run_count_off = 0xC8 if metrics_off == 0x128 else 0xD0
    run_count, = struct.unpack_from("<I", data, run_count_off)

    run_times = [t for t in struct.unpack_from("<8Q", data, 0x80) if t]

    files = [f for f in data[names_off:names_off + names_size]
             .decode("utf-16-le", "replace").split("\x00") if f]

    volumes = []
    for i in range(vol_n):
        entry = vol_off + i * 96                        # version 30 entry is 96 bytes
        path_off, path_len, created, serial = struct.unpack_from("<IIQI", data, entry)
        start = vol_off + path_off
        volumes.append({
            "device_path": data[start:start + path_len * 2].decode("utf-16-le", "replace"),
            "created": created,
            "serial": f"{serial:08X}",
        })

    return {
        "version": version, "exe_name": exe_name, "hash": f"{pf_hash:08X}",
        "run_count": run_count, "run_times": run_times,
        "files": files, "volumes": volumes,
    }


def parse_prefetch(path: Path) -> dict:
    """Read, decompress and parse one .pf file."""
    raw = Path(path).read_bytes()
    info = parse_scca(decompress_mam(raw))
    info["pf_file"] = Path(path).name
    return info


def load_prefetch_dir(folder: Path) -> tuple[pd.DataFrame, list[dict]]:
    """Parse every .pf in a folder.

    Returns (DataFrame with one row per execution time, list of parse errors).
    One row per run time makes it easy to put every recorded run on the timeline.
    """
    rows, errors = [], []
    for pf in sorted(Path(folder).glob("*.pf")):
        try:
            info = parse_prefetch(pf)
        except Exception as exc:
            errors.append({"file": pf.name, "error": str(exc)})
            continue
        for i, t in enumerate(info["run_times"] or [0]):
            rows.append({
                "pf_file": info["pf_file"], "exe_name": info["exe_name"],
                "run_count": info["run_count"], "run_index": i,   # 0 = most recent run
                "run_time_raw": t, "run_time": filetime_to_datetime(t),
                "version": info["version"], "file_count": len(info["files"]),
                "files": info["files"],
            })
    return pd.DataFrame(rows), errors
