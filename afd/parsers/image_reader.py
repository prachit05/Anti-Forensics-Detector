"""Disk image reader (E01 or raw/dd) using The Sleuth Kit (pytsk3).

Forensic concept
----------------
* raw/dd is a byte-for-byte copy of the disk. E01 (Expert Witness) stores the same
  bytes compressed, in segments (.E01, .E02...), with case metadata and an embedded
  hash of the acquired data. pyewf (libewf) reads E01 and gives us the raw bytes.
* A disk holds a partition table (MBR or GPT). Each partition starts at a sector
  offset. The Sleuth Kit opens the NTFS file system at that offset and lets us read
  files by path, including system files such as $MFT that Windows normally locks.
* We never write to the image. Every extracted file is hashed and logged, so the
  report can show exactly which bytes were analysed.

Note on hashes: FTK Imager reports the hash of the *disk data*, not of the .E01
file. To compare with FTK's value, use media_hash(), which hashes the data stream.
"""
import hashlib
from pathlib import Path

import pytsk3

try:
    import pyewf
except ImportError:          # E01 support is optional
    pyewf = None

CHUNK = 4 * 1024 * 1024

# Artifacts to pull out of the Windows volume: (folder, filename pattern, output subfolder)
TARGETS = [
    ("/", "$MFT", "mft"),
    ("/Windows/System32/winevt/Logs", "*.evtx", "evtx"),
    ("/Windows/System32/config", "SOFTWARE", "registry"),
    ("/Windows/System32/config", "SYSTEM", "registry"),
    ("/Windows/Prefetch", "*.pf", "prefetch"),
]


class EWFImgInfo(pytsk3.Img_Info):
    """Adapter so pytsk3 can read an E01 through pyewf."""

    def __init__(self, ewf_handle):
        self._ewf = ewf_handle
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        self._ewf.close()

    def read(self, offset, size):
        self._ewf.seek(offset)
        return self._ewf.read(size)

    def get_size(self):
        return self._ewf.get_media_size()


def open_image(path: Path):
    """Open an E01 (all segments) or a raw image. Returns a pytsk3 image object."""
    path = Path(path)
    if path.suffix.lower() in (".e01", ".ex01"):
        if pyewf is None:
            raise RuntimeError("libewf-python is not installed; cannot open E01")
        handle = pyewf.handle()
        handle.open(pyewf.glob(str(path)))        # finds .E02, .E03 ... automatically
        return EWFImgInfo(handle)
    return pytsk3.Img_Info(str(path))


BITLOCKER_SIG = b"-FVE-FS-"   # OEM ID at byte 3 of a BitLocker volume's boot sector


def find_bitlocker_volumes(img) -> list[dict]:
    """List partitions encrypted with BitLocker.

    Windows 11 turns on device encryption automatically on TPM machines, so a
    modern image may have an encrypted C:. Its contents cannot be read without the
    recovery key, so the tool must report this rather than silently find nothing.
    """
    found = []
    try:
        vol = pytsk3.Volume_Info(img)
    except OSError:
        return found
    block = vol.info.block_size
    for part in vol:
        if part.len < 2048:
            continue
        offset = part.start * block
        if img.read(offset + 3, 8) == BITLOCKER_SIG:
            found.append({"offset": offset, "size": part.len * block,
                          "desc": part.desc.decode(errors="replace")})
    return found


def find_ntfs_volumes(img) -> list[dict]:
    """List NTFS partitions as {offset, size, desc}. Falls back to offset 0
    (a partition image with no partition table)."""
    volumes = []
    try:
        vol = pytsk3.Volume_Info(img)
        block = vol.info.block_size
        for part in vol:
            if part.len < 2048:                   # skip tiny gaps / metadata entries
                continue
            offset = part.start * block
            try:
                fs = pytsk3.FS_Info(img, offset=offset)
            except OSError:
                continue
            if fs.info.ftype in (pytsk3.TSK_FS_TYPE_NTFS, pytsk3.TSK_FS_TYPE_NTFS_DETECT):
                volumes.append({"offset": offset, "size": part.len * block,
                                "desc": part.desc.decode(errors="replace")})
    except OSError:
        pass
    if not volumes:
        try:
            fs = pytsk3.FS_Info(img, offset=0)
            if fs.info.ftype in (pytsk3.TSK_FS_TYPE_NTFS, pytsk3.TSK_FS_TYPE_NTFS_DETECT):
                volumes.append({"offset": 0, "size": img.get_size(), "desc": "NTFS (no table)"})
        except OSError:
            pass
    return volumes


def pick_windows_volume(img, volumes: list[dict]) -> dict | None:
    """The system volume is the NTFS partition that has a /Windows folder.
    Returns None if no partition has one (e.g. C: is BitLocker-encrypted)."""
    for v in volumes:
        fs = pytsk3.FS_Info(img, offset=v["offset"])
        try:
            fs.open_dir("/Windows")
            return v
        except OSError:
            continue
    return None


def _copy_file(fs_file, dest: Path) -> int:
    """Copy a file's default $DATA stream out of the image, in chunks."""
    size = fs_file.info.meta.size
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as out:
        offset = 0
        while offset < size:
            n = min(CHUNK, size - offset)
            out.write(fs_file.read_random(offset, n))
            offset += n
    return size


def _matches(name: str, pattern: str) -> bool:
    if pattern.startswith("*"):
        return name.lower().endswith(pattern[1:].lower())
    return name.lower() == pattern.lower()


def extract_artifacts(image_path: Path, out_dir: Path, case=None) -> list[Path]:
    """Copy $MFT, event logs, SOFTWARE/SYSTEM hives, user NTUSER.DAT files and
    prefetch files from the Windows volume into out_dir. Returns extracted paths."""
    img = open_image(image_path)
    volumes = find_ntfs_volumes(img)
    vol = pick_windows_volume(img, volumes)
    if vol is None:
        encrypted = find_bitlocker_volumes(img)
        if case:
            case.log("no_windows_volume", ntfs_volumes=volumes, bitlocker_volumes=encrypted)
        if encrypted:
            sizes = ", ".join(f"{v['size'] / 2**30:.1f} GB at offset {v['offset']}" for v in encrypted)
            raise RuntimeError(
                f"Windows volume is BitLocker-encrypted ({sizes}). Decrypt it with the "
                "recovery key (or capture the system live) before analysis.")
        raise RuntimeError("No NTFS volume with a Windows folder found in image")
    fs = pytsk3.FS_Info(img, offset=vol["offset"])
    if case:
        case.log("volume_selected", image=str(image_path), **vol)

    targets = list(TARGETS)
    # One NTUSER.DAT per user profile; keep them apart by user name
    try:
        for entry in fs.open_dir("/Users"):
            user = entry.info.name.name.decode(errors="replace")
            if user not in (".", "..") and entry.info.meta and \
               entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                targets.append((f"/Users/{user}", "NTUSER.DAT", f"registry/{user}"))
    except OSError:
        pass

    extracted = []
    for folder, pattern, sub in targets:
        try:
            directory = fs.open_dir(folder)
        except OSError:
            continue
        for entry in directory:
            name = entry.info.name.name.decode(errors="replace")
            meta = entry.info.meta
            if not meta or meta.type != pytsk3.TSK_FS_META_TYPE_REG or not _matches(name, pattern):
                continue
            dest = Path(out_dir) / sub / name
            try:
                _copy_file(entry, dest)
            except OSError as exc:
                if case:
                    case.log("extract_failed", path=f"{folder}/{name}", error=str(exc))
                continue
            extracted.append(dest)
            if case:
                case.add_evidence(dest, source=f"extracted:{folder}/{name}")
    return extracted


def media_hash(image_path: Path) -> dict:
    """Hash the disk data inside the image (comparable with FTK Imager's hash).
    Reads the whole disk, so it takes a few minutes for a 50 GB image."""
    img = open_image(image_path)
    md5, sha256 = hashlib.md5(), hashlib.sha256()
    size, offset = img.get_size(), 0
    while offset < size:
        data = img.read(offset, min(CHUNK, size - offset))
        md5.update(data)
        sha256.update(data)
        offset += len(data)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest(), "media_size": size}
