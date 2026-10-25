"""Check that every library the tool needs is installed and importable.

Run:  python check_env.py
"""
import importlib
import struct
import sys

# (import name, pip package, required?)
MODULES = [
    ("pytsk3", "pytsk3", True),
    ("pyewf", "libewf-python", False),   # only needed for E01 images
    ("Evtx", "python-evtx", True),
    ("Registry", "python-registry", True),
    ("numpy", "numpy", True),
    ("pandas", "pandas", True),
    ("sklearn", "scikit-learn", False),  # only needed for the ML module
    ("streamlit", "streamlit", True),
    ("plotly", "plotly", True),
    ("jinja2", "jinja2", True),
    ("reportlab", "reportlab", True),
    ("yaml", "pyyaml", True),
]


def main() -> int:
    print(f"Python {sys.version.split()[0]} ({struct.calcsize('P') * 8}-bit)")
    if sys.version_info[:2] != (3, 12):
        print("  WARNING: tested on Python 3.12; pytsk3/pyewf wheels may be missing for other versions")

    missing_required = 0
    for name, pkg, required in MODULES:
        try:
            mod = importlib.import_module(name)
            version = getattr(mod, "__version__", "")
            print(f"  [OK]   {pkg:16} {version}")
        except ImportError as exc:
            tag = "FAIL" if required else "OPT "
            print(f"  [{tag}] {pkg:16} not importable ({exc})")
            missing_required += required

    # Prefetch decompression relies on ntdll.dll, which only exists on Windows
    if sys.platform == "win32":
        import ctypes
        ok = hasattr(ctypes.windll.ntdll, "RtlDecompressBufferEx")
        print(f"  [{'OK' if ok else 'FAIL'}]   ntdll RtlDecompressBufferEx (Win10+ prefetch)")
    else:
        print("  [OPT ] not Windows: compressed Win10+ prefetch files cannot be decompressed")

    print("\nAll required packages present." if not missing_required
          else f"\n{missing_required} required package(s) missing.")
    return 1 if missing_required else 0


if __name__ == "__main__":
    sys.exit(main())
