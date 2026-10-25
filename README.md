# Anti-Forensics Detector

Analyses a Windows (NTFS) disk image or extracted artifacts for signs of evidence
tampering: timestomping, log clearing, file/free-space wiping, hidden files and
anti-forensic tool use. Findings are rated by confidence and placed on one timeline.

Findings mean "likely", not proof. Scope is Windows and NTFS only.

## Project layout

```
CF/
├── app.py                  Streamlit dashboard (Stage 6)
├── check_env.py            Checks that all libraries import
├── requirements.txt
├── config/settings.yaml    Detection thresholds (Stage 3+)
├── afd/
│   ├── core/               Evidence loading, hashing, chain-of-custody log, Finding model
│   ├── parsers/            image_reader, mft, evtx, registry, prefetch     (Stage 2)
│   ├── detectors/          timestomp, log_wiping                            (Stage 3)
│   │                       file_wiping, freespace, hidden_files, tool_traces (Stage 4)
│   ├── analysis/           scoring, timeline, ml_anomaly                    (Stage 5)
│   └── reporting/          HTML/PDF report, CSV/JSON export, templates/     (Stage 6)
├── tests/                  pytest tests and sample_data/
└── docs/                   Your own notes (test plan records, screenshots)
```

## Setup (Windows 10/11, Python 3.12 64-bit)

1. **Use Python 3.12.** pytsk3 and libewf-python ship Windows wheels for 3.12;
   3.13/3.14 may try to compile from source and fail. Check: `py -0p`.

2. **Create the virtual environment outside OneDrive.** OneDrive would try to sync
   thousands of venv files, and long paths can exceed Windows' 260-character limit:
   ```powershell
   py -3.12 -m venv $env:USERPROFILE\venvs\afd
   & $env:USERPROFILE\venvs\afd\Scripts\Activate.ps1
   ```
   If PowerShell blocks the script:
   `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

3. **Install the dependencies:**
   ```powershell
   cd $env:USERPROFILE\OneDrive\Desktop\CF
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **Verify:**
   ```powershell
   python check_env.py
   ```
   Every required line should say `[OK]`.

5. **External tools for cross-checking** (install on the host, not in the venv):
   - FTK Imager: capture the image and export artifacts ($MFT, .evtx, hives, prefetch).
   - Autopsy 4.x: compare its results with this tool.
   - Optional: Eric Zimmerman's MFTECmd and PECmd, to validate our MFT and prefetch parsers.

## Evidence and case folders

Evidence and output live **outside OneDrive**, so multi-GB images are never uploaded.

| Setting | Default | Override |
|---|---|---|
| Evidence (input, read-only) | `C:\forensics\evidence` | `AFD_EVIDENCE_DIR` |
| Cases (output) | `C:\forensics\cases` | `AFD_CASES_DIR` |

Defaults are set in `config/settings.yaml`. An environment variable overrides the file:
```powershell
$env:AFD_EVIDENCE_DIR = "D:\evidence"
```
Suggested layout inside the evidence folder:
```
C:\forensics\evidence\
├── images\       win10_test.E01 (or .dd/.raw) plus FTK Imager's .txt hash log
└── artifacts\    $MFT, *.evtx, NTUSER.DAT, SOFTWARE, SYSTEM, *.pf
```

- Two inputs are supported: **exported artifacts** (the primary input: small and fast) and
  **full disk images** (E01 or raw).
- Work on a **copy**. Keep the original and its FTK Imager hash file separately.
- The tool hashes evidence on load (MD5 and SHA-256) and logs every action to
  `<cases_dir>\<case>\custody_log.jsonl`.
