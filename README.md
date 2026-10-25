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

## Stage 3: detectors (timestomping and log wiping)

Run on an image or a folder of exported artifacts:

```powershell
python run_detectors.py C:\forensics\cases\stage2_test_clean_v2\extracted clean_check
python run_detectors.py <image or folder> my_case --min-confidence LOW --limit 0
python run_detectors.py <image or folder> my_case --reference-time 2026-10-25T09:30:00Z
```

It prints a count per confidence level and up to 50 MEDIUM/HIGH findings (change with
`--min-confidence` and `--limit`), writes *every* finding to `<cases_dir>\<case>\findings.json`
and logs each step to the custody log. Run the tests with `python -m pytest`.

| Detector | File | Looks for |
|---|---|---|
| Timestomping (T1070.006) | `afd/detectors/timestomp.py` | `$SI` created earlier than `$FN` created, whole-second `$SI` dates, edit trace in `$SI` "MFT changed", dates copied from a system file, future or zeroed dates |
| Log wiping (T1070.001) | `afd/detectors/log_wiping.py` | Events 1102 / 104, missing record IDs, unexplained silence, header expecting more records, log history missing |

**Confidence** means how sure we are the *action* happened, not who did it or why.
Each finding lists its reasons and the innocent explanations that were considered.
Scores and thresholds are in `config/settings.yaml` under `detection:`.

**False positives that are handled on purpose**
- Installers and archive extraction (many files, whole-second original dates, same folder,
  arriving within seconds, often under Program Files) are downgraded to LOW with a note.
- Windows setup and updates (thousands of files across many folders arriving within minutes,
  with no "edited after arrival" trace) are downgraded the same way.
- Folders are skipped: their "MFT changed" time moves whenever a file is added to them.
- Gaps in a log are not reported when a restart, sleep or clock-change event from the System
  log sits next to them. Supply `System.evtx` along with the log you care about.
- A header that is *behind* the records (dirty file) is not a finding; one that is *ahead* is.

**Known limits:** a careful attacker can also edit `$FN` (for example by moving the file) or
stomp forward; a copy that keeps every date looks like `si_before_fn` and stays LOW unless
other indicators join it; log editing that leaves record IDs contiguous is not detectable here.
