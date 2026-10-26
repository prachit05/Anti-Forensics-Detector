# Stage 8: Likely viva questions, with short answers

Grouped by topic. Each member should know their own section well and the *General* section fully.

## General

**1. What does the project do, in one sentence?**
It analyses a Windows disk image or its exported artifacts, flags signs that evidence was tampered with or destroyed, rates each sign HIGH/MEDIUM/LOW with reasons, and puts them on one timeline.

**2. Why "likely" and not "proof"?**
Each indicator has innocent explanations: archive extraction keeps old dates, reboots leave log gaps, admins run cleaners. The tool shows the indicators and the explanations it considered; the examiner draws the conclusion.

**3. What is anti-forensics? Give the MITRE ATT&CK IDs.**
Actions that hide, destroy or falsify evidence. Indicator Removal is T1070: T1070.001 clear Windows event logs, T1070.004 file deletion, T1070.006 timestomp. Hiding data in an ADS is T1564.004; masquerading with a wrong extension is T1036.008.

**4. How is confidence calculated?**
Each detector adds weighted points for the indicators that fired and subtracts points for known innocent patterns. The total maps to LOW/MEDIUM/HIGH using thresholds (`medium_at`, `high_at`) in `config/settings.yaml`. Correlation can raise an action's level if a matching tool *execution* is within 30 minutes.

**5. How do you keep false positives down?**
- **Timestomping:** bulk and volume-burst patterns (installers, updates) are downgraded, and folders are skipped.
- **Log gaps:** gaps next to a restart or clock change are ignored.
- **Built-in tools:** System32 copies are ignored and their executions score lower.
- **Free space:** only unallocated clusters are sampled.
- **Campaigns:** LOW findings never form one.

We measured on a clean image of the same VM.

**6. Why did you compare with Autopsy?**
To validate the parsers and detections against an accepted tool, and to show what each tool finds that the other does not. Autopsy has no log-clearing check or `$SI`/`$FN` comparison rule; we have no carving or keyword search.

**7. What are the main limitations?**
- A skilled attacker can also wipe the cleaner's traces.
- Moving a file can overwrite `$FN`, which defeats the timestomping check.
- Contiguous-ID log editing is not detected.
- Zero-filled free space is weak evidence on SSDs and VMs.
- Header checks on large files need the full image.
- Windows and NTFS only.

**8. What would you add next?**
- `$UsnJrnl` and `$LogFile` analysis (they record when timestamps were changed).
- Volume Shadow Copies (older versions of logs and files).
- Shellbags and Amcache for more execution evidence.
- Hash-chained custody log entries.
- Linux support (ext4 `crtime`, journald).

## Evidence handling (Member 3)

**9. Why hash the evidence? Why both MD5 and SHA-256?**
To show the data did not change during analysis: re-hashing later must give the same value. MD5 is still in use (FTK Imager reports it) but has known collision attacks. SHA-256 has no practical collisions. Using both gives compatibility and strength.

**10. Why does our hash of `tampered.E01` differ from FTK Imager's?**
FTK hashes the *disk data*, while a file hash covers the E01 *container* (compression, metadata). Our `media_hash()` reads the disk data out of the E01 and matches FTK's MD5, and it matches `Get-FileHash` of the raw `.img`.

**11. E01 vs raw/dd?**
- **Raw:** a byte-for-byte copy, simple, same size as the disk.
- **E01 (Expert Witness):** compressed and segmented, stores case metadata, CRCs per chunk, and a hash of the acquired data.

**12. What is chain of custody and how does the tool support it?**
A record of who handled the evidence, when, and what was done. The tool appends one JSON line per action (evidence hashed, artifact extracted, detector run, report written, with output hashes) to `custody_log.jsonl`, with UTC time, examiner and host. It is append-only by design but not tamper-proof; hash-chaining the lines would fix that.

**13. Why image a powered-off VM?**
A running system keeps writing to the disk (logs, prefetch, pagefile), so a live image changes while it is taken and cannot be reproduced.

**14. Is your output admissible evidence?**
The tool supports an examiner; it does not replace one. In India, electronic records need a certificate under Section 63 of the Bharatiya Sakshya Adhiniyam, 2023 (formerly Section 65B of the Indian Evidence Act). Hashes, the custody log and a repeatable method support that, but the examiner's testimony and conclusion are what count.

## NTFS, MFT and timestomping (Member 1)

**15. What is the MFT?**
The NTFS Master File Table. One record (normally 1024 bytes, signature `FILE`) per file or folder, holding attributes: `$STANDARD_INFORMATION`, `$FILE_NAME`, `$DATA` and so on. Entries 0–23 are reserved for NTFS metadata files (`$MFT`, `$MFTMirr`, `$LogFile`, `$Volume`, root `.` at 5, `$Bitmap` at 6, …).

**16. `$STANDARD_INFORMATION` vs `$FILE_NAME`: why compare them?**
Both hold four timestamps (MACB: modified, accessed, MFT changed, born/created). `$SI` is what Explorer shows and can be set by any program through `SetFileTime()`. `$FN` is written by the kernel when the file is created, renamed or moved. A file cannot be created before it arrived, so `$SI` created earlier than `$FN` created suggests the `$SI` date was faked.

**17. Why do whole-second timestamps matter?**
NTFS stores time as a FILETIME: 100-nanosecond ticks since 1 Jan 1601 UTC. Real times almost always have a fraction. Tools that take a date as text write `.0000000`, so whole seconds in `$SI` next to a fractional `$FN` support timestomping.

**18. What is the "MFT changed" time used for?**
`SetFileTime()` cannot set it, and it updates when the dates are edited. If it is long after the file arrived while the write time is before arrival, it shows *when* the stomping happened. That is the time we put on the timeline.

**19. How can an attacker beat your timestomping check?**
- Moving or renaming a file makes Windows copy `$SI` values into the new `$FN`, so "timestomp, then move twice" makes both agree.
- Setting dates *forward* is also not caught.

`$UsnJrnl` (reason `BASIC_INFO_CHANGE`) would still show it; that is future work.

**20. Why write your own MFT parser instead of analyzeMFT?**
We need raw 100-ns ticks for both `$SI` and `$FN`, every `$FN` (short and long names), named streams (ADS), resident data bytes and fixup handling. Our own parser keeps all of that; MFTECmd is used to cross-check it.

**21. What are fixups?**
NTFS writes an update sequence number into the last 2 bytes of each 512-byte sector of a record, and saves the real bytes in the record header. The parser puts them back, and a mismatch means a torn or corrupt record.

**22. Resident vs non-resident data?**
Small files (under ~700 bytes) keep their content *inside* the MFT record. Larger ones store data runs pointing to clusters. With an exported `$MFT` we can only see resident content; with a disk image we read the first bytes of large files from their clusters.

## File wiping, free space and hidden data (Member 1)

**23. How does SDelete leave a trace?**
It overwrites the file, then renames it 26 times (`AAAA.AAA` … `ZZZZ.ZZZ`, keeping the name length) to hide the old name, then deletes it. The deleted MFT record keeps the last name, and SDelete leaves a prefetch file.

**24. What is Shannon entropy and why use it?**
H = −Σ pᵢ log₂ pᵢ over the 256 byte values, from 0 (all one byte) to 8 bits/byte (random). Text is about 4–5, executables 5–6.5, compressed or encrypted data near 8. Wiping writes zeros (0), patterns such as 0xFF (0), or random data (about 8).

**25. Why is zero-filled free space only LOW?**
Space that was never written (a new VM disk, a fresh install) and SSD TRIM also read as zeros. Random or 0xFF patterns across most of the free space are more telling; even then, a wiping tool's execution trace is needed.

**26. Why sample only unallocated clusters?**
Allocated files include compressed archives and update packages, which are random-looking and would trigger the check. NTFS's `$Bitmap` has one bit per cluster, so we read only 1 MB chunks whose clusters are all free.

**27. What is an Alternate Data Stream?**
A named `$DATA` attribute on an NTFS file (`notes.txt:payload.exe`). Explorer and `dir` show only the main stream's size, so data can hide there. Windows itself uses `Zone.Identifier` (Mark of the Web), which we whitelist.

**28. How do you detect a disguised file?**
By magic bytes: the first bytes of the content (`MZ` = Windows executable, `PK\x03\x04` = ZIP/Office, `%PDF`, `\xFF\xD8\xFF` = JPEG). An `MZ` header with a `.jpg` or `.txt` extension is a mismatch.

## Logs, registry and tool traces (Member 2)

**29. Which event IDs show log clearing?**
- **1102** (Security log): "The audit log was cleared"; it records the account that cleared it.
- **104** (System log): any other log cleared.

Related:
- **4719**: audit policy changed.
- **6005 / 6006**: Event Log service started / stopped (boot and shutdown).
- **6008**: unexpected shutdown.
- **4616**: system time changed.

**30. How do you find gaps in a log?**
Every `.evtx` record has a sequential EventRecordID. Missing IDs mean records were removed. Long silences in a normally busy log are suspicious unless a restart, sleep or clock change in the System log explains them. We also compare the file header's next-record number with the last record actually present.

**31. Can logs be cleared without Event 1102?**
Yes. Stopping the Event Log service threads (e.g. Phant0m) silences logging, and specialised tools can delete single records and fix the IDs. Silencing shows up as an unexplained time gap; seamless record editing is a stated limit.

**32. What is Prefetch?**
`C:\Windows\Prefetch\<EXE>-<hash>.pf` speeds up program start. On Windows 10/11 it stores the executable name, run count and the last 8 run times, compressed with Xpress-Huffman (signature `MAM`). It persists after the program is deleted. It can be disabled (`EnablePrefetcher` = 0), and cleaners can delete it.

**33. What is UserAssist?**
A key in each user's `NTUSER.DAT` (`…\Explorer\UserAssist\{GUID}\Count`) recording GUI program launches with run count and last run time. Value names are ROT13-encoded. GUID `{CEBFF5CD-…}` is executables and `{F4E57C4B-…}` is shortcuts.

**34. RunMRU and the Uninstall key?**
RunMRU (`NTUSER.DAT …\Explorer\RunMRU`) lists commands typed into Win+R, e.g. `wevtutil cl Security`. `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` lists installed programs, e.g. CCleaner or Eraser, and the key's last-write time.

**35. A tool on disk vs a tool that ran: how do you treat them?**
Presence (MFT, Uninstall key) shows capability only and is LOW/MEDIUM. Execution (prefetch, UserAssist, RunMRU) shows use. Only execution raises the confidence of a nearby wipe, timestomp or log clear.

**36. Why are `cipher.exe` and `wevtutil.exe` handled differently?**
They are built into every Windows install and are also used by installers and admin scripts. Their System32 copies are ignored, and their executions score 2 points lower. `cipher /w` and `wevtutil cl` command lines (RunMRU, Event 4688) are the stronger evidence.

## Timeline, correlation and ML (Member 3)

**37. How is the timeline built?**
Every dated finding becomes an entry, sorted in UTC. Entries less than 30 minutes apart form an *episode*. Each entry carries a *time meaning* (prefetch last run, `$SI` MFT changed, event logged), because the times come from different artifacts and mean different things.

**38. What is a "campaign" finding?**
At least three different techniques at MEDIUM or above within 2 hours. It is reported as a cluster that is only as strong as its members, and it lists them.

**39. How does Isolation Forest work, and why use it?**
It builds random trees that split the data on random features at random values. Unusual points are isolated in fewer splits, so a short average path means an anomaly. It is unsupervised, which suits us because we have no labelled tampering data. `contamination` sets the expected share of anomalies. Features: time between events and record-ID step for logs; `$SI`/`$FN` differences and whole-second flags for the MFT. ML findings stay LOW/MEDIUM and only support the rules.

**40. Why UTC everywhere?**
NTFS and EVTX store UTC. Converting to local time invites daylight-saving and time-zone mistakes, and the VM's time zone may differ from the examiner's.

## Code and design

**41. How is the code split?**
- `afd/parsers` (image, MFT, evtx, registry, prefetch)
- `afd/detectors` (one file per module)
- `afd/analysis` (scoring, timeline, ML)
- `afd/reporting` (HTML/PDF/CSV/JSON)
- `afd/pipeline.py` (runs everything)
- `app.py` (dashboard)
- `run_detectors.py` (command line)

Every detector returns the same `Finding` object.

**42. How did you test it without many real images?**
Unit tests build synthetic but valid MFT records (real headers, fixups, attributes) and run the real parser on them, plus clean/tampered cases for each detector and an end-to-end pipeline → report → reopen test. Then the VM images test it on real data.
