# Mal-Vigil: Real-Time Static PE Malware Guardian & Zero-Day Isolation Daemon

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-lightgrey.svg)
![Architecture](https://img.shields.io/badge/architecture-Static%20PE%20%2B%20LightGBM-success.svg)

Mal-Vigil is an autonomous, non-intrusive endpoint daemon that monitors local download vectors, extracts static Portable Executable (PE) structural indicators, and predicts malicious intent using gradient-boosted decision trees (LightGBM).

By relying on structural heuristics (Shannon entropy, API import table characteristics, and header anomalies) rather than static cryptographic hashes, Mal-Vigil detects obfuscated, packed, and zero-day threats. Upon detecting a high-risk executable, the daemon instantly executes a non-destructive **soft quarantine** (`.isolated` extension swap) to prevent accidental execution while leaving final authority in the user's hands via native Windows interactive toast notifications.

---

## Architecture Overview

[Inbound Download Vector (Browser / Discord / Telegram / Storage)]
│
▼
Downloads Directory
│
▼ (FileSystemEventHandler Hook)
Mal-Vigil Watchdog Daemon
│
┌───────────────────────┴───────────────────────┐
▼                                               ▼

    PE Header & Section Parser               2. Static Feature Extraction
    • Section Entropy (Shannon)                 • RWE Section Detection
    • Optional Header Metrics                   • Dangerous API Call Frequency
    • Virtual vs. Raw Size Deltas               • Total Imported Symbols
    └───────────────────────┬───────────────────────┘
    │
    ▼ (Normalized Feature Vector)
    LightGBM Binary Classifier
    │
    ┌───────────────┴───────────────┐
    ▼                               ▼
    Risk Score < 40%                 Risk Score >= 50%
    [Pass Through]                 [Intervention Pipeline]
    │                               │
    │                               ├── 1. Atomic Soft Quarantine (.isolated)
    │                               └── 2. Native Toast Interactive Prompt
    │                                       │
    │                       ┌───────────────┴───────────────┐
    │                       ▼                               ▼
    │             [Keep & Restore Action]         [Acknowledge Block]
    │                       │                               │
    │             Strip .isolated Extension       Retain Neutralized State
    ▼                       ▼                               ▼
    [Standard Execution]   [User Restored File]            [Threat Neutralized]

    ---

## Core Capabilities

* **Real-Time Directory Monitoring:** Intercepts files via native Windows filesystem hooks (`watchdog`) at the exact millisecond writing completes.
* **Pre-Execution Static Inspection:** Evaluates binaries (`.exe`, `.dll`, `.scr`) without running code or requiring hypervisors/virtualized sandboxes.
* **Structural Feature Vectorization:** Extracts Shannon entropy per section, checks for Read-Write-Execute (`PAGE_EXECUTE_READWRITE`) flags, and inspects import tables for process injection primitives (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`).
* **Zero-Day ML Inference:** Leverages an optimized LightGBM model trained on structural attributes from the open EMBER benchmark dataset.
* **Non-Destructive Soft Quarantine:** Instead of deleting false-positive utilities, Mal-Vigil appends `.isolated` to the file extension, disarming the binary while preserving all raw bytes.
* **Native Desktop Interaction:** Prompts the user through Windows notification center buttons (`Keep & Restore` vs. `Keep Isolated`) powered by `win11toast`.
* **Zero Resource Overhead:** Operates continuously at ~25 MB of resident memory (RAM) with no recurring background processing when idle.

---

## Feature Extraction Matrix

| Feature | Extraction Logic | Threat Indication |
| :--- | :--- | :--- |
| **Max Section Entropy** | Shannon entropy calculation: $-\sum p(x) \log_2 p(x)$ | Values $> 7.2$ indicate encrypted/packed payloads or ransomware blocks. |
| **RWE Sections** | Bitwise evaluation of `IMAGE_SECTION_HEADER.Characteristics` | Flags writable and executable memory spaces typical of shellcode injectors. |
| **Suspicious API Imports** | String matching against dangerous Win32 API pointers | Identifies memory allocation, remote thread hijacking, and process hollowing primitives. |
| **Virtual Size vs Raw Size** | Discrepancy between section disk size vs memory reservation | Unusually large virtual sizes denote unpacking/uncompressing behaviors. |
| **Section Count** | Metric counts from `IMAGE_FILE_HEADER.NumberOfSections` | Anomalously low ($< 2$) or high ($> 8$) section counts indicate custom compilation scrapers. |

---

## Repository Structure

```text
Mal-Vigil/
├── .gitignore               # Excludes caches, venv, and quarantined binaries
├── README.md                # System documentation and setup guide
├── requirements.txt         # Runtime and static analysis dependencies
├── train_model.py           # Training pipeline for the LightGBM classifier
├── extractor.py             # Binary feature extraction logic using pefile
├── watcher.py               # Background filesystem listener & toast alert engine
└── models/
    └── malware_lgbm.txt     # Serialized, lightweight LightGBM decision tree weights