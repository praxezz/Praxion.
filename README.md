# 🛡️ Praxion — Cross-Platform USB Malware Scanner & Cleaner

**Praxion** watches for removable USB drives, automatically scans every file that lands on them, and quarantines anything malicious — combining YARA rules, format-aware binary analysis (PE/ELF/Mach-O), fuzzy hashing, optional ClamAV signatures, and optional VirusTotal lookups into one self-contained Python script.

```
██████╗ ██████╗  █████╗ ██╗  ██╗██╗ ██████╗ ███╗   ██╗
██╔══██╗██╔══██╗██╔══██╗╚██╗██╔╝██║██╔═══██╗████╗  ██║
██████╔╝██████╔╝███████║ ╚███╔╝ ██║██║   ██║██╔██╗ ██║
██╔═══╝ ██╔══██╗██╔══██║ ██╔██╗ ██║██║   ██║██║╚██╗██║
██║     ██║  ██║██║  ██║██╔╝ ██╗██║╚██████╔╝██║ ╚████║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝
```

> **Status:** actively developed personal security tool. Not a certified/commercial antivirus — see [Disclaimer](#-disclaimer).

---

## ✨ Features

- **Automatic USB detection** — polls for newly connected removable drives (with optional real-time, event-driven scanning via `watchdog` instead of polling).
- **YARA rule engine** — built-in rules covering common malware patterns, plus support for your own custom rules.
- **Cross-platform binary analysis**
  - 🪟 Windows: PE header analysis, suspicious import/API detection (`pefile`)
  - 🐧 Linux: ELF analysis and malware heuristics
  - 🍎 macOS: Mach-O analysis and malware heuristics
  - 📜 Cross-platform script detection (Python, Node.js, shell, PowerShell, batch, etc.)
- **Built-in fallback heuristics** — expanded suspicious-pattern detection that runs even without YARA/ClamAV, so Praxion never scans "blind."
- **Fuzzy hashing** — pure-Python CTPH hashing (`ppdeep`, ssdeep-compatible) to catch near-duplicate/variant malware samples.
- **ClamAV integration (optional)** — uses `clamdscan` when the daemon is running (fast) or falls back to `clamscan` (slower, reloads the DB per file); works fine without ClamAV at all.
- **VirusTotal integration (optional)** — submit suspicious files/hashes to the VirusTotal API for a second opinion.
- **Safe quarantine with evidence trail** — malicious files are copied to a quarantine folder alongside a JSON evidence file (detection reasons, hashes, timestamps) before the original is removed from the USB drive.
- **Bounded parallel scanning** — `ThreadPoolExecutor`-based worker pool so large drives scan quickly without overwhelming the system.
- **Live terminal UI** — a Rich-powered, color-coded (red/amber) interface showing dependency status, an animated in-progress scanner indicator, and a session summary on exit.
- **Self-healing dependencies** — required packages are checked and auto-installed on first run; optional ones degrade gracefully if they can't be installed.
- **Built-in test mode** — generates a folder of synthetic (inert) malicious-looking samples across all supported platforms to verify detection without needing real malware.

---

## 📸 How it works

1. Praxion starts, silently bootstraps its own dependencies, then shows a dependency/status panel.
2. It detects currently connected removable drives and starts a background scan on each.
3. It then watches for new drives being plugged in (real-time via `watchdog` if available, otherwise polling every `POLL_INTERVAL` seconds).
4. Every scanned file is checked against YARA rules, format-specific heuristics, the built-in fallback scanner, ClamAV (if installed), and optionally VirusTotal.
5. Files flagged as malicious are quarantined (copied with an evidence JSON) and removed from the USB drive; safe files are left untouched.
6. Press `Ctrl+C` to stop — Praxion prints a session summary (files scanned, threats removed, errors) before exiting.

---

## 🚀 Getting Started

### Requirements

- Python 3.8+
- Windows, macOS, or Linux

### Installation

```bash
git clone https://github.com/<your-username>/praxion.git
cd praxion
pip install -r requirements.txt
```

> You don't strictly need to run `pip install` first — Praxion checks and auto-installs its required dependencies (`rich`, `psutil`, `yara-python`) the first time you run it. `requirements.txt` is there for reproducible setups, CI, and Docker builds.

### (Optional) Install ClamAV

For an additional signature-based detection layer, see **[CLAMAV_SETUP.md](CLAMAV_SETUP.md)** for OS-specific instructions.

### Run it

```bash
python praxionz.py
```

Plug in a USB drive — Praxion will pick it up automatically and start scanning.

---

## 🧰 Usage

```bash
python praxionz.py [--mode {run,test,debug,auto-delete}] [options]
```

| Flag | Description |
|---|---|
| `--mode run` | Default mode — watch for USB drives and scan them live. |
| `--mode test` | Generate synthetic (inert) malicious samples in a temp folder and scan them, to verify Praxion is detecting correctly. |
| `--mode debug` | Enable verbose debug logging to `scan_debug.txt`. |
| `--mode auto-delete` | Automatically delete original files after quarantining (no confirmation). |
| `--poll-interval N` | Override the drive-detection poll interval, in seconds (default: 2). |
| `--virustotal` | Enable VirusTotal lookups for suspicious files. |
| `--vt-api-key KEY` | VirusTotal API key (or set the `VIRUSTOTAL_API_KEY` environment variable). |
| `--vt-scan-timeout N` | VirusTotal API timeout in seconds (default: 30). |

### Examples

```bash
# Run the built-in test suite to confirm everything works
python praxionz.py --mode test

# Watch for USB drives with a faster poll interval
python praxionz.py --poll-interval 1

# Enable VirusTotal scanning for an extra opinion on suspicious files
export VIRUSTOTAL_API_KEY=your_key_here
python praxionz.py --virustotal
```

---

## 📁 Where Praxion stores its data

Praxion picks a writable application directory automatically (script folder if writable, otherwise a per-OS user directory):

| OS | Fallback location |
|---|---|
| Windows | `%LOCALAPPDATA%\Praxion` |
| macOS | `~/Library/Application Support/Praxion` |
| Linux | `~/.praxion` |

Inside that directory:

```
Praxion/
├── logs/
│   ├── scan_log.txt              # main activity log
│   ├── scan_debug.txt            # verbose log (--mode debug)
│   ├── scan_history.txt          # per-file scan history
│   └── threat_explanations.txt   # human-readable reasons for each detection
└── suspicious/
    ├── <quarantined_file>
    ├── <quarantined_file>.evidence.json
    └── report_<timestamp>.txt
```

None of this is committed to the repo — see `.gitignore`.

---

## ⚙️ Dependencies

| Package | Required? | Purpose |
|---|---|---|
| `rich` | ✅ Required | Powers the entire terminal UI |
| `psutil` | ✅ Required | Cross-platform drive/process detection |
| `yara-python` | ✅ Required | YARA rule matching engine |
| `colorama` | Optional | ANSI color fallback on older terminals |
| `pefile` | Optional | Deep Windows PE analysis |
| `ppdeep` | Optional | Fuzzy (CTPH) hashing |
| `watchdog` | Optional | Real-time, event-driven scanning |
| `vt-py` | Optional | VirusTotal API integration |
| ClamAV (`clamscan`/`clamdscan`) | Optional, external | Signature-based scanning layer — see [CLAMAV_SETUP.md](CLAMAV_SETUP.md) |

Required packages are auto-installed on first run if missing. If auto-install fails (e.g. no internet, no prebuilt wheel for your platform), Praxion prints the exact manual `pip install` command to run.

---

## 🧪 Testing

Praxion includes a self-contained test mode that generates synthetic, **non-functional** malicious-looking files (fake PE droppers, EICAR-style patterns, suspicious scripts, fake ELF binaries, etc.) and scans them — useful for verifying detection after changes, and for demos.

```bash
python praxionz.py --mode test
```

---

## 🗺️ Roadmap ideas

- [ ] Configurable YARA rule directory (load external `.yar` files)
- [ ] JSON/CSV export of scan sessions for SIEM ingestion
- [ ] GUI/tray-icon front end
- [ ] Signed release builds (PyInstaller) for non-technical users
- [ ] Docker image for headless/server use

Have another idea? Open an issue!

---

## 🤝 Contributing

Contributions are welcome! Please read **[CONTRIBUTING.md](CONTRIBUTING.md)** for setup instructions, testing steps, and guidelines before opening a PR.

## 🔒 Security

Found a security issue in Praxion itself? Please see **[SECURITY.md](SECURITY.md)** for responsible disclosure instead of opening a public issue.

## ⚠️ Disclaimer

Praxion is a heuristic and signature-assisted scanner built for personal/educational use. It is **not** a certified antivirus product and cannot guarantee detection of all malware. Always maintain a proper, dedicated antivirus/EDR solution and backups — treat Praxion as an additional layer of defense for removable media, not a replacement.

Test samples generated in `--mode test` are intentionally inert and cannot execute or spread; they exist only to exercise Praxion's detection logic.

## 📄 License

Released under the [MIT License](LICENSE) — Copyright (c) 2025 Praveen K.
