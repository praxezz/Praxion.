# ClamAV Setup Guide for Praxion

Praxion works without ClamAV (YARA rules, PE/ELF/Mach-O heuristics, and the built-in fallback scanner all run regardless), but installing ClamAV adds a second, signature-based detection layer alongside Praxion's own heuristics.

For best performance, install **both** `clamscan` and the `clamd` daemon so Praxion can use `clamdscan` (fast — database stays loaded in memory) instead of plain `clamscan` (slow — reloads the entire virus database on every single file, adding 10–30+ seconds per file).

## Windows

1. Go to https://www.clamav.net/downloads.
2. Download the installer matching your architecture (e.g. `clamav-X.Y.Z.win.x64.msi` for 64-bit Windows). Installing the wrong architecture is the most common cause of "installed but nothing works."
3. Run the installer and follow the prompts.
4. Update the virus definitions:
   ```powershell
   freshclam
   ```
5. Make sure `clamscan.exe` (and `clamd.exe`/`clamdscan.exe` if you want daemon mode) is on your `PATH`.

## macOS

```bash
brew install clamav
freshclam
```

To run the daemon for fast `clamdscan`-based scans:

```bash
brew services start clamav
```

## Linux (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install clamav clamav-daemon
sudo systemctl enable --now clamav-daemon
sudo freshclam   # update signatures (daemon usually does this automatically)
```

## Linux (Fedora/RHEL)

```bash
sudo dnf install clamav clamd
sudo freshclam
sudo systemctl enable --now clamd@scan
```

## Verifying it works

```bash
clamscan --version
clamdscan --version   # if you installed the daemon
```

Then just run Praxion normally — it auto-detects `clamscan`/`clamdscan` on `PATH` (and common install locations) at startup and reports which one it's using in the "SYSTEM READY" panel.

## Troubleshooting

- **"Only clamscan is available" warning**: the daemon (`clamd`) isn't running. Start it with your OS's service manager (see commands above) — Praxion will automatically prefer `clamdscan` once it's reachable.
- **Definitions out of date**: run `freshclam` manually, or check that the `freshclam` update service/timer is enabled.
- **ClamAV not found at all**: Praxion still works fully without it — you just lose the signature-based layer on top of YARA and the built-in heuristics.
