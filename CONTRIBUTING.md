# Contributing to Praxion

Thanks for your interest in improving Praxion! Contributions of all kinds are welcome — new YARA rules, platform fixes, performance improvements, and documentation.

## Getting started

1. Fork the repo and clone your fork.
2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate   # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. Create a branch for your change: `git checkout -b feature/my-improvement`.

## Testing your changes

Praxion ships a built-in test mode that generates synthetic malicious samples (never real malware) and scans them:

```bash
python praxionz.py --mode test
```

Run this before and after your change to confirm detection behavior didn't regress.

## Guidelines

- Keep platform-specific code behind the existing `CURRENT_PLATFORM` checks (Windows/Linux/macOS).
- New optional dependencies must degrade gracefully — follow the pattern in `ensure_dependencies()` so Praxion still runs if the package is missing.
- Match the existing Rich-based UI style (`cprint`, `print_box`, `info/ok/warn`) rather than raw `print()`.
- Don't add real malicious code, live C2 domains, or functional exploit payloads — test samples must stay inert (see `create_test_samples()`).
- Add a short entry to `README.md`'s feature list if you add a user-facing capability.

## Reporting bugs / suggesting features

Open a GitHub Issue with:
- Your OS and Python version
- Command you ran (`--mode`, flags used)
- Full console output or traceback
- What you expected to happen

## Security issues

Please do **not** open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md) for how to report them privately.
