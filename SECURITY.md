# Security

Praxion works with untrusted removable media and untrusted files by design, so if you spot a way it could be tricked, crashed, or bypassed, I'd like to know.

## Found a problem?

- Open an issue on this repo, or
- Reach out to the maintainer directly (see profile) if it's something sensitive you'd rather not put in a public issue.

When you do, please include:
- Praxion version / commit hash
- OS and Python version
- Steps to reproduce
- What actually happened vs. what you expected

## Scope notes

- Praxion is a heuristic/YARA-based scanner, not a full antivirus/EDR replacement — missing a brand-new piece of malware isn't a bug by itself.
- Test samples from `--mode test` are intentionally inert. If you find a way they cause real harm, that's worth flagging.
