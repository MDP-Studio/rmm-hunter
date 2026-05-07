# Changelog

## 0.1.0 - Unreleased

- Windows GUI for local RMM and living-off-the-land scanner.
- PowerShell collector for installed apps, services, scheduled tasks, startup entries, recent installers, Defender events, PowerShell logs, process creation logs, and WMI activity where available.
- Python rules engine with `clean`, `needs_review`, and `high_risk` verdicts.
- JSON, text, and PDF reporting.
- Deterministic next-step recommendations.
- Optional AI explanations with sanitized report data and no verdict authority.
- Electron hardening: sandboxed renderer, context isolation, disabled Node integration, restrictive CSP, navigation blocking, and report-path restrictions.
- Windows release packaging through Electron Builder and bundled PyInstaller scanner executable.
