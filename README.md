# RMM Hunter

Standalone Windows scanner for unauthorized remote access tools and living-off-the-land traces.

Created and maintained by Meidie. Published by MDP Studio.

RMM Hunter is a triage tool. It collects endpoint artifacts, applies local rules, and produces:

- `clean`
- `needs_review`
- `high_risk`

It does not delete files, stop services, uninstall software, quarantine artifacts, or change system settings.

## Contact

Repository: `https://github.com/MDP-Studio/rmm-hunter`

Security reports and project contact: `meidie@mdpstudio.com.au`

Do not send raw scan reports unless requested. Reports can contain usernames, file paths, command-line fragments, service names, task actions, and event excerpts.

## Why This Exists

Threat actors frequently abuse legitimate remote monitoring and management tools because they blend into normal IT activity. This MVP focuses on the fast questions an analyst or small business operator needs answered:

- Is a known remote access tool installed?
- Is it running as a service or scheduled task?
- Did it appear from `Downloads`, `Temp`, or another user-writable path?
- Are there recent service-install, PowerShell, Defender, WMI, or process-creation traces that need review?

## Current Scope

Windows MVP:

- Installed programs from uninstall registry keys
- Windows services, including executable path and Authenticode summary where possible
- Recent service creation events, event ID `7045`
- Scheduled tasks
- Startup registry keys and startup folders
- Recent installer and script files in Downloads and Temp locations
- Defender events where available
- PowerShell Operational and Windows PowerShell logs where available
- Security process creation events where available, event ID `4688`
- WMI Activity events where available

Known remote access tools covered in the initial rules:

- ScreenConnect / ConnectWise Control
- SimpleHelp
- AnyDesk
- TeamViewer
- MeshAgent / MeshCentral
- Tactical RMM
- Atera
- Splashtop
- RustDesk
- DWAgent / DWService

Later platform scope:

- macOS: LaunchAgents, LaunchDaemons, login items, installed apps, remote management settings, shell traces
- Linux: systemd, cron, SSH login traces, shell history hints, remote agents, auditd where available
- Mobile: no native scanner. MDM and posture checks only.

## Quick Start

### Desktop GUI

Install the desktop dependency once:

```powershell
npm.cmd install
```

Start the Windows desktop app:

```powershell
npm.cmd start
```

The GUI provides:

- Big `Scan this device` action
- Progress screen during collection and analysis
- Dashboard verdict: `clean`, `needs_review`, or `high_risk`
- Evidence cards for each finding
- Deterministic recommended next steps
- Optional AI explanations and recommendations
- JSON and PDF export
- No automatic deletion or remediation

Enable optional AI explanations:

```powershell
$env:OPENAI_API_KEY = "your-api-key"
npm.cmd start
```

Optional model override:

```powershell
$env:RMM_HUNTER_AI_MODEL = "gpt-5.2"
```

Default model: `gpt-5-mini`.

AI is only used to explain the report and suggest next steps. It does not set or change the scanner verdict. Before any AI request, the desktop app sends a minimized report summary and strips or summarizes sensitive values such as full user paths, emails, long tokens, encoded blobs, and raw event payloads.

### CLI

Run from an elevated PowerShell session for the best coverage:

```powershell
cd "C:\Users\meidi\Documents\personal project\RMM Hunter"
python .\rmm_hunter.py
```

Default outputs are written under `reports\`:

- Raw collector artifacts JSON
- Final rule report JSON
- Human-readable summary text

Packaged desktop builds write scan reports under the per-user RMM Hunter profile in `%LOCALAPPDATA%\RMM Hunter\reports` so the installed app does not need write access to its install directory.

Analyze an existing collector artifact file:

```powershell
python .\rmm_hunter.py --input .\reports\rmm_hunter_artifacts_20260507T000000Z.json
```

Run the PowerShell collector only:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\collect_windows.ps1 -OutputPath .\reports\artifacts.json
```

## Release Build

The GitHub release build is Windows-first. It bundles the Python scanner as a PyInstaller executable, then packages the Electron desktop app with Electron Builder.

Install build dependencies:

```powershell
npm.cmd ci
python -m pip install -r requirements-build.txt
```

Run the full local verification gate:

```powershell
npm.cmd run release:verify
pip-audit -r requirements-build.txt
```

Build Windows installer and portable artifacts:

```powershell
npm.cmd run dist
```

The scanner build script uses `RMM_HUNTER_PYINSTALLER` when set, then `.release-venv\Scripts\pyinstaller.exe` when present, then `pyinstaller` from `PATH`.

Release artifacts are written to `release\`.

GitHub Actions workflow:

- `.github/workflows/release.yml`
- manual `workflow_dispatch`
- automatic draft release when pushing a `v*` tag

Example tag flow after committing:

```powershell
git tag v0.1.0
git push origin v0.1.0
```

Before making the repository public, choose a license. The package is currently marked `UNLICENSED` until you decide the public license.

## Reading The Verdict

`clean` means the collected sources did not contain known RMM or suspicious living-off-the-land indicators. It is not a guarantee that the endpoint is safe.

`needs_review` means something legitimate-but-sensitive was found, such as TeamViewer installed under Program Files, or a scheduled task/startup entry that resembles a remote access tool.

`high_risk` means the scanner found evidence that is hard to justify without a known admin action, such as:

- A service executable running from Downloads or Temp
- A known RMM service installed recently
- Encoded PowerShell traces
- Defender malware detections
- `msiexec` launched from browser, Downloads, or Temp paths

## Privacy Notes

Reports can include usernames, file paths, command-line fragments, service names, task actions, and event excerpts. Do not publish raw reports without reviewing them.

The optional AI explanation layer is off by default and requires `OPENAI_API_KEY`. If enabled, only sanitized report evidence is sent to the AI provider. Keep the deterministic JSON report as the source of truth for technical review.

## Security And Release Docs

- `SECURITY.md`: vulnerability reporting and release security checklist
- `docs/SECURITY_AUDIT.md`: current security audit summary
- `RELEASE_CHECKLIST.md`: GitHub release readiness checklist
- `CHANGELOG.md`: release notes

## Product Direction

Best initial positioning: a lightweight second-opinion scanner for Windows endpoints after a suspicious support scam, MSP handover, or small-business incident. It should complement EDR and RMM inventory tools rather than claim to replace them.

Fast validation experiment:

1. Run against 3 clean Windows machines and 3 intentionally seeded lab machines.
2. Track false positives for each source: services, tasks, startup keys, recent files, logs.
3. Add an allowlist file only after the first false-positive pass.
4. Package as a signed single-folder release once the CLI output is stable.

## References

- CISA, NSA, and MS-ISAC advisory on malicious use of legitimate RMM software: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a
- CISA advisory on SimpleHelp RMM exploitation: https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-163a
- MITRE ATT&CK data sources for process, scheduled job, service, script, registry, and WMI evidence: https://attack.mitre.org/datasources/
