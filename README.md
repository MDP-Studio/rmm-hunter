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

Downloads: `https://github.com/MDP-Studio/rmm-hunter/releases`

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
- Plain-English finding explanations with non-destructive review actions
- Extracted context for PowerShell URLs/domains, Defender threat actions, affected resources, and Defender setting changes
- Deterministic recommended next steps
- GitHub Releases update check with installer auto-update for the installed Windows build
- Optional bring-your-own-key AI explanations and recommendations
- About and feedback sections with GitHub issue, security policy, privacy policy, private email, and donation links
- JSON and PDF export
- No automatic deletion or remediation

Optional AI explanations are configured inside the app. Run a scan, click `AI Recommendations`, then choose a provider and paste your own API key when prompted. If no key is configured, the app shows a setup notice beside the summary and does not send report data anywhere. Use `Open API key field` from that notice to open provider settings.

Built-in provider presets:

- OpenAI: Responses API
- OpenRouter: OpenAI-compatible chat completions
- Groq: OpenAI-compatible chat completions
- Custom OpenAI-compatible endpoint

Saved API keys stay on the local Windows profile and are encrypted with Electron safe storage where available. Keys are not written to scan reports or exports.

Environment variables are also supported for portable or managed use:

```powershell
$env:OPENAI_API_KEY = "your-api-key"
npm.cmd start
```

Provider and model overrides:

```powershell
$env:RMM_HUNTER_AI_PROVIDER = "openai"
$env:RMM_HUNTER_AI_MODEL = "gpt-5.2"
$env:RMM_HUNTER_AI_ENDPOINT = "https://api.example.com/v1/chat/completions"
$env:RMM_HUNTER_AI_API_KEY = "provider-api-key"
```

Provider-specific API key variables are supported: `OPENAI_API_KEY`, `OPENROUTER_API_KEY`, and `GROQ_API_KEY`.

Default OpenAI model: `gpt-5-mini`.

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

Write an optional mapped detection export for SOC or threat-intelligence workflows:

```powershell
python .\rmm_hunter.py --input .\reports\rmm_hunter_artifacts_20260507T000000Z.json --mapped-out .\reports\rmm_hunter_mapped.json
```

The mapped export does not change the deterministic `clean`, `needs_review`, or `high_risk` verdict. It adds rule IDs, ATT&CK/D3FEND mappings, Sigma-style tags, and STIX/MISP object hints for downstream tooling.

Run the PowerShell collector only:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\collect_windows.ps1 -OutputPath .\reports\artifacts.json
```

## Release Build

The GitHub release build is Windows-first. It bundles the Python scanner as a PyInstaller executable, then packages the Electron desktop app with Electron Builder.

Current public downloads are published from GitHub Releases. RMM Hunter beta releases are unsigned until SignPath or another trusted signing route is configured, so Windows may show `Unknown publisher` or Microsoft Defender SmartScreen warnings. Verify release artifacts with the bundled `SHA256SUMS.txt`, `rmm-hunter-release-manifest.json`, and `VERIFY_RELEASE.md` files.

The installed Windows app can check GitHub Releases for newer versions, download the NSIS installer update, and restart to install it after the user clicks the update action. Update checks do not send scan reports or artifacts. Portable builds can still check for updates, but they must be replaced manually from the release page.

Builds older than `0.1.2` only opened the GitHub release page. Install `0.1.2` or newer manually once, then later installed builds can use the in-app download and restart-to-install flow.

The per-user NSIS installer detects an existing RMM Hunter install from the current user's registry keys, keeps the existing install location to avoid duplicate app folders, shows an update or repair confirmation page, and keeps local reports, AI settings, and updater state during upgrades. If a newer version is already installed, the installer blocks the older build instead of downgrading it.

The Windows app icon is tracked at `gui/assets/icon.ico`, with SVG/PNG sources beside it. Regenerate it from `gui/assets/icon.svg` with ImageMagick:

```powershell
magick .\gui\assets\icon.svg -resize 1024x1024 .\gui\assets\icon.png
magick .\gui\assets\icon.png -define icon:auto-resize=256,128,64,48,32,16 .\gui\assets\icon.ico
```

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

Run the seeded coverage corpus directly:

```powershell
python .\scripts\evaluate_corpus.py --manifest .\tests\corpus\manifest.json
```

Build Windows installer and portable artifacts:

```powershell
npm.cmd run dist
```

Release packaging passes `--publish never` to Electron Builder. The GitHub workflow creates the draft GitHub release explicitly after artifacts are built and uploads `latest.yml` so installed NSIS builds can auto-update from GitHub Releases.

Package only, after `npm.cmd run build:scanner` has already produced the scanner executable:

```powershell
npm.cmd run package:windows
```

The scanner build script uses `RMM_HUNTER_PYINSTALLER` when set, then `.release-venv\Scripts\pyinstaller.exe` when present, then `python -m PyInstaller`.

Release artifacts are written to `release\`.

GitHub Actions workflow:

- `.github/workflows/release.yml`
- manual `workflow_dispatch`
- automatic draft release when pushing a `v*` tag
- release assets include `SHA256SUMS.txt`, `rmm-hunter-release-manifest.json`, `VERIFY_RELEASE.md`, and `latest.yml`

Example tag flow after committing:

```powershell
git tag v0.1.4
git push origin v0.1.4
```

RMM Hunter is released under the Apache License 2.0. The npm package remains marked `private` to prevent accidental registry publishing.

## Code Signing Policy

RMM Hunter's code signing policy is documented in `docs/CODE_SIGNING_POLICY.md`.

Current status:

- Current beta artifacts are unsigned builds.
- Future signed open-source releases are intended to use SignPath Foundation if the project is accepted.
- Signing credentials and API tokens must never be committed to the repository.
- Maintainers and signing approvers must keep multi-factor authentication enabled for GitHub and SignPath accounts.

Signing policy statement for future SignPath-backed releases:

```text
Free code signing provided by SignPath.io, certificate by SignPath Foundation.
```

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

The optional AI explanation layer is off by default and requires a user-supplied provider key or environment variable. If enabled, only sanitized report evidence is sent to the selected AI provider. Keep the deterministic JSON report as the source of truth for technical review.

Full privacy policy: `PRIVACY.md`

## Security And Release Docs

- `SECURITY.md`: vulnerability reporting and release security checklist
- `LICENSE`: Apache License 2.0 terms
- `docs/CODE_SIGNING.md`: Windows signing and icon setup
- `docs/CODE_SIGNING_POLICY.md`: SignPath-ready project signing policy
- `docs/VERIFY_RELEASE.md`: SHA256, Authenticode, and release provenance checks
- `PRIVACY.md`: local report handling and optional AI data handling
- `docs/SECURITY_AUDIT.md`: current security audit summary
- `docs/GAP_ADDENDUM.md`: release trust, interoperability, coverage, and mapping gaps
- `docs/DETECTION_MAPPING.md`: rule-to-ATT&CK/D3FEND matrix and mapped export profile
- `docs/COVERAGE_SCORECARD.md`: seeded corpus scorecard and coverage boundaries
- `RELEASE_CHECKLIST.md`: GitHub release readiness checklist
- `CHANGELOG.md`: release notes

## Product Direction

Best initial positioning: a lightweight second-opinion scanner for Windows endpoints after a suspicious support scam, MSP handover, or small-business incident. It should complement EDR and RMM inventory tools rather than claim to replace them.

Fast validation experiment:

1. Run against 3 clean Windows machines and 3 intentionally seeded lab machines.
2. Track false positives for each source: services, tasks, startup keys, recent files, logs.
3. Add an allowlist file only after the first false-positive pass.
4. Package as a signed release once the CLI output is stable and a Windows code-signing option is configured.

Near-term roadmap discipline:

1. Prioritize release trust and provenance before broadening detector coverage.
2. Add optional interoperable exports only after the core finding schema is stable.
3. Measure coverage with a seeded corpus and release scorecard before making broad efficacy claims.
4. Map evidence to ATT&CK and D3FEND only when the mapping is grounded in collected artifacts and rule logic.

See `docs/GAP_ADDENDUM.md` for the current gap addendum.

Implemented gap slices in `0.1.1`:

- Release provenance: workflow-generated checksums, manifest, and verification guide.
- Interoperability: optional mapped detection export.
- Coverage measurement: seeded eval corpus and scorecard.
- Operator mapping: evidence-to-rule-to-ATT&CK/D3FEND matrix.

## References

- CISA, NSA, and MS-ISAC advisory on malicious use of legitimate RMM software: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a
- CISA advisory on SimpleHelp RMM exploitation: https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-163a
- MITRE ATT&CK data sources for process, scheduled job, service, script, registry, and WMI evidence: https://attack.mitre.org/datasources/
