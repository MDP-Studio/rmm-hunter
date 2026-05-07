# Security Audit

Date: 2026-05-07

## Scope

Reviewed the RMM Hunter Windows MVP:

- Electron main, preload, renderer, HTML, and CSS under `gui/`
- Python analyzer in `rmm_hunter.py`
- PowerShell collector in `collect_windows.ps1`
- npm dependency tree
- release packaging path

Excluded generated folders and local scan output:

- `node_modules/`
- `reports/`
- `build/`
- `release/`
- Python cache folders

## Result

No reportable security vulnerabilities were found in the application code after the hardening pass.

## Security Controls Verified

- Electron renderer uses context isolation, sandboxing, and no Node integration.
- Renderer navigation is locked to the local app file and popups are denied.
- The preload bridge exposes only scanner, export, AI explanation, and report reveal actions.
- Report reveal is restricted to the app reports directory.
- Renderer evidence and AI output are inserted as text nodes.
- PDF report HTML escapes report fields and includes a restrictive CSP.
- Optional AI explanations are off by default, send only sanitized/minimized report data, enforce a payload cap, and cannot change the deterministic verdict.
- AI provider settings support OpenAI, OpenRouter, Groq, and custom OpenAI-compatible endpoints. Saved API keys are encrypted with Electron safe storage when available and are never returned to the renderer after saving.
- Preset provider endpoints are fixed in application code so a modified settings file cannot redirect a saved preset-provider key to another host.
- AI endpoint validation requires HTTPS unless the endpoint is localhost.
- Python invokes the collector with an argument array, not shell string concatenation.
- PowerShell collector treats collected endpoint artifacts as data and does not execute them.
- Release builds bundle a PyInstaller scanner executable so the packaged Electron app does not require Python on the target endpoint.
- Packaged builds ignore developer scanner override environment variables and prefer the bundled scanner executable.
- Local unsigned builds set `signAndEditExecutable` to `false` so non-admin Windows sessions do not fail while extracting Electron Builder code-signing helpers. Public releases should still be signed when a certificate is available.

## Dependency Notes

- `npm audit --audit-level=moderate` passed with 0 vulnerabilities after adding `electron-builder`.
- `npm audit --omit=dev --audit-level=moderate` passed with 0 vulnerabilities.
- Secret-pattern scan across source and docs found only documented API-key placeholder examples and runtime key-handling code, not a committed secret.
- `electron-builder` brings some deprecated transitive packages in the current npm tree. They are build-time dependencies and no vulnerability was reported by npm audit, but they should be watched during dependency updates.
- Build Python dependencies are pinned in `requirements-build.txt` and should be checked with `pip-audit -r requirements-build.txt`.
- `pip-audit -r requirements-build.txt` passed with no known vulnerabilities.

## Release Verification Performed

- `npm run release:verify` passed.
- `npm run dist` produced:
  - `release/RMM-Hunter-Setup-0.1.0-x64.exe`
  - `release/RMM-Hunter-Portable-0.1.0-x64.exe`
  - `release/RMM-Hunter-Setup-0.1.0-x64.exe.blockmap`
- The bundled scanner executable under `release/win-unpacked/resources/bin/rmm-hunter-cli.exe` successfully analyzed the high-risk sample artifact.
- The unpacked packaged app launched and stayed alive.
- The portable executable launched and stayed alive.
- The NSIS installer silently installed to a temp directory, launched the app, found the uninstaller, uninstalled successfully, and removed the temp install directory.

## Release Risks

- Unsigned Windows builds can trigger SmartScreen. Add code signing before public distribution.
- Raw reports can contain sensitive local evidence. Keep `reports/` ignored and add a visible report-retention control in a future version.
- User-supplied AI keys are local machine secrets. Do not add an MDP Studio shared API key to public desktop builds.
- Administrator mode improves scan coverage, but the app intentionally requests `asInvoker` to avoid unnecessary privilege escalation.
- Electron Builder writes `builder-debug.yml`, `latest.yml`, and `win-unpacked` into `release/` for local debugging/update metadata. The GitHub workflow uploads only the setup executable, setup blockmap, and portable executable.

## Commands

```powershell
npm run release:verify
pip-audit -r requirements-build.txt
npm run dist
```
