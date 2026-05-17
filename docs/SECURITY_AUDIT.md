# Security Audit

Date: 2026-05-18

## Scope

Reviewed the RMM Hunter Windows MVP:

- Electron main, preload, renderer, HTML, and CSS under `gui/`
- Python analyzer in `rmm_hunter.py`
- PowerShell collector in `collect_windows.ps1`
- npm dependency tree
- release packaging path
- privacy and code-signing policy documentation
- roadmap gap documentation for release trust, interoperability, coverage measurement, and mapping
- mapped detection export, release verification manifest generation, and seeded corpus evaluation
- System Trust Health collection and reporting for Defender state, Windows Authenticode validation, and trusted root store signals
- RMM vendor log collection
- KAPE import mode
- evidence strength, confidence labels, and timeline reporting

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
- Finding review-action buttons only expand local guidance. They do not delete files, stop services, change settings, or execute remediation commands.
- System Trust Health checks are report-only. They collect Defender status, code-signing validation results, and trusted-root summaries, but do not repair certificates, modify exclusions, or change Defender settings.
- PDF report HTML escapes report fields and includes a restrictive CSP.
- Update checks and installer downloads run in the Electron main process through `electron-updater` and GitHub Releases metadata. The renderer CSP remains `connect-src 'none'`, no scan evidence is sent, and external opening is restricted to allowlisted RMM Hunter project links.
- Optional AI explanations are off by default, send only sanitized/minimized report data, enforce a payload cap, and cannot change the deterministic verdict.
- AI recommendation setup checks run before provider calls. If an API key is missing, the app shows local setup guidance and sends no report data to an AI provider.
- AI provider settings support OpenAI, OpenRouter, Groq, and custom OpenAI-compatible endpoints. Saved API keys are encrypted with Electron safe storage when available and are never returned to the renderer after saving.
- AI prompts receive extracted artifact context, not raw full logs, and are instructed to separate known evidence from unproven delivery source.
- AI prompts receive minimized System Trust Health context so recommendations can account for stale Defender intelligence, weak protections, broad exclusions, or broken signature validation without changing the deterministic verdict.
- Preset provider endpoints are fixed in application code so a modified settings file cannot redirect a saved preset-provider key to another host.
- AI endpoint validation requires HTTPS unless the endpoint is localhost.
- Python invokes the collector with an argument array, not shell string concatenation.
- PowerShell collector treats collected endpoint artifacts as data and does not execute them.
- RMM vendor log collection reads metadata and bounded tail samples only. It does not delete logs, stop agents, or contact vendor services.
- KAPE import mode reads bounded text-like output files and records source file and row context. It does not parse live disk images, mount evidence, or alter the KAPE collection.
- Timeline output is derived from collected report timestamps and does not run additional commands.
- Release builds bundle a PyInstaller scanner executable so the packaged Electron app does not require Python on the target endpoint.
- Packaged builds ignore developer scanner override environment variables and prefer the bundled scanner executable.
- Windows release builds use the tracked `gui/assets/icon.ico` instead of the default Electron icon.
- The per-user NSIS installer detects existing RMM Hunter installs from the current user's Electron Builder registry keys, reuses the existing install path during upgrades, preserves app data, and blocks older installers from downgrading newer installed versions.
- `PRIVACY.md` states that reports stay local by default and optional AI sends only sanitized summaries to the user-selected provider.
- `docs/CODE_SIGNING_POLICY.md` states that RMM Hunter detects breach traces and unauthorized remote management tools, and does not exploit systems, bypass controls, scan networks, delete files, stop services, or change Windows settings by default.
- The optional mapped export is derived from completed findings and does not feed back into verdict scoring.
- Evidence strength and confidence labels are explanatory fields. They do not change the deterministic verdict model.
- Release verification files include hashes, source SHA, workflow run URL, and Authenticode status so users can validate provenance.
- Local unsigned builds set `signAndEditExecutable` to `false` so non-admin Windows sessions do not fail while extracting Electron Builder code-signing helpers. Public releases should still be signed when a certificate is available.

## Dependency Notes

- `npm audit --audit-level=moderate` passed with 0 vulnerabilities after adding `electron-builder`.
- `npm audit --omit=dev --audit-level=moderate` passed with 0 vulnerabilities.
- Secret-pattern scan across source and docs found only documented API-key placeholder examples and runtime key-handling code, not a committed secret.
- `electron-builder` brings some deprecated transitive packages in the current npm tree. They are build-time dependencies and no vulnerability was reported by npm audit, but they should be watched during dependency updates.
- Build Python dependencies are pinned in `requirements-build.txt` and should be checked with `pip-audit -r requirements-build.txt` or `uvx pip-audit==2.10.0 -r requirements-build.txt`.
- `uvx pip-audit==2.10.0 -r requirements-build.txt` passed with no known vulnerabilities.
- `python scripts/evaluate_corpus.py --manifest tests/corpus/manifest.json` passed against the seeded corpus, 4/4 cases.
- System Trust Health smoke analysis confirmed Defender protections were enabled, security intelligence was recent, Windows code-signing validation passed for 3 known Windows binaries, and the trusted root store was readable on the test machine.

## Release Verification Performed

- `npm run release:verify` passed.
- `npm run dist` produced:
  - `release/RMM-Hunter-Setup-0.2.0-x64.exe`
  - `release/RMM-Hunter-Portable-0.2.0-x64.exe`
  - `release/RMM-Hunter-Setup-0.2.0-x64.exe.blockmap`
- The bundled scanner executable under `release/win-unpacked/resources/bin/rmm-hunter-cli.exe` successfully analyzed the AnyDesk connection-trace fixture.
- The CLI KAPE import smoke produced a `needs_review` report with `kape_execution_reference`.
- The PowerShell collector smoke produced schema `1.0` output and included the `rmm_vendor_logs` artifact key.
- The bundled scanner executable successfully analyzed a local trust-health smoke artifact and preserved the System Trust Health section in the text report.
- The unpacked packaged app launched and stayed alive.
- The portable executable launched and stayed alive.
- The NSIS installer silently upgraded the existing per-user install to `0.1.6`, preserved the install path, and kept reports/settings in the local app data directory.

## Release Risks

- Unsigned Windows builds can trigger SmartScreen. Add code signing before public distribution.
- Raw reports can contain sensitive local evidence. Keep `reports/` ignored and add a visible report-retention control in a future version.
- User-supplied AI keys are local machine secrets. Do not add an MDP Studio shared API key to public desktop builds.
- Administrator mode improves scan coverage, but the app intentionally requests `asInvoker` to avoid unnecessary privilege escalation.
- Electron Builder writes `builder-debug.yml`, `latest.yml`, and `win-unpacked` into `release/` for local debugging/update metadata. The GitHub workflow uploads `latest.yml` because installed builds need it for auto-update checks.
- Until code signing is configured, auto-update should be treated as beta-channel convenience rather than broad public trust. The updater relies on GitHub release provenance and Electron update integrity metadata, but Windows publisher trust still needs a signing certificate.
- Detection quality claims should stay tied to measured seeded-corpus results. `docs/GAP_ADDENDUM.md` tracks the eval harness and scorecard as follow-on work.
- Electron Builder emitted a Node deprecation warning from its packaging path about child process arguments with shell execution. Source search found no `shell: true` usage in RMM Hunter app or scripts. Keep watching this during Electron Builder updates.

## Commands

```powershell
npm run release:verify
npm audit --audit-level=moderate
pip-audit -r requirements-build.txt
uvx pip-audit==2.10.0 -r requirements-build.txt
python scripts/evaluate_corpus.py --manifest tests/corpus/manifest.json
npm run dist
```
