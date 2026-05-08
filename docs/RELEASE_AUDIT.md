# Release Audit

Date: 2026-05-08

## Scope

This audit checked whether RMM Hunter is ready to publish as a GitHub Windows release.

Reviewed:

- Windows scanner CLI and collector
- Electron desktop app
- optional AI explanation path
- JSON/PDF export
- Windows icon and unsigned signing status
- dependency security
- privacy policy and SignPath-ready code-signing policy
- gap addendum for release trust, interoperability, coverage measurement, and ATT&CK/D3FEND mapping
- release verification assets, mapped detection export, seeded corpus eval, and mapping matrix
- GitHub Actions release workflow
- Windows installer, portable executable, and bundled scanner executable

## Release Readiness Result

RMM Hunter is ready for an unsigned public beta release after committing the current files, pushing a `v*` tag, and publishing the generated draft release as a prerelease.

The release is not ready for broad public trust until code signing is complete.

Target repository: `https://github.com/MDP-Studio/rmm-hunter`

## Build Artifacts Verified

Current local release artifacts:

- `release/RMM-Hunter-Setup-0.1.4-x64.exe`
- `release/RMM-Hunter-Setup-0.1.4-x64.exe.blockmap`
- `release/RMM-Hunter-Portable-0.1.4-x64.exe`

Electron Builder also creates local debug output:

- `release/win-unpacked/`
- `release/builder-debug.yml`
- `release/latest.yml`

The GitHub workflow uploads the setup executable, setup blockmap, portable executable, and `latest.yml` so installed NSIS builds can discover and download updates from GitHub Releases.

## Verification Matrix

| Check | Result | Notes |
| --- | --- | --- |
| JavaScript syntax | Pass | `gui` and `scripts` JS files checked with `node --check`. |
| Python compile | Pass | `python -m py_compile rmm_hunter.py`. |
| Unit tests | Pass | 4 tests passed. |
| npm audit | Pass | 0 vulnerabilities for all dependencies. |
| production npm audit | Pass | 0 vulnerabilities with `--omit=dev`. |
| Python build dependency audit | Pass | `pip-audit -r requirements-build.txt` found no known vulnerabilities. |
| seeded corpus evaluation | Pass | `scripts/evaluate_corpus.py` checks clean, needs-review, and high-risk seeded artifacts. |
| secret-pattern scan | Pass | Only documented API-key placeholder examples and runtime key-handling code were found outside ignored/generated folders. |
| PyInstaller scanner build | Pass | Bundled `rmm-hunter-cli.exe` created successfully. |
| Bundled scanner behavior | Pass | Packaged scanner analyzed the high-risk sample artifact successfully. |
| Electron Builder release build | Pass | Setup and portable Windows artifacts generated. |
| Unpacked packaged app launch | Pass | App launched and stayed alive. |
| Portable launch | Pass | Portable executable launched and stayed alive. |
| Installer smoke test | Pass | Silent temp install, clean app launch, uninstall, and cleanup all succeeded. |
| Authenticode signature | Expected fail | Artifacts are unsigned until a code-signing certificate is configured. |

## Release Blockers Found And Fixed

- Packaged app report path moved to `%LOCALAPPDATA%\RMM Hunter\reports` so installed builds do not write into the install directory.
- Packaged app now prefers `resources/bin/rmm-hunter-cli.exe`, so target machines do not need Python installed.
- Packaged app now ignores developer scanner override environment variables, reducing local process-hijack risk in installed builds.
- AI settings are now bring-your-own-key with OpenAI, OpenRouter, Groq, and custom OpenAI-compatible provider support. No-key clicks show a visible setup notice and send no report data.
- Feedback and About sections use main-process allowlisted external links for GitHub issues, the security policy, privacy policy, private email, and Buy Me a Coffee.
- Finding artifacts now include extracted PowerShell domains/URLs, Defender threat/action/result fields, affected resources, and Defender old/new setting values where available.
- Windows app and installer packaging now use `gui/assets/icon.ico`.
- Build now creates separate installer and portable filenames.
- Build now cleans stale release artifacts before packaging.
- PyInstaller now runs through `scripts/build-scanner.js` with absolute paths, avoiding fragile Windows quoting and spec-path behavior.
- The scanner build script now detects `.release-venv` or an explicit `RMM_HUNTER_PYINSTALLER` override before falling back to `python -m PyInstaller`.
- GitHub Actions Python setup now points pip caching at `requirements-build.txt`, matching this repo's build dependency file.
- GitHub Actions release packaging now runs clean, test, scanner build, and `npm run package:windows` as separate steps for clearer release failures.
- GitHub Actions captures Electron Builder packaging output into `package-windows.log`, uploads it for failed runs, and surfaces the tail if packaging fails.
- Electron Builder packaging now passes `--publish never`; draft GitHub release creation is handled by the explicit `gh release create` step.
- GitHub release workflow now refreshes existing draft release assets with `gh release upload --clobber`, but refuses to overwrite a published release.
- GitHub release workflow now uploads explicit artifact paths instead of relying on shell wildcard expansion.
- Local unsigned build avoids the Electron Builder symlink privilege failure encountered when extracting the Windows code-sign helper.
- `docs/CODE_SIGNING.md` now documents the unsigned status, future Microsoft Artifact Signing setup, and icon regeneration commands.
- `PRIVACY.md` now documents local report handling and optional AI provider data handling.
- `docs/CODE_SIGNING_POLICY.md` now documents the SignPath-ready signing policy, maintainer roles, signing scope, MFA expectation, release integrity gates, and security-tool scope.
- GitHub Actions now publishes `SHA256SUMS.txt`, `rmm-hunter-release-manifest.json`, and `VERIFY_RELEASE.md` beside Windows release assets.
- GitHub Actions now publishes `latest.yml` beside Windows release assets so installed builds can use the official GitHub release as the auto-update feed.
- The NSIS installer now detects existing installs, reuses the existing install path, shows an update/repair confirmation page, preserves local app data, and blocks obvious downgrades.
- The CLI now supports `--mapped-out` for profile `rmm-hunter.detection-mapping.v1`, preserving deterministic verdict behavior while adding portable detection labels.
- `scripts/evaluate_corpus.py` now runs a seeded corpus and fails the verification gate on verdict or expected-category regressions.
- `docs/DETECTION_MAPPING.md` and `docs/COVERAGE_SCORECARD.md` now document the mapping matrix and current seeded coverage scorecard.

## Residual Release Risks

- Windows artifacts are unsigned. Expect SmartScreen friction until SignPath Foundation, Microsoft Artifact Signing, or another trusted signing option is configured.
- GitHub MFA status cannot be verified through the current CLI response. The maintainer must confirm MFA in GitHub account settings before applying to SignPath.
- Release trust and provenance remain the biggest external trust gap. Do not prioritize new detector breadth ahead of signing, verification instructions, and clean-host friction testing.
- Detection interoperability, coverage measurement, and ATT&CK/D3FEND mapping are documented in `docs/GAP_ADDENDUM.md` as follow-on work after release trust.
- The current coverage scorecard is intentionally small. Treat it as a regression harness, not efficacy proof.
- Do not publish an app build that embeds an MDP Studio AI provider key. Desktop users should supply their own key unless a server-side paid AI service is added later.
- Source is licensed under Apache-2.0. The package remains `private` to prevent accidental npm publishing.
- Electron Builder currently includes deprecated transitive build-time packages, although `npm audit` reports no vulnerabilities.
- GitHub Actions are pinned to major versions of official actions, not immutable commit SHAs. Pin to SHAs if you want stricter supply-chain control.

## Commands Used

```powershell
npm run release:verify
npm audit --omit=dev --audit-level=moderate
uvx pip-audit==2.10.0 -r requirements-build.txt
python scripts/evaluate_corpus.py --manifest tests/corpus/manifest.json
npm run dist
```

Installer smoke test:

```powershell
release\RMM-Hunter-Setup-0.1.4-x64.exe /S /D=%TEMP%\RMMHunterInstallTest
```

## Next Release Steps

1. Publish the generated `v0.1.4` draft as an unsigned prerelease with clear SmartScreen wording and verification assets.
2. Confirm GitHub MFA is enabled for the maintainer account.
3. Apply to SignPath Foundation using the public repository, public release page, privacy policy, and code-signing policy.
4. After SignPath approval, add the SignPath GitHub Actions signing step and required repository secret.
5. Test one signed release candidate on 3 clean Windows hosts and record SmartScreen, Defender, browser, and installer friction.
6. Add interoperable output and coverage scorecards only after release provenance is fixed.
