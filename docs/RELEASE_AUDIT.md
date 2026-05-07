# Release Audit

Date: 2026-05-07

## Scope

This audit checked whether RMM Hunter is ready to publish as a GitHub Windows release.

Reviewed:

- Windows scanner CLI and collector
- Electron desktop app
- optional AI explanation path
- JSON/PDF export
- dependency security
- GitHub Actions release workflow
- Windows installer, portable executable, and bundled scanner executable

## Release Readiness Result

RMM Hunter is ready for a draft GitHub release after committing the current files and pushing a `v*` tag.

The release is not ready for broad public trust until code signing and a public license decision are complete.

Target repository: `https://github.com/MDP-Studio/rmm-hunter`

## Build Artifacts Verified

Current local release artifacts:

- `release/RMM-Hunter-Setup-0.1.0-x64.exe`
- `release/RMM-Hunter-Setup-0.1.0-x64.exe.blockmap`
- `release/RMM-Hunter-Portable-0.1.0-x64.exe`

Electron Builder also creates local debug output:

- `release/win-unpacked/`
- `release/builder-debug.yml`
- `release/latest.yml`

The GitHub workflow uploads only the setup executable, setup blockmap, and portable executable.

## Verification Matrix

| Check | Result | Notes |
| --- | --- | --- |
| JavaScript syntax | Pass | `gui` and `scripts` JS files checked with `node --check`. |
| Python compile | Pass | `python -m py_compile rmm_hunter.py`. |
| Unit tests | Pass | 4 tests passed. |
| npm audit | Pass | 0 vulnerabilities for all dependencies. |
| production npm audit | Pass | 0 vulnerabilities with `--omit=dev`. |
| Python build dependency audit | Pass | `pip-audit -r requirements-build.txt` found no known vulnerabilities. |
| secret-pattern scan | Pass | Only the documented `OPENAI_API_KEY` placeholder example was found outside ignored/generated folders. |
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
- Build now creates separate installer and portable filenames.
- Build now cleans stale release artifacts before packaging.
- PyInstaller now runs through `scripts/build-scanner.js` with absolute paths, avoiding fragile Windows quoting and spec-path behavior.
- The scanner build script now detects `.release-venv` or an explicit `RMM_HUNTER_PYINSTALLER` override before falling back to `python -m PyInstaller`.
- GitHub Actions Python setup now points pip caching at `requirements-build.txt`, matching this repo's build dependency file.
- GitHub Actions release packaging now runs clean, test, scanner build, and `npm run package:windows` as separate steps for clearer release failures.
- GitHub Actions captures Electron Builder packaging output into `package-windows.log`, uploads it for failed runs, and surfaces the tail if packaging fails.
- Electron Builder packaging now passes `--publish never`; draft GitHub release creation is handled by the explicit `gh release create` step.
- GitHub release workflow now uploads explicit artifact paths instead of relying on shell wildcard expansion.
- Local unsigned build avoids the Electron Builder symlink privilege failure encountered when extracting the Windows code-sign helper.

## Residual Release Risks

- Windows artifacts are unsigned. Expect SmartScreen friction until code signing is configured.
- The app still uses the default Electron executable icon in packaged builds. Add a Windows `.ico` before a polished public release.
- The package is marked `UNLICENSED`. Choose a license before making the repository public.
- Electron Builder currently includes deprecated transitive build-time packages, although `npm audit` reports no vulnerabilities.
- GitHub Actions are pinned to major versions of official actions, not immutable commit SHAs. Pin to SHAs if you want stricter supply-chain control.

## Commands Used

```powershell
npm run release:verify
npm audit --omit=dev --audit-level=moderate
.\.release-venv\Scripts\pip-audit.exe -r requirements-build.txt
npm run dist
```

Installer smoke test:

```powershell
release\RMM-Hunter-Setup-0.1.0-x64.exe /S /D=%TEMP%\RMMHunterInstallTest
```

## Next Release Steps

1. Decide public license.
2. Add a proper `.ico` app icon.
3. Configure Windows code signing.
4. Commit the release-ready files.
5. Push to GitHub.
6. Create and push `v0.1.0`.
7. Let `.github/workflows/release.yml` create the draft release.
8. Download and smoke-test the GitHub-built artifacts before publishing.
