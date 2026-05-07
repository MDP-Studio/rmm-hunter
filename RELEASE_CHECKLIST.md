# Release Checklist

Use this checklist before creating a GitHub release.

## Version And Repo

- [ ] Confirm `package.json` version is correct.
- [ ] Confirm `CHANGELOG.md` has release notes for the version.
- [ ] Confirm maintainer and security contact details are current.
- [ ] Confirm GitHub remote is `https://github.com/MDP-Studio/rmm-hunter.git`.
- [ ] Confirm `LICENSE` and `package.json` both use Apache-2.0.
- [ ] Confirm no secrets or raw scan reports are tracked.

## Local Verification

- [ ] `npm ci`
- [ ] `python -m pip install -r requirements-build.txt`
- [ ] `npm run release:verify`
- [ ] `pip-audit -r requirements-build.txt`
- [ ] `npm run dist`

## Windows Smoke Test

- [ ] Install the NSIS build from `release/`.
- [ ] Launch RMM Hunter from Start Menu or installer finish screen.
- [ ] Run a non-elevated scan and confirm a report is generated under the app profile.
- [ ] Run an elevated scan and confirm extra event-log coverage where available.
- [ ] Export JSON and PDF.
- [ ] Confirm AI is disabled without a provider key.
- [ ] Confirm clicking AI Recommendations with no key opens AI settings and sends no report data.
- [ ] Confirm the AI panel does not change the deterministic verdict when a provider key is configured.
- [ ] Confirm saved AI keys are not shown in the UI, JSON report, or PDF export.
- [ ] Test the portable `.exe`.

## GitHub Release

- [ ] Commit all release files.
- [ ] Push to GitHub.
- [ ] Create a version tag, for example `v0.1.0`.
- [ ] Wait for the `Build Windows Release` workflow to finish.
- [ ] Download and smoke-test the workflow artifacts.
- [ ] Edit the draft GitHub release notes with known limitations.
- [ ] Publish the draft release.

## Known Limitations To Mention

- Windows-only MVP.
- Best scan coverage requires Administrator.
- No automatic remediation.
- AI explanations are optional, bring-your-own-key, and cloud-based when enabled unless a local custom endpoint is configured.
- Unsigned builds may trigger Windows SmartScreen until code signing is configured.
- Local unsigned builds skip Electron executable signing/editing to avoid symlink privilege failures on non-admin Windows sessions. Turn signing back on when a Windows code-signing certificate is available.
