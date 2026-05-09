# Release Checklist

Use this checklist before creating a GitHub release.

## Version And Repo

- [ ] Confirm `package.json` version is correct.
- [ ] Confirm `CHANGELOG.md` has release notes for the version.
- [ ] Confirm maintainer and security contact details are current.
- [ ] Confirm GitHub remote is `https://github.com/MDP-Studio/rmm-hunter.git`.
- [ ] Confirm `LICENSE` and `package.json` both use Apache-2.0.
- [ ] Confirm `gui/assets/icon.ico` is present and referenced by `package.json`.
- [ ] Confirm `docs/CODE_SIGNING.md` reflects the current signing status.
- [ ] Confirm `docs/CODE_SIGNING_POLICY.md` reflects maintainer roles, signing scope, and SignPath status.
- [ ] Confirm `PRIVACY.md` reflects local report handling and optional AI provider data handling.
- [ ] Confirm System Trust Health wording explains Defender/trust confidence without promising automatic repair.
- [ ] Confirm `docs/GAP_ADDENDUM.md` reflects the current release-trust, interoperability, coverage, and mapping gaps.
- [ ] Confirm `docs/VERIFY_RELEASE.md`, `docs/DETECTION_MAPPING.md`, and `docs/COVERAGE_SCORECARD.md` are current.
- [ ] Confirm no secrets or raw scan reports are tracked.

## Local Verification

- [ ] `npm ci`
- [ ] `python -m pip install -r requirements-build.txt`
- [ ] `npm run release:verify`
- [ ] `pip-audit -r requirements-build.txt`
- [ ] `python scripts/evaluate_corpus.py --manifest tests/corpus/manifest.json`
- [ ] `npm run dist`

## Windows Smoke Test

- [ ] Install the NSIS build from `release/`.
- [ ] Launch RMM Hunter from Start Menu or installer finish screen.
- [ ] Run a non-elevated scan and confirm a report is generated under the app profile.
- [ ] Run an elevated scan and confirm extra event-log coverage where available.
- [ ] Export JSON and PDF.
- [ ] Confirm System Trust Health shows Defender, code-signing, and trusted-root checks without changing Windows settings.
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
- [ ] Confirm installer and portable artifacts show the RMM Hunter icon.
- [ ] Confirm release includes `SHA256SUMS.txt`, `rmm-hunter-release-manifest.json`, and `VERIFY_RELEASE.md`.
- [ ] Edit the draft GitHub release notes with known limitations.
- [ ] Include SHA256 hashes and Authenticode verification guidance beside release assets.
- [ ] For signed candidates, test SmartScreen, Defender, browser download, and installer friction on 3 clean Windows hosts.
- [ ] Publish the draft release.

## Known Limitations To Mention

- Windows-only MVP.
- Best scan coverage requires Administrator.
- No automatic remediation.
- AI explanations are optional, bring-your-own-key, and cloud-based when enabled unless a local custom endpoint is configured.
- Unsigned builds may trigger Windows SmartScreen until code signing is configured.
- Local unsigned builds skip Electron executable signing/editing to avoid symlink privilege failures on non-admin Windows sessions. Turn signing back on when a Windows code-signing certificate is available.
