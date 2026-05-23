# App And Website Sync Rule

RMM Hunter has two public user-facing surfaces:

- The Windows desktop app and CLI in this repository.
- The public website at `https://rmmhunter.mdpstudio.com.au`.

Every app-facing change must include a website impact check before final delivery. The website does not need to change for every code commit, but agents must prove they checked whether it should.

## Required Rule

When changing the app, scanner, installer, release process, or docs that affect users, do one of the following before finishing:

- Update the website in the same branch or commit.
- State `Website impact: none` in the final answer or pull request summary, with a short reason.

Do not leave the website silently stale after changing product behavior, release status, screenshots, security boundaries, privacy behavior, AI behavior, Watch behavior, or download instructions.

## Changes That Usually Require Website Updates

Update the website when work changes any of these areas:

- App version, latest release, installer names, release links, release verification, or code-signing status.
- Desktop UI screenshots, hero mockups, feature screenshots, or visible app workflow.
- New or changed app features, especially Watch, active response, KAPE import, RMM vendor logs, system trust health, AI recommendations, update checks, PDF or JSON export, or evidence explanations.
- Security posture, privacy behavior, AI data handling, local storage, report contents, alert destinations, or active defense boundaries.
- Public positioning, tagline, LinkedIn copy, roadmap, donation copy, maintainer details, or support contact details.
- Website update-log content, including once-per-user notices for a new release or major website update.

## Changes That May Not Require Website Updates

The website can usually stay unchanged for:

- Internal refactors that do not change behavior or user-visible copy.
- Test-only changes.
- Fixture-only changes that do not change demonstrated coverage.
- Small bug fixes that do not affect public claims, screenshots, release notes, privacy, security, or download behavior.

Even then, record `Website impact: none` so reviewers can see that the check happened.

## Files To Check

App and release changes that should trigger a website review often touch:

- `gui/`
- `rmm_hunter.py`
- `collect_windows.ps1`
- `installer/`
- `package.json`
- `CHANGELOG.md`
- `README.md`
- `PRIVACY.md`
- `SECURITY.md`
- `RELEASE_CHECKLIST.md`
- `.github/workflows/`
- `docs/`

Website files live in:

- `website/index.html`
- `website/styles.css`
- `website/script.js`
- `website/assets/`
- `website/README.md`
- `website/Dockerfile`
- `website/nginx.conf`

## Website Update Checklist

Before finishing an app-facing change:

1. Search the website for stale version strings, feature names, screenshots, and claims.
2. Update website copy, links, screenshots, and release metadata when user-visible behavior changed.
3. If `website/styles.css` or `website/script.js` changes, update the query strings in `website/index.html`, such as `styles.css?v=<version>` or `script.js?v=<version>`, so browser caches refresh.
4. If the website update log should reappear for visitors, change the `data-update-log-id` value in `website/index.html`.
5. Keep website claims aligned with the app. Do not claim signed builds, automatic remediation, AI autonomy, platform support, or bundled forensic tools unless the repo actually ships that behavior.
6. Do not put private report data, usernames, local paths, API keys, webhook URLs, tokens, or customer details into website assets or screenshots.
7. If no website change is needed, write `Website impact: none` in the final answer or pull request summary.

Useful stale-copy checks:

```powershell
rg -n "v0\\.|Watch Preview|KAPE|AI|code signing|unsigned|download|release|RMM vendor logs|system trust" website
rg -n "0\\.1|0\\.2|old|TODO|placeholder" website
```

Adjust the search terms to match the feature being changed.

## Verification Checklist

For website changes, run the strongest practical checks before delivery:

```powershell
Set-Location "C:\Users\meidi\Documents\personal project\RMM Hunter"
git diff --check

Set-Location "C:\Users\meidi\Documents\personal project\RMM Hunter\website"
python -m http.server 8790
```

Then preview `http://127.0.0.1:8790/` in the in-app browser or Playwright. Check desktop and mobile widths when layout or screenshots change.

After deployment, verify the live site:

```powershell
$html = Invoke-WebRequest -Uri "https://rmmhunter.mdpstudio.com.au/" -UseBasicParsing
$html.StatusCode
$html.Content -match "v0.3.4"
```

Update the version check to the release being shipped. Also confirm old version strings are not still present when they should be gone.

## Deployment Notes

The website is a static site served from `website/`.

- Public site: `https://rmmhunter.mdpstudio.com.au`
- Deployment target: Coolify application on the always-on remote host
- Dockerfile: `website/Dockerfile`
- Health check path: `/healthz`

The deployment identifiers can drift, so verify before using them. Last known hints:

- Coolify app: `rmm-hunter-website`
- Resource UUID: `c14cncy42yibusgfawizd1kb`
- Remote host: `meidie@100.110.79.52`

Do not manually redeploy unless website files changed and the automatic deployment did not refresh. If manual deployment is needed, preserve the existing hostname, labels, health check, and static-site behavior.

## Safe Copy Boundaries

The website should clearly say that RMM Hunter:

- Detects suspicious RMM, living-off-the-land, DFIR artifact, and endpoint trust signals.
- Does not exploit systems.
- Does not delete files by default.
- Does not bypass security controls.
- Keeps AI optional and bring-your-own-key.
- Keeps active response policy-gated, audited, and non-deleting in the first active-defense release.
- Treats KAPE as an optional import source, not a bundled dependency or clone.

If the app behavior changes those boundaries, update the website, README, `PRIVACY.md`, and security docs together.
