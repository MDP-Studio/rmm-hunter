# RMM Hunter Website

Static public website for RMM Hunter.

Primary URL target:

```text
https://rmmhunter.mdpstudio.com.au/
```

The site is intentionally static and dependency-free. It links to the public GitHub release assets, explains the scanner's trust boundaries, and avoids claiming code signing until signed builds are available.

The update-log notice is also static. It stores a local `rmm-hunter:update-log:*` flag in the visitor's browser so each update notice is only shown once per browser. Change the `data-update-log-id` value in `index.html` whenever the notice should appear again for a new release or major website update.

The download section surfaces the exact command from
`scripts/verify-published-release.ps1`. Keep its tag, signing status, and
publisher-identity wording synchronized with `docs/VERIFY_RELEASE.md` and the
actual GitHub release. Never change the site to claim a signed release until the
public verifier passes against signed artifacts.

When changing the desktop app, scanner, installer, release flow, security boundaries, privacy behavior, or public feature set, follow `docs/APP_WEBSITE_SYNC.md` from the repository root. App-facing changes must either update this website or explicitly record `Website impact: none`.

Local preview:

```powershell
Set-Location "C:\Users\meidi\Documents\personal project\RMM Hunter\website"
python -m http.server 8790
```

Deployment target:

- Coolify application on the always-on remote host.
- Cloudflare Tunnel public hostname under `mdpstudio.com.au`.
- Dockerfile: `website/Dockerfile`
- Exposed container port: `80`
- Health check path: `/healthz`

The previous Netlify site is retained as rollback only:

- Netlify site: `rmm-hunter-mdpstudio`
- Netlify site ID: `41cda6b8-85cb-4988-9d16-49bd4fa344a7`
- Netlify admin: `https://app.netlify.com/projects/rmm-hunter-mdpstudio`
