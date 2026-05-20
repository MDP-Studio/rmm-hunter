# RMM Hunter Website

Static public website for RMM Hunter.

Primary URL target:

```text
https://rmmhunter.mdpstudio.com.au/
```

The site is intentionally static and dependency-free. It links to the public GitHub release assets, explains the scanner's trust boundaries, and avoids claiming code signing until signed builds are available.

The update-log notice is also static. It stores a local `rmm-hunter:update-log:*` flag in the visitor's browser so each update notice is only shown once per browser. Change the `data-update-log-id` value in `index.html` whenever the notice should appear again for a new release or major website update.

Local preview:

```powershell
Set-Location "C:\Users\meidi\Documents\personal project\RMM Hunter\website"
python -m http.server 8790
```

Deployment target:

- Netlify static deploy from this `website` folder.
- Cloudflare DNS-only CNAME under `mdpstudio.com.au`.
- Netlify site: `rmm-hunter-mdpstudio`
- Netlify site ID: `41cda6b8-85cb-4988-9d16-49bd4fa344a7`
- Netlify admin: `https://app.netlify.com/projects/rmm-hunter-mdpstudio`
