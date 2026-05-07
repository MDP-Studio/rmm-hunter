# Security Policy

## Supported Versions

RMM Hunter is pre-1.0. Security fixes are applied to the latest released version only.

## Reporting A Vulnerability

Do not open a public issue with raw scan reports, usernames, paths, event excerpts, API keys, or other sensitive local evidence.

Report vulnerabilities privately to `meidie@mdpstudio.com.au`. Include:

- affected version or commit
- affected file and function when known
- reproduction steps
- expected impact
- whether the issue can expose report data, execute code, change a verdict, or send data off-device

## Security Design

- The scanner is read-only by default. It does not delete files, stop services, uninstall tools, quarantine artifacts, or change Windows settings.
- The scanner detects suspicious remote management tools and breach traces on Windows devices the user owns, administers, or has permission to inspect. It does not exploit systems, bypass security controls, attack services, or scan networks.
- The deterministic scanner verdict is the source of truth. Optional AI explanations cannot set or change `clean`, `needs_review`, or `high_risk`.
- Optional AI is off by default and only runs when the user configures a provider key or environment variable and clicks the AI button.
- Saved AI keys are stored under the local Windows profile and encrypted with Electron safe storage where available. They are never returned to the renderer after saving.
- If no AI key is configured, the app opens the AI settings panel and does not send report data to any provider.
- Raw reports can contain local usernames, paths, service data, process command lines, and event excerpts. Treat exported JSON/PDF reports as sensitive.
- The Electron renderer runs with context isolation, sandboxing, no Node integration, a restrictive CSP, and a narrow preload bridge.
- See `PRIVACY.md` for privacy handling and `docs/CODE_SIGNING_POLICY.md` for the signing policy.

## Release Security Checklist

Before publishing a release:

- Run `npm run release:verify`.
- Run `npm run dist` on Windows.
- Review `npm audit` and `pip-audit -r requirements-build.txt`.
- Smoke-test the generated installer and portable executable on a clean Windows VM.
- Run one elevated scan and one non-elevated scan.
- Confirm no raw report files are committed.
- Sign the Windows installer/executable before public distribution when a code-signing certificate is available.
