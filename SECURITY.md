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
- Watch Preview keeps read-only scanning as the default. Active Defense actions are optional, policy-gated, audited, and never delete files automatically in the first release.
- The scanner detects suspicious remote management tools and breach traces on Windows devices the user owns, administers, or has permission to inspect. It does not exploit systems, bypass security controls, attack services, or scan networks.
- The deterministic scanner verdict is the source of truth. Optional AI explanations cannot set or change `clean`, `needs_review`, or `high_risk`.
- AI Copilot for Watch can explain alerts, rank options, and choose only from pre-approved actions after deterministic policy gates. It cannot run arbitrary commands, create new actions, override severity or confidence, or bypass approval mode.
- Optional AI is off by default and only runs when the user configures a provider key or environment variable and clicks the AI button.
- Saved AI keys are stored under the local Windows profile and encrypted with Electron safe storage where available. They are never returned to the renderer after saving.
- If no AI key is configured, the app opens the AI settings panel and does not send report data to any provider.
- Raw reports can contain local usernames, paths, service data, process command lines, and event excerpts. Treat exported JSON/PDF reports as sensitive.
- The Electron renderer runs with context isolation, sandboxing, no Node integration, a restrictive CSP, and a narrow preload bridge.
- See `PRIVACY.md` for privacy handling and `docs/CODE_SIGNING_POLICY.md` for the signing policy.

## Watch Preview And Active Defense Controls

Watch Preview is designed for local monitoring and alerting, not breach prevention. It compares current scan evidence with a local checkpoint store, records alert history, and records action history.

Setup must ask before installing or enabling persistent helpers such as:

- a scheduled Watch task
- a service wrapper
- Sysmon or a Sysmon configuration
- Discord webhook alerting

RMM Hunter must not silently install helper services, bundle KAPE, bundle third-party tools, or enable persistent monitoring without user approval.

Response modes are security boundaries:

- `alert_only`: alert and record only.
- `approval_required`: default mode, requiring user approval before response.
- `daytime_auto`: limited soft containment during configured support hours.
- `night_auto`: guarded containment for high-confidence conditions outside configured support hours.

All response actions must pass deterministic policy gates before they are offered or run. Policy gates should check severity, confidence, evidence source, response mode, support-hours context, reversibility, and whether the action is allowlisted for that finding type.

Active response must be logged with timestamp, triggering alert, selected policy, selected mode, action attempted, result, and rollback guidance when available. First-release actions must avoid destructive deletion. If evidence preservation matters, collection and isolation should be preferred over removal.

## Release Security Checklist

Before publishing a release:

- Run `npm run release:verify`.
- Run `npm run dist` on Windows.
- Review `npm audit` and `pip-audit -r requirements-build.txt`.
- Smoke-test the generated installer and portable executable on a clean Windows VM.
- Run one elevated scan and one non-elevated scan.
- Confirm no raw report files are committed.
- Sign the Windows installer/executable before public distribution when a code-signing certificate is available.
