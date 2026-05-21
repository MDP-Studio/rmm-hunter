# Changelog

## Unreleased

- Added a brief Discord webhook setup guide to the Watch tab, README, Watch docs, and website copy.

## 0.3.1 - 2026-05-21

- Split the desktop workspace into Scan, Evidence, Timeline, Watch, Trust health, and Info tabs so new features do not crowd the main scan view.
- Combined the collapsed sidebar logo and expand/collapse control into one hoverable button.
- Updated the website and desktop update log for the tabbed workspace release.
- Added regression coverage for Discord webhook validation so alert destinations stay restricted to official Discord webhook URLs.

## 0.3.0 - 2026-05-21

- Added Watch Preview CLI commands for one-shot checks, continuous watch, scheduled-task install/remove, and dry-run/apply response actions.
- Added the desktop Watch panel for local policy editing, one-shot Watch checks, Discord webhook test alerts, and recent alert history.
- Documented the Watch Preview and Active Defense design, including local checkpoint, alert-history, and action-history storage.
- Documented hybrid monitoring with near-real-time delta checks, full reconciliation scans, and optional user-approved Sysmon support.
- Documented response modes for `alert_only`, default `approval_required`, `daytime_auto`, and `night_auto`.
- Documented AI Copilot boundaries, Discord webhook alerting, setup consent for helpers, and the first-release rule that response actions must not delete files automatically.

## 0.2.1 - 2026-05-21

- Changed the GUI review area so evidence cards and the timeline appear side by side on wide screens.
- Limited the timeline to the first few timestamped artifacts with a `Show more` control instead of rendering long event lists at once.
- Added a compact collapsible sidebar and removed the visible report-file path strip from the dashboard.
- Added a compact desktop evidence-source strip with optional KAPE folder import, so the GUI can merge KAPE output with the live Windows scan.
- Fixed scanner quality-gate logging so safe fallback paths are observable during development and release checks.

## 0.2.0 - 2026-05-18

- Added native RMM vendor log collection for common AnyDesk, TeamViewer, ScreenConnect, RustDesk, Splashtop, Atera, MeshAgent, and DWAgent paths.
- Added KAPE output import mode for RMM references from artifact collections, including CSV, TSV, text, log, and JSON-like output files.
- Added evidence strength and confidence labels to findings, mapped exports, text summaries, PDF reports, and GUI evidence cards.
- Added timestamped finding timelines to JSON, text, PDF, GUI, and AI-safe report summaries.
- Added RMM artifact source and investigation cheat-sheet documentation for vendor logs, KAPE evidence, and safe non-remediating triage.
- Added corpus and unit-test coverage for AnyDesk connection traces and KAPE-derived RMM evidence.

## 0.1.6 - 2026-05-13

- Polished the dashboard action area so `Scan this device` stays visually primary and update checking is smaller.
- Reframed the left sidebar entries as a non-clickable scan coverage checklist instead of navigation.
- Made the up-to-date notice more compact and changed its action to release notes.
- Improved PDF report pagination so major sections stay together when they fit and long evidence artifacts can split cleanly only when needed.

## 0.1.5 - 2026-05-09

- Added System Trust Health checks for Defender protection state, security intelligence age, broad exclusions, Windows code-signing validation, and trusted-root-store review.
- Added trust-health findings so weak Defender or Windows trust state is called out separately from RMM and malware evidence.
- Added GUI and PDF trust-health sections so users can see whether local security evidence is healthy, stale, weakened, or not collected.
- Updated AI sanitization and instructions so AI recommendations account for trust-health context without changing deterministic verdicts.

## 0.1.4 - 2026-05-08

- Added deterministic artifact context for PowerShell URLs/domains, Defender threat names, remediation actions, affected resources, and Defender setting old/new values.
- Updated AI instructions to explain exact artifact context when present and to separate known evidence from unknown delivery source.
- Expanded GUI and PDF evidence rows so the first artifact shows the most useful context before raw event excerpts.

## 0.1.3 - 2026-05-08

- Added an NSIS installer upgrade guard that detects an existing RMM Hunter install, reuses its install location, shows an update/repair confirmation page, preserves local app data, and blocks obvious downgrades.
- Added About and Feedback sections with allowlisted links for GitHub issues, the security policy, privacy policy, private email, and Buy Me a Coffee.
- Tuned Defender configuration grouping so internal notification keys such as `MpDisablePropBagNotification` stay in routine timeline context instead of being treated as protection changes.
- Moved generated AI explanations next to the summary action and kept no-key setup prompts visible beside the button.

## 0.1.2 - 2026-05-08

- Improved AI setup feedback so `AI Recommendations` visibly shows when an API key is needed and focuses the API key field.
- Evidence cards now wrap long paths, certificate subjects, and command fragments inside the card instead of stretching the dashboard.
- Added deterministic plain-English finding explanations and non-destructive review-action checklists to the GUI, JSON, text, PDF, and mapped exports.
- Split routine Defender configuration churn from security-sensitive Defender setting changes to reduce noisy medium findings.
- Suppressed RMM Hunter release-manifest PowerShell events from local developer scans.
- Added installer auto-update support through GitHub Releases, including update download, progress, and restart-to-install states for installed Windows builds.

## 0.1.1 - 2026-05-08

- Release verification assets generated by GitHub Actions: `SHA256SUMS.txt`, `rmm-hunter-release-manifest.json`, and `VERIFY_RELEASE.md`.
- Optional mapped detection export with rule IDs, ATT&CK/D3FEND mappings, Sigma-style tags, and STIX/MISP object hints.
- Seeded corpus evaluation harness and coverage scorecard.
- Evidence source to rule to ATT&CK/D3FEND mapping documentation.

## 0.1.0 - 2026-05-07

- Windows GUI for local RMM and living-off-the-land scanner.
- PowerShell collector for installed apps, services, scheduled tasks, startup entries, recent installers, Defender events, PowerShell logs, process creation logs, and WMI activity where available.
- Python rules engine with `clean`, `needs_review`, and `high_risk` verdicts.
- JSON, text, and PDF reporting.
- Deterministic next-step recommendations.
- Optional AI explanations with sanitized report data and no verdict authority.
- Bring-your-own-key AI provider settings for OpenAI, OpenRouter, Groq, and custom OpenAI-compatible endpoints.
- Privacy policy and SignPath-ready code signing policy.
- Gap addendum for release trust, interoperability, coverage measurement, and ATT&CK/D3FEND mapping.
- Custom Windows app icon and installer icon.
- Electron hardening: sandboxed renderer, context isolation, disabled Node integration, restrictive CSP, navigation blocking, and report-path restrictions.
- Windows release packaging through Electron Builder and bundled PyInstaller scanner executable.
