# Privacy Policy

RMM Hunter is a local Windows endpoint scanner. Its default scan mode runs on the device, writes reports locally, and does not upload scan evidence to MDP Studio or any other service.

## Data Collected Locally

Scan reports can include:

- Windows usernames and profile paths
- installed application names and publisher metadata
- Windows service names, executable paths, and signature summaries
- scheduled task names and actions
- startup registry entries
- recent installer and script filenames from Downloads and Temp paths
- Defender, PowerShell, Security, WMI, and service-install event excerpts where available
- Defender health and preference details, including security intelligence age and limited exclusion samples
- Windows code-signing validation results for known signed Windows binaries
- trusted root certificate store summaries and unusual root-certificate metadata where available
- command-line fragments from relevant event logs where available

Reports are written locally on the scanned device. In packaged desktop builds, reports are written under the per-user RMM Hunter profile in `%LOCALAPPDATA%\RMM Hunter\reports`.

## No Default Network Uploads

RMM Hunter does not transfer scan reports, artifacts, telemetry, analytics, or usage data to MDP Studio by default.

Do not publish or send raw scan reports unless you have reviewed them. They can contain sensitive local system details.

## Update Checks

The desktop app checks public GitHub Releases metadata to see whether a newer RMM Hunter version is available. This request does not include scan reports, artifacts, usernames, file paths, event logs, AI settings, or API keys.

If the installed Windows app downloads an update, it downloads the public release installer and update metadata from GitHub Releases. GitHub receives normal request metadata such as IP address, time, and user agent. Portable builds do not install updates automatically.

## Optional AI Recommendations

The AI recommendation feature is optional and off unless the user configures an AI provider key or matching environment variable and clicks the AI recommendation action.

If enabled, RMM Hunter sends a minimized and sanitized scan summary to the selected provider. The deterministic scanner verdict remains local rule output and is not set by AI.

Before sending an AI request, RMM Hunter strips or summarizes sensitive values such as full user paths, email addresses, long tokens, encoded blobs, and raw event payloads where possible.

Supported provider presets include:

- OpenAI
- OpenRouter
- Groq
- custom OpenAI-compatible endpoint

Provider API keys are stored under the local Windows profile and encrypted with Electron safe storage where available. Keys are not written to scan reports or exports.

Users are responsible for reviewing the privacy policy and data handling terms of any AI provider they configure.

## Security Reports

Do not send raw scan reports in public GitHub issues.

Security reports can be sent privately to:

```text
meidie@mdpstudio.com.au
```

Include only the minimum evidence needed to reproduce the issue.
