# Coverage Scorecard

Date: 2026-07-14

This scorecard is a seeded regression check, not a claim of broad endpoint-security efficacy.

Run locally:

```powershell
python .\scripts\evaluate_corpus.py --manifest .\tests\corpus\manifest.json
```

## Current Seeded Corpus

| Case | Expected verdict | Purpose |
| --- | --- | --- |
| `clean-baseline` | `clean` | Empty clean artifact baseline. |
| `authorized-teamviewer-program-files` | `needs_review` | Known remote tool in a standard program path. |
| `anydesk-connection-trace` | `needs_review` | AnyDesk connection trace evidence from a vendor log location. |
| `high-risk-download-service-encoded-powershell` | `high_risk` | RMM service from Downloads plus encoded PowerShell. |
| `scheduled-task-persistence` | `needs_review` | Known RMM task under a user-writable path. |
| `startup-registry-persistence` | `needs_review` | Known RMM startup persistence under a temporary path. |
| `recent-remote-tool-download` | `needs_review` | Recently downloaded signed remote-access tool. |
| `defender-malware-event` | `high_risk` | Defender malware/remediation evidence. |
| `powershell-download` | `needs_review` | PowerShell download behavior. |
| `msiexec-browser-download` | `needs_review` | Browser-context MSI installation from Downloads. |
| `wmi-persistence` | `needs_review` | WMI event consumer persistence evidence. |
| `defender-sensitive-change` | `needs_review` | Security-sensitive Defender configuration change. |

## Current Result

| Metric | Value |
| --- | --- |
| Total cases | 12 |
| Passed cases | 12 |
| Exact verdict accuracy | 1.0 |
| Review-or-high precision | 1.0 |
| Review-or-high recall | 1.0 |

## Next Corpus Targets

- Clean Windows 11 desktop with no RMM tools.
- Clean Windows Server host with normal admin tooling.
- Authorized MSP-style Atera or ScreenConnect deployment under Program Files.
- KAPE Prefetch, Amcache, and Shimcache output with benign and suspicious RMM references.
- SimpleHelp-style recent service-install trace from public advisory patterns where safe to model.
- Benign variants for browser-launched `msiexec` and Defender configuration changes.

Every release should state the corpus size and whether any rule changes moved precision, recall, false positives, or false negatives.
