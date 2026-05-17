# Coverage Scorecard

Date: 2026-05-18

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

## Current Result

| Metric | Value |
| --- | --- |
| Total cases | 4 |
| Passed cases | 4 |
| Exact verdict accuracy | 1.0 |
| Review-or-high precision | 1.0 |
| Review-or-high recall | 1.0 |

## Next Corpus Targets

- Clean Windows 11 desktop with no RMM tools.
- Clean Windows Server host with normal admin tooling.
- Authorized MSP-style Atera or ScreenConnect deployment under Program Files.
- KAPE Prefetch, Amcache, and Shimcache output with benign and suspicious RMM references.
- SimpleHelp-style recent service-install trace from public advisory patterns where safe to model.
- Browser-launched `msiexec` from Downloads with benign and suspicious variants.
- Defender configuration-change event with benign admin context.

Every release should state the corpus size and whether any rule changes moved precision, recall, false positives, or false negatives.
