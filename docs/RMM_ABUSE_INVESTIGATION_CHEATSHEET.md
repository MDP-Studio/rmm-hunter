# RMM Abuse Investigation Cheat Sheet

This is a practical workflow for reviewing an RMM Hunter report. It is designed for safe triage after a support scam, MSP handover, suspicious remote session, or endpoint incident.

RMM Hunter does not exploit systems, scan the network, delete files, stop services, quarantine artifacts, or bypass security. Treat it as an evidence organizer and second-opinion scanner.

## 1. Preserve The Report

- Export the JSON report for technical review.
- Export the PDF report for a non-technical handoff.
- Keep the raw collector artifacts if they are available.
- Do not clear logs or delete installers before the timeline is understood.
- Do not post raw reports publicly. Reports may contain usernames, local paths, command lines, event excerpts, and security-product details.

## 2. Read The Verdict Correctly

| Verdict | Meaning | What to do first |
| --- | --- | --- |
| `clean` | No known RMM or suspicious living-off-the-land indicators were found in collected sources. | Treat it as limited reassurance, not proof the endpoint is safe. |
| `needs_review` | Legitimate but sensitive artifacts were found. | Confirm whether each remote tool, service, task, or script was expected. |
| `high_risk` | Evidence is hard to justify without known admin activity or an incident. | Preserve evidence, build a timeline, and escalate if the activity is not recognized. |

## 3. Check Evidence Strength And Confidence

Start with findings that have high severity, very strong evidence, or high confidence.

Useful priority order:

1. Defender malware detections or remediation events.
2. RMM services, scheduled tasks, or startup entries.
3. Vendor logs that show sessions, connection traces, IDs, or relay activity.
4. KAPE execution evidence such as Prefetch, Amcache, Shimcache, SRUM, or UserAssist.
5. PowerShell, `msiexec`, WMI, or process events near the same timestamps.
6. Recent installers in Downloads, Temp, or another user-writable path.
7. Defender configuration and trust-health changes.

Severity answers "how serious if true." Confidence answers "how much the artifact supports the finding."

## 4. Build A Timeline

Use the report timeline if present. If no timeline view exists, build one manually from:

- File creation and last-write times.
- Service creation event ID `7045`.
- Scheduled task registration or action timestamps.
- PowerShell Operational events and Windows PowerShell events.
- Process creation event ID `4688` when available.
- Defender detection, remediation, and configuration-change events.
- RMM vendor log timestamps.
- KAPE timestamps from Prefetch, Amcache, SRUM, event logs, and registry-derived output.

Timeline questions:

- What happened first?
- Did a browser download or email event happen before the installer?
- Did PowerShell, `msiexec`, WMI, or a scheduled task appear near the RMM activity?
- Did Defender detect or remove anything around the same time?
- Did protection settings or exclusions change before or after the suspicious activity?
- Was the activity during normal admin hours or outside expected support windows?

## 5. Confirm Authorization

For every RMM tool or remote-access artifact, confirm:

- Who requested the session.
- Who approved the session.
- Which IT provider or vendor performed it.
- Whether the tool is still required.
- Whether the device owner remembers the installer, prompt, or support call.
- Whether the account, tenant, or server ID matches the expected provider.

Do not assume that a valid signature or known vendor name means the activity was authorized.

## 6. Review Vendor Logs

Vendor logs can be stronger than installed-app inventory because they may show actual use.

For AnyDesk, review `connection_trace.txt` and service trace files where present. For other RMM tools, review agent logs, streamer logs, service logs, and config files under Program Files, ProgramData, and the user profile.

Look for:

- Connection timestamps.
- Remote IDs, aliases, tenant IDs, relay hosts, or server URLs.
- Repeated connection attempts.
- Service start and stop activity.
- Account or user context.
- Logs that stop suddenly or appear to be missing.

If logs are missing, record that as a limitation instead of treating it as clean evidence.

## 7. Use KAPE Import Mode Safely

KAPE collections can strengthen the investigation when live logs are missing, deleted, or incomplete. Use KAPE import mode to bring parsed artifact output into the same RMM Hunter evidence model.

Recommended imported sources:

- Prefetch for execution evidence.
- Amcache and Shimcache for executable path history.
- SRUM for application and network usage context.
- UserAssist for user-launched program evidence.
- Shellbags for folder access context.
- Event logs for service, PowerShell, WMI, process, and Defender events.
- Registry-derived output for uninstall keys, services, Run keys, and user profile traces.

When reviewing imported evidence:

- Keep the original KAPE collection intact.
- Record the source file and row number.
- Validate high-impact findings in the original artifact when possible.
- Do not mix imported evidence with live collection without labeling the source.

## 8. Decide Next Actions

Safe triage actions:

- Preserve reports and logs.
- Run a Microsoft Defender full scan.
- Use Microsoft Defender Offline if detections recur or the endpoint behaves strangely.
- Confirm remote tools with the expected IT provider.
- Review services, scheduled tasks, startup entries, and installed apps.
- Check browser downloads and recent files around the same timestamps.
- Rotate passwords and API keys if credential stores, browsers, cloud config, or developer folders were involved.
- Isolate the device from the network if there is active malware, unknown remote access, credential theft, or suspicious lateral movement.

Actions to avoid during first triage:

- Do not delete installers before documenting the timeline.
- Do not uninstall a tool before confirming whether it is the only evidence of access.
- Do not clear event logs.
- Do not remove trusted root certificates automatically.
- Do not publish raw JSON or screenshots with paths, users, tokens, or event excerpts.

## 9. Report The Finding

A good handoff should include:

- Verdict and risk score.
- Findings grouped by severity.
- Evidence strength and confidence.
- Timeline of key events.
- Confirmed authorized activity.
- Unknown or disputed activity.
- Defender threat names and actions.
- RMM vendor log references.
- KAPE source references where used.
- Clear limitations, such as missing process logging or unavailable PowerShell logs.
- Recommended next steps with owner and priority.

Keep the language evidence-based. Say "observed," "reported," "matches," or "needs review" instead of claiming compromise when the artifacts do not prove it.
