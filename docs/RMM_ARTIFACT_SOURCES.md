# RMM Artifact Sources

This document defines the Windows evidence sources RMM Hunter should collect or import for remote access triage. The goal is to explain what each source can prove, how strong the evidence is, and what still needs analyst review.

RMM Hunter is non-remediating. These sources are used to report evidence, not to delete files, stop services, uninstall tools, or change system settings.

## Evidence Strength

| Strength | Meaning | Example |
| --- | --- | --- |
| Very strong | Strong evidence that a tool ran, connected, or was used. | AnyDesk `connection_trace.txt`, Prefetch execution evidence, Defender malware remediation event. |
| Strong | Strong evidence that a tool exists or persisted on the device. | RMM service, scheduled task, startup entry, Amcache or Shimcache reference. |
| Medium | Evidence that needs context before it is treated as suspicious. | Installer in Downloads, PowerShell download behavior, Defender configuration change. |
| Low | Useful timeline context, usually not enough by itself. | Routine Defender configuration hash changes or internal status events. |

Confidence is separate from severity. A finding can be high severity but lower confidence if the artifact is incomplete. A finding can be medium severity and high confidence if the artifact clearly shows a known RMM tool in a normal admin location.

## Native Windows Sources

| Source | What it answers | Useful fields | Evidence notes |
| --- | --- | --- | --- |
| Installed apps | Is a known RMM tool installed? | Display name, publisher, version, install path. | Good inventory evidence, but it does not prove recent use. |
| Services | Is an agent installed as a persistent service? | Service name, display name, executable path, start type, signer. | Strong evidence when the path or name matches an RMM tool. |
| Service install events | Was a service created recently? | Event ID `7045`, service name, image path, timestamp. | Very useful for timeline building. |
| Scheduled tasks | Is persistence configured through Task Scheduler? | Task name, action, author, enabled state. | Review user-writable paths and odd task names first. |
| Startup registry and folders | Will a tool launch at sign-in? | Key path, value name, command path. | Useful for persistence, especially under user profiles. |
| Recent installers and scripts | Did an RMM installer appear in Downloads or Temp? | File name, directory, timestamps, signer. | Medium evidence. It may only be a downloaded installer. |
| PowerShell logs | Was living-off-the-land behavior observed? | Event IDs, command text, script block text. | Review full command lines, user, timestamp, and parent process where available. |
| Process creation logs | Was `msiexec`, PowerShell, WMI, or a browser-launched installer observed? | Event ID `4688`, command line, parent process. | Coverage depends on Windows audit policy. |
| WMI Activity logs | Was WMI used for execution or persistence? | Client process ID, operation, user, namespace. | Correlate with process events when possible. |
| Defender events | Did Defender detect, remove, or block something? | Threat name, action, path, timestamp, security intelligence version. | High value, but still verify Protection History and affected paths. |
| Defender status | Are protections weakened? | Real-time protection, cloud protection, exclusions, intelligence age. | A configuration issue is not proof of compromise by itself. |
| Code-signing trust | Can Windows validate known signed files? | Authenticode status, signer, trust result. | Trust-health context for interpreting signed or unsigned binaries. |
| Trusted root store | Are unusual trusted roots present? | Subject, issuer, thumbprint, private key signal. | Review changes carefully. Do not remove certificates automatically. |

## RMM Vendor Log Sources

Vendor logs are valuable because they can show use, sessions, IDs, connection attempts, or service behavior that installed-app inventory cannot show. File locations vary by version and install mode, so missing logs do not prove a tool was never used.

| Tool | Common Windows locations to check | High-value files or names | What it may show |
| --- | --- | --- | --- |
| AnyDesk | `%ProgramData%\AnyDesk`, `%AppData%\AnyDesk` | `connection_trace.txt`, `ad_svc.trace`, `ad.trace` | Connection history, service activity, local AnyDesk ID context. |
| TeamViewer | `%ProgramFiles%\TeamViewer`, `%ProgramFiles(x86)%\TeamViewer`, `%ProgramData%\TeamViewer`, `%AppData%\TeamViewer` | `TeamViewer*.log`, `Connections*.txt` | Session and service activity depending on edition and logging settings. |
| ScreenConnect or ConnectWise Control | `%ProgramFiles%\ScreenConnect Client*`, `%ProgramData%\ScreenConnect Client*`, `%ProgramData%\ConnectWise*` | Client service logs, relay or session logs. | Client install, service startup, server or relay references. |
| SimpleHelp | `%ProgramFiles%\SimpleHelp*`, `%ProgramData%\SimpleHelp*`, `%AppData%\SimpleHelp*` | Agent or service logs. | Agent install and support-session context where logs exist. |
| RustDesk | `%AppData%\RustDesk`, `%ProgramData%\RustDesk` | `log\*.log`, config files. | Service, relay, ID, and session-adjacent activity. |
| Splashtop | `%ProgramData%\Splashtop`, `%ProgramFiles(x86)%\Splashtop`, `%AppData%\Splashtop` | Streamer and agent logs. | Streamer install, service activity, connection context. |
| Atera | `%ProgramFiles%\ATERA Networks\AteraAgent`, `%ProgramData%\ATERA Networks` | Agent logs. | MSP agent behavior, service activity, tenant or management context. |
| MeshAgent or MeshCentral | `%ProgramFiles%\Mesh Agent`, `%ProgramData%\Mesh Agent` | Mesh agent logs and config. | Agent identity, server, service activity, connection context. |
| Tactical RMM | Tactical agent folders under Program Files or ProgramData | Agent logs, service logs, config. | Agent install and management-server context. |
| DWAgent or DWService | `%ProgramFiles%\DWAgent`, `%ProgramData%\DWAgent` | `log\*.log` | Agent activity and connection context. |

## KAPE Import Mode

KAPE output should be treated as a separate imported evidence set, not as a live scan replacement. RMM Hunter should preserve where each imported row or text hit came from so an analyst can verify it in the original collection.

| KAPE artifact family | What it can add | Evidence strength |
| --- | --- | --- |
| Prefetch | Evidence that an executable likely ran on the device. | Very strong when the executable name matches an RMM tool. |
| Amcache | Evidence that Windows recorded file execution or program inventory metadata. | Strong to very strong depending on fields present. |
| Shimcache | Evidence that Windows observed an executable path. | Strong, but not always proof of execution. |
| SRUM | Network and application resource usage context. | Strong when it lines up with RMM process names and timestamps. |
| UserAssist | User-launched application evidence. | Strong when it names a known RMM executable. |
| Shellbags | Folder access context. | Medium, useful for user activity and timeline. |
| Event logs | Additional service, PowerShell, Defender, WMI, and process evidence. | Depends on event type. |
| Registry hives | Installed app, service, Run key, and user profile context. | Depends on key and value. |

Imported KAPE evidence should include:

- Source folder path.
- Relative source file path.
- Artifact family, such as Prefetch, Amcache, or event logs.
- Row number or line number when available.
- Short row context or sample text.
- Matched RMM tool name.
- Timestamp fields if the parsed output includes them.

## Interpretation Rules

- Do not treat one source as the whole story. Correlate install, persistence, execution, vendor logs, and Defender events.
- Prefer exact tool names, executable names, service names, and vendor-log files over broad keyword matches.
- Mark standard Program Files deployments as review items unless the surrounding timeline is suspicious.
- Raise priority when RMM evidence appears near Defender detections, encoded PowerShell, service creation, browser-launched installers, or WMI activity.
- Keep raw reports private. Paths, usernames, command lines, and event excerpts can expose sensitive information.
