# Detection Mapping

RMM Hunter keeps verdict calculation deterministic and local. The optional mapped export is for SOC and incident-response workflows that need portable evidence labels.

Generate it with:

```powershell
python .\rmm_hunter.py --input .\tests\sample_artifacts_high_risk.json --mapped-out .\reports\mapped.json
```

The mapped export uses profile:

```text
rmm-hunter.detection-mapping.v1
```

## Matrix

| Rule category | Evidence source | Severity behavior | ATT&CK mapping | D3FEND mapping |
| --- | --- | --- | --- | --- |
| `known_rmm_installed_app` | Installed programs | Medium, high if user-writable path | T1219 Remote Access Software | D3-PM Platform Monitoring |
| `known_rmm_service` | Services | Medium, high if user-writable path | T1219 Remote Access Software, T1543.003 Windows Service | D3-SBV Service Binary Verification |
| `service_from_user_writable_path` | Services | High | T1543.003 Windows Service | D3-SBV Service Binary Verification |
| `unsigned_nonstandard_service` | Services | Medium | T1543.003 Windows Service | D3-SBV Service Binary Verification |
| `recent_rmm_service_install` | Service install events | High | T1219 Remote Access Software, T1543.003 Windows Service | D3-SBV Service Binary Verification |
| `recent_service_install_from_suspicious_path` | Service install events | High | T1543.003 Windows Service | D3-SBV Service Binary Verification |
| `known_rmm_scheduled_task` | Scheduled tasks | Medium | T1219 Remote Access Software, T1053.005 Scheduled Task | D3-SJA Scheduled Job Analysis |
| `scheduled_task_from_suspicious_path` | Scheduled tasks | Medium | T1053.005 Scheduled Task | D3-SJA Scheduled Job Analysis |
| `known_rmm_startup_registry` | Startup registry | Medium | T1219 Remote Access Software, T1547.001 Registry Run Keys / Startup Folder | D3-PM Platform Monitoring |
| `startup_registry_suspicious_path` | Startup registry | Medium | T1547.001 Registry Run Keys / Startup Folder | D3-PM Platform Monitoring |
| `known_rmm_startup_folder` | Startup folders | Medium | T1219 Remote Access Software, T1547.001 Registry Run Keys / Startup Folder | D3-PM Platform Monitoring |
| `unsigned_startup_folder_item` | Startup folders | Low | T1547.001 Registry Run Keys / Startup Folder | D3-PM Platform Monitoring |
| `recent_remote_tool_file` | Recent files | Medium | T1219 Remote Access Software | D3-FA File Analysis |
| `rmm_vendor_log` | RMM vendor logs | Medium | T1219 Remote Access Software | D3-FA File Analysis |
| `rmm_connection_log` | RMM vendor connection logs | Medium | T1219 Remote Access Software | D3-FA File Analysis |
| `kape_rmm_reference` | Imported KAPE output | Medium | T1219 Remote Access Software | D3-PM Platform Monitoring |
| `kape_execution_reference` | Imported KAPE execution-style output | Medium | T1219 Remote Access Software, T1204.002 Malicious File | D3-PM Platform Monitoring |
| `odd_unsigned_recent_executable` | Recent files | Medium | T1027 Obfuscated Files or Information | D3-FA File Analysis |
| `encoded_powershell` | PowerShell events | High | T1059.001 PowerShell, T1027 Obfuscated Files or Information | D3-SEA Script Execution Analysis |
| `powershell_download_cradle` | PowerShell events | Medium | T1059.001 PowerShell | D3-SEA Script Execution Analysis |
| `powershell_policy_or_hidden_window` | PowerShell events | Medium | T1059.001 PowerShell | D3-SEA Script Execution Analysis |
| `powershell_policy_bypass_only` | PowerShell events | Low | T1059.001 PowerShell | D3-SEA Script Execution Analysis |
| `msiexec_from_browser_or_download_path` | Process creation events | Medium | T1218.007 Msiexec | D3-PA Process Analysis |
| `encoded_powershell_process` | Process creation events | High | T1059.001 PowerShell, T1027 Obfuscated Files or Information | D3-PA Process Analysis |
| `suspicious_wmi_activity` | WMI events | Medium | T1047 Windows Management Instrumentation | D3-PA Process Analysis |
| `defender_malware_event` | Defender events | High | Defensive event, no direct behavior technique assigned | D3-PM Platform Monitoring |
| `defender_sensitive_configuration_event` | Defender events | Medium | T1562.001 Disable or Modify Tools | D3-PM Platform Monitoring |
| `defender_routine_configuration_event` | Defender events | Low | Defensive timeline event, no direct behavior technique assigned | D3-PM Platform Monitoring |
| `defender_health_issue` | Defender status and preferences | Medium or high depending on protection impact | T1562.001 Disable or Modify Tools | D3-PM Platform Monitoring |
| `trust_validation_issue` | Windows Authenticode validation | High when known signed Windows binaries fail validation | Defensive trust-health event, no direct behavior technique assigned | D3-SBV Service Binary Verification |
| `trusted_root_store_issue` | Windows trusted root stores | Medium | T1553.004 Install Root Certificate | D3-PM Platform Monitoring |

## Interoperability Fields

Each mapped finding includes:

- `rule_id`: stable rule category from the deterministic report
- `plain_language` and `recommended_actions`: operator-facing guidance copied from the deterministic finding
- `mapping.attack.techniques`: ATT&CK technique IDs and names where grounded in collected evidence
- `mapping.attack.data_sources`: evidence data-source labels
- `mapping.d3fend`: defensive analysis concepts
- `interoperability.sigma_tags`: Sigma-style ATT&CK tags, for example `attack.t1219`
- `interoperability.stix_observable_hints`: STIX object hints, not a full STIX bundle
- `interoperability.misp_attribute_hints`: MISP attribute-type hints, not a full MISP event
- `timeline`: timestamped finding context from the source report when available

## Boundaries

The mapped export is not a SIEM connector, STIX bundle, MISP event, or Sigma rule pack yet. It is a stable bridge layer so those integrations can be added without changing scanner verdicts.

Do not add ATT&CK labels unless the rule has matching collected evidence.
