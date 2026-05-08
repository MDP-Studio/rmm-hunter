#!/usr/bin/env python3
"""RMM Hunter CLI.

Collects Windows artifacts with PowerShell, then applies local triage rules.
The analyzer is intentionally conservative: it reports evidence and risk, but
does not claim to know whether a remote management tool is authorized.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCANNER_VERSION = "0.1.2"

REMOTE_TOOLS: dict[str, tuple[str, ...]] = {
    "ScreenConnect / ConnectWise Control": (
        "screenconnect",
        "connectwise control",
        "connectwisecontrol",
        "screenconnect.clientservice",
        "connectwisecontrol.client",
    ),
    "SimpleHelp": (
        "simplehelp",
        "simple-help",
    ),
    "AnyDesk": (
        "anydesk",
        "anydesk.exe",
    ),
    "TeamViewer": (
        "teamviewer",
        "teamviewer.exe",
        "teamviewer_service",
    ),
    "MeshAgent / MeshCentral": (
        "meshagent",
        "mesh agent",
        "meshcentral",
    ),
    "Tactical RMM": (
        "tacticalrmm",
        "tactical rmm",
        "trmm",
    ),
    "Atera": (
        "ateraagent",
        "atera agent",
        "atera networks",
        "atera",
    ),
    "Splashtop": (
        "splashtop",
        "srservice",
        "srmanager",
        "splashtopremote",
        "splashtop streamer",
    ),
    "RustDesk": (
        "rustdesk",
        "rustdesk.exe",
    ),
    "DWAgent / DWService": (
        "dwagent",
        "dwservice",
        "dwservice.exe",
    ),
}

SUSPICIOUS_PATH_MARKERS = (
    "\\downloads\\",
    "\\appdata\\local\\temp\\",
    "\\windows\\temp\\",
    "\\temp\\",
    "\\temporary internet files\\",
    "\\appdata\\local\\microsoft\\windows\\inetcache\\",
)

STANDARD_PROGRAM_PATHS = (
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "c:\\windows\\",
)

ENCODED_POWERSHELL_PATTERNS = (
    "-encodedcommand",
    " encodedcommand ",
    " -enc ",
    " -enco ",
    "frombase64string",
    "[convert]::frombase64string",
)

POWERSHELL_DOWNLOAD_PATTERNS = (
    "invoke-webrequest",
    " iwr ",
    "downloadstring",
    "new-object net.webclient",
    "start-bitstransfer",
    "bitsadmin",
)

POWERSHELL_BYPASS_PATTERNS = (
    "executionpolicy bypass",
    " -ep bypass",
    " -nop ",
    " -windowstyle hidden",
    " -window hidden",
)

MSIEXEC_TERMS = (
    "msiexec",
    "msiexec.exe",
)

BROWSER_TERMS = (
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
)

WMI_SUSPICIOUS_TERMS = (
    "__eventfilter",
    "commandlineeventconsumer",
    "activescripteventconsumer",
    "__filtertoconsumerbinding",
    "wmic ",
)

SELF_EVENT_TERMS = (
    "collect_windows.ps1",
    "rmm_hunter.py",
    "rmm_hunter_artifacts",
    "rmm hunter windows collector",
    "generate-release-manifest.ps1",
)

DEFENDER_HIGH_RISK_IDS = {1116, 1117, 1118, 1119, 1121, 1122}
DEFENDER_CONFIG_IDS = {5001, 5004, 5007, 5013}
DEFENDER_SENSITIVE_CONFIG_TERMS = (
    "disable",
    "exclusion",
    "\\exclusions\\",
    "realtime",
    "real-time",
    "tamper",
    "puaprotection",
    "spynetreporting",
    "submitsamplesconsent",
    "cloudblocklevel",
    "controlledfolderaccess",
    "disableantispyware",
)

SEVERITY_SCORE = {
    "high": 45,
    "medium": 20,
    "low": 5,
}

RULE_MAPPINGS: dict[str, dict[str, Any]] = {
    "known_rmm_installed_app": {
        "attack": {
            "techniques": [{"id": "T1219", "name": "Remote Access Software"}],
            "data_sources": ["Software: Software Discovery"],
        },
        "d3fend": [{"id": "D3-PM", "name": "Platform Monitoring"}],
    },
    "known_rmm_service": {
        "attack": {
            "techniques": [
                {"id": "T1219", "name": "Remote Access Software"},
                {"id": "T1543.003", "name": "Windows Service"},
            ],
            "data_sources": ["Service: Service Metadata", "Process: Process Metadata"],
        },
        "d3fend": [{"id": "D3-SBV", "name": "Service Binary Verification"}],
    },
    "service_from_user_writable_path": {
        "attack": {
            "techniques": [{"id": "T1543.003", "name": "Windows Service"}],
            "data_sources": ["Service: Service Metadata", "File: File Metadata"],
        },
        "d3fend": [{"id": "D3-SBV", "name": "Service Binary Verification"}],
    },
    "unsigned_nonstandard_service": {
        "attack": {
            "techniques": [{"id": "T1543.003", "name": "Windows Service"}],
            "data_sources": ["Service: Service Metadata", "File: File Metadata"],
        },
        "d3fend": [{"id": "D3-SBV", "name": "Service Binary Verification"}],
    },
    "recent_rmm_service_install": {
        "attack": {
            "techniques": [
                {"id": "T1219", "name": "Remote Access Software"},
                {"id": "T1543.003", "name": "Windows Service"},
            ],
            "data_sources": ["Service: Service Creation", "Windows Event Log: Windows Event Log Entry"],
        },
        "d3fend": [{"id": "D3-SBV", "name": "Service Binary Verification"}],
    },
    "recent_service_install_from_suspicious_path": {
        "attack": {
            "techniques": [{"id": "T1543.003", "name": "Windows Service"}],
            "data_sources": ["Service: Service Creation", "File: File Metadata"],
        },
        "d3fend": [{"id": "D3-SBV", "name": "Service Binary Verification"}],
    },
    "known_rmm_scheduled_task": {
        "attack": {
            "techniques": [
                {"id": "T1219", "name": "Remote Access Software"},
                {"id": "T1053.005", "name": "Scheduled Task"},
            ],
            "data_sources": ["Scheduled Job: Scheduled Job Metadata"],
        },
        "d3fend": [{"id": "D3-SJA", "name": "Scheduled Job Analysis"}],
    },
    "scheduled_task_from_suspicious_path": {
        "attack": {
            "techniques": [{"id": "T1053.005", "name": "Scheduled Task"}],
            "data_sources": ["Scheduled Job: Scheduled Job Metadata", "File: File Metadata"],
        },
        "d3fend": [{"id": "D3-SJA", "name": "Scheduled Job Analysis"}],
    },
    "known_rmm_startup_registry": {
        "attack": {
            "techniques": [
                {"id": "T1219", "name": "Remote Access Software"},
                {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder"},
            ],
            "data_sources": ["Windows Registry: Windows Registry Key Modification"],
        },
        "d3fend": [{"id": "D3-PM", "name": "Platform Monitoring"}],
    },
    "startup_registry_suspicious_path": {
        "attack": {
            "techniques": [{"id": "T1547.001", "name": "Registry Run Keys / Startup Folder"}],
            "data_sources": ["Windows Registry: Windows Registry Key Modification", "File: File Metadata"],
        },
        "d3fend": [{"id": "D3-PM", "name": "Platform Monitoring"}],
    },
    "known_rmm_startup_folder": {
        "attack": {
            "techniques": [
                {"id": "T1219", "name": "Remote Access Software"},
                {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder"},
            ],
            "data_sources": ["File: File Metadata"],
        },
        "d3fend": [{"id": "D3-PM", "name": "Platform Monitoring"}],
    },
    "unsigned_startup_folder_item": {
        "attack": {
            "techniques": [{"id": "T1547.001", "name": "Registry Run Keys / Startup Folder"}],
            "data_sources": ["File: File Metadata"],
        },
        "d3fend": [{"id": "D3-PM", "name": "Platform Monitoring"}],
    },
    "recent_remote_tool_file": {
        "attack": {
            "techniques": [{"id": "T1219", "name": "Remote Access Software"}],
            "data_sources": ["File: File Creation", "File: File Metadata"],
        },
        "d3fend": [{"id": "D3-FA", "name": "File Analysis"}],
    },
    "odd_unsigned_recent_executable": {
        "attack": {
            "techniques": [{"id": "T1027", "name": "Obfuscated Files or Information"}],
            "data_sources": ["File: File Metadata"],
        },
        "d3fend": [{"id": "D3-FA", "name": "File Analysis"}],
    },
    "encoded_powershell": {
        "attack": {
            "techniques": [
                {"id": "T1059.001", "name": "PowerShell"},
                {"id": "T1027", "name": "Obfuscated Files or Information"},
            ],
            "data_sources": ["Script: Script Execution", "Windows Event Log: Windows Event Log Entry"],
        },
        "d3fend": [{"id": "D3-SEA", "name": "Script Execution Analysis"}],
    },
    "powershell_download_cradle": {
        "attack": {
            "techniques": [{"id": "T1059.001", "name": "PowerShell"}],
            "data_sources": ["Script: Script Execution", "Network Traffic: Network Connection Creation"],
        },
        "d3fend": [{"id": "D3-SEA", "name": "Script Execution Analysis"}],
    },
    "powershell_policy_or_hidden_window": {
        "attack": {
            "techniques": [{"id": "T1059.001", "name": "PowerShell"}],
            "data_sources": ["Script: Script Execution", "Process: Process Creation"],
        },
        "d3fend": [{"id": "D3-SEA", "name": "Script Execution Analysis"}],
    },
    "msiexec_from_browser_or_download_path": {
        "attack": {
            "techniques": [{"id": "T1218.007", "name": "Msiexec"}],
            "data_sources": ["Process: Process Creation", "Command: Command Execution"],
        },
        "d3fend": [{"id": "D3-PA", "name": "Process Analysis"}],
    },
    "encoded_powershell_process": {
        "attack": {
            "techniques": [
                {"id": "T1059.001", "name": "PowerShell"},
                {"id": "T1027", "name": "Obfuscated Files or Information"},
            ],
            "data_sources": ["Process: Process Creation", "Command: Command Execution"],
        },
        "d3fend": [{"id": "D3-PA", "name": "Process Analysis"}],
    },
    "suspicious_wmi_activity": {
        "attack": {
            "techniques": [{"id": "T1047", "name": "Windows Management Instrumentation"}],
            "data_sources": ["WMI: WMI Creation", "Process: Process Creation"],
        },
        "d3fend": [{"id": "D3-PA", "name": "Process Analysis"}],
    },
    "defender_malware_event": {
        "attack": {
            "techniques": [],
            "data_sources": ["Malware Repository: Malware Metadata", "Windows Event Log: Windows Event Log Entry"],
        },
        "d3fend": [{"id": "D3-PM", "name": "Platform Monitoring"}],
    },
    "defender_configuration_event": {
        "attack": {
            "techniques": [{"id": "T1562.001", "name": "Disable or Modify Tools"}],
            "data_sources": ["Sensor Health: Host Status", "Windows Event Log: Windows Event Log Entry"],
        },
        "d3fend": [{"id": "D3-PM", "name": "Platform Monitoring"}],
    },
    "defender_sensitive_configuration_event": {
        "attack": {
            "techniques": [{"id": "T1562.001", "name": "Disable or Modify Tools"}],
            "data_sources": ["Sensor Health: Host Status", "Windows Event Log: Windows Event Log Entry"],
        },
        "d3fend": [{"id": "D3-PM", "name": "Platform Monitoring"}],
    },
    "defender_routine_configuration_event": {
        "attack": {
            "techniques": [],
            "data_sources": ["Sensor Health: Host Status", "Windows Event Log: Windows Event Log Entry"],
        },
        "d3fend": [{"id": "D3-PM", "name": "Platform Monitoring"}],
    },
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=False)
        handle.write("\n")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def deep_values(value: Any) -> Iterable[str]:
    if value is None:
        return
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, (int, float, bool)):
        yield str(value)
        return
    if isinstance(value, dict):
        for child in value.values():
            yield from deep_values(child)
        return
    if isinstance(value, list):
        for child in value:
            yield from deep_values(child)
        return
    yield str(value)


def artifact_text(item: Any) -> str:
    return " ".join(deep_values(item)).lower()


def match_remote_tool(item: Any) -> str | None:
    text = artifact_text(item)
    for tool, terms in REMOTE_TOOLS.items():
        if any(term in text for term in terms):
            return tool
    return None


def first_present(item: dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        value = item.get(key)
        if value not in (None, "", []):
            return value
    return None


def event_data_text(event: dict[str, Any]) -> str:
    return artifact_text(
        {
            "message": event.get("message"),
            "data": event.get("data"),
            "provider": event.get("provider"),
        }
    )


def defender_config_is_sensitive(event: dict[str, Any]) -> bool:
    event_id = event.get("id")
    try:
        event_id = int(event_id)
    except (TypeError, ValueError):
        event_id = None
    if event_id in {5001, 5004, 5013}:
        return True
    text = event_data_text(event)
    return any(term in text for term in DEFENDER_SENSITIVE_CONFIG_TERMS)


def is_self_generated_event_text(text: str) -> bool:
    return any(term in text for term in SELF_EVENT_TERMS)


def path_text(item: dict[str, Any]) -> str:
    value = first_present(
        item,
        (
            "executable_path",
            "path",
            "path_name",
            "value",
            "install_location",
            "uninstall_string",
            "directory",
        ),
    )
    return str(value or "").lower()


def path_is_suspicious(path: str) -> bool:
    normalized = path.lower().replace("/", "\\")
    return any(marker in normalized for marker in SUSPICIOUS_PATH_MARKERS)


def path_is_standard(path: str) -> bool:
    normalized = path.lower().replace("/", "\\")
    return normalized.startswith(STANDARD_PROGRAM_PATHS)


def signature_status(item: dict[str, Any]) -> str | None:
    signature = item.get("signature")
    if isinstance(signature, dict):
        status = signature.get("status")
        if status:
            return str(status)
    return None


def signature_is_untrusted(item: dict[str, Any]) -> bool:
    status = signature_status(item)
    if status is None:
        return False
    return status.lower() not in {"valid"}


def file_stem_from_path(path: str) -> str:
    if not path:
        return ""
    clean = path.strip().strip('"').replace("/", "\\")
    name = clean.rsplit("\\", 1)[-1]
    return name.rsplit(".", 1)[0].lower()


def name_looks_odd(path: str) -> bool:
    stem = file_stem_from_path(path)
    if len(stem) < 8 or len(stem) > 40:
        return False
    if re.fullmatch(r"[a-f0-9]{8,40}", stem):
        return True
    if re.fullmatch(r"[a-z0-9]{12,40}", stem):
        digit_ratio = sum(ch.isdigit() for ch in stem) / max(len(stem), 1)
        vowel_count = sum(ch in "aeiou" for ch in stem)
        return digit_ratio >= 0.35 or vowel_count <= 1
    return False


def compact_artifact(source: str, item: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "display_name",
        "name",
        "task_name",
        "task_path",
        "value_name",
        "registry_path",
        "path",
        "directory",
        "path_name",
        "executable_path",
        "install_location",
        "uninstall_string",
        "publisher",
        "state",
        "start_mode",
        "start_name",
        "creation_time_utc",
        "last_write_time_utc",
        "time_created_utc",
        "id",
        "log_name",
        "provider",
    )
    artifact = {"source": source}
    for key in keys:
        value = item.get(key)
        if value not in (None, "", []):
            artifact[key] = value

    if "actions" in item:
        artifact["actions"] = item["actions"]

    signature = item.get("signature")
    if isinstance(signature, dict):
        artifact["signature"] = {
            "status": signature.get("status"),
            "signer_subject": signature.get("signer_subject"),
        }

    message = item.get("message")
    if message:
        artifact["message_excerpt"] = str(message)[:700]

    data = item.get("data")
    if isinstance(data, dict):
        compact_data = {}
        for key, value in data.items():
            if value not in (None, ""):
                compact_data[key] = str(value)[:500]
        if compact_data:
            artifact["event_data"] = compact_data

    return artifact


def artifact_identity(source: str, item: dict[str, Any]) -> str:
    data = item.get("data")
    if isinstance(data, dict):
        for key in ("ScriptBlockId", "ProcessId", "NewProcessId", "ServiceName", "TaskName"):
            value = data.get(key)
            if value:
                return f"{source}:{key}:{value}"

    for key in (
        "executable_path",
        "path",
        "path_name",
        "name",
        "display_name",
        "task_name",
        "registry_path",
        "value_name",
        "time_created_utc",
    ):
        value = item.get(key)
        if value:
            return f"{source}:{key}:{value}"

    message = str(item.get("message") or "")
    if message:
        return f"{source}:message:{message[:120]}"
    return f"{source}:unknown:{id(item)}"


def make_finding(
    findings: list[dict[str, Any]],
    *,
    severity: str,
    category: str,
    title: str,
    reason: str,
    source: str,
    artifact: dict[str, Any],
    tool: str | None = None,
    confidence: float = 0.7,
) -> None:
    dedupe_key = f"{category}|{source}|{artifact_identity(source, artifact)}"
    if any(
        existing.get("_dedupe_key") == dedupe_key or dedupe_key in existing.get("_dedupe_keys", set())
        for existing in findings
    ):
        return

    grouped_artifact = compact_artifact(source, artifact)
    group_key = f"{severity}|{category}|{title}|{tool or ''}"
    for existing in findings:
        if existing.get("_group_key") == group_key:
            existing["artifacts"].append(grouped_artifact)
            existing["artifact_count"] = len(existing["artifacts"])
            existing.setdefault("_dedupe_keys", set()).add(dedupe_key)
            return

    finding_id = f"RMMH-{len(findings) + 1:03d}"
    findings.append(
        {
            "id": finding_id,
            "_dedupe_key": dedupe_key,
            "_dedupe_keys": {dedupe_key},
            "_group_key": group_key,
            "severity": severity,
            "category": category,
            "title": title,
            "tool": tool,
            "confidence": round(confidence, 2),
            "reason": reason,
            "artifact_count": 1,
            "artifacts": [grouped_artifact],
        }
    )


def add_finding_guidance(finding: dict[str, Any]) -> None:
    tool = str(finding.get("tool") or "the referenced tool")
    category = str(finding.get("category") or "")

    if category == "recent_remote_tool_file":
        finding["plain_language"] = (
            f"An installer or script for {tool} was found in Downloads, Temp, or another recent-file location. "
            "This does not prove it is installed or active, but it needs an explanation because support-scam and intrusion chains often begin with downloaded remote-access installers."
        )
        finding["recommended_actions"] = [
            f"Ask the device owner or IT provider whether {tool} was intentionally downloaded.",
            f"Check Installed apps, Services, Startup entries, and Scheduled tasks for {tool} before deciding it is only an installer.",
            "If nobody recognizes it, preserve this report, run a Defender full scan, and remove the installer only after the timeline is documented.",
        ]
    elif category in {
        "known_rmm_installed_app",
        "known_rmm_service",
        "known_rmm_scheduled_task",
        "known_rmm_startup_registry",
        "known_rmm_startup_folder",
        "recent_rmm_service_install",
    }:
        finding["plain_language"] = (
            f"{tool} appears in a place Windows can use to run software. Remote tools can be legitimate for MSP or helpdesk support, "
            "but unauthorized remote access is a common breach pattern."
        )
        finding["recommended_actions"] = [
            f"Confirm who installed {tool}, when it was installed, and whether it is still approved.",
            "Compare the timestamps in this card with support calls, invoices, admin work, or suspicious browser activity.",
            "If unauthorized, preserve the report first, disconnect from untrusted networks if needed, then remove it through normal vendor or Windows uninstall steps.",
        ]
    elif category in {"service_from_user_writable_path", "recent_service_install_from_suspicious_path"}:
        finding["plain_language"] = (
            "A Windows service appears to run from Downloads, Temp, or another user-writable location. Services normally live under Windows or Program Files, "
            "so this is stronger evidence than a loose downloaded file."
        )
        finding["recommended_actions"] = [
            "Preserve the JSON/PDF report before changing the service.",
            "Review the service name, executable path, publisher signature, and creation time.",
            "If the service is not approved by your IT provider, escalate as an incident and remove it using Windows Services or vendor uninstall guidance after evidence is saved.",
        ]
    elif category in {"encoded_powershell", "encoded_powershell_process"}:
        finding["plain_language"] = (
            "PowerShell ran with encoded content. Attackers use this to hide commands, although some admin tools also generate encoded PowerShell."
        )
        finding["recommended_actions"] = [
            "Review the script block, parent process, user, and timestamp before running any cleanup.",
            "If the command is not recognized, preserve the report and run a Defender full scan or offline scan.",
            "Rotate credentials that may have been exposed around the same time if the command touched browsers, cloud tools, or password files.",
        ]
    elif category in {
        "powershell_policy_or_hidden_window",
        "powershell_download_cradle",
        "msiexec_from_browser_or_download_path",
        "suspicious_wmi_activity",
    }:
        finding["plain_language"] = (
            "This is living-off-the-land activity: normal Windows tools used in a way that can be legitimate for admin work or suspicious in a breach. "
            "The important question is whether the command, user, timestamp, and file path match expected activity."
        )
        finding["recommended_actions"] = [
            "Compare the timestamp with known installs, updates, support sessions, or your own development work.",
            "Review the command line and script path. Downloads, Temp, browser-launched installers, and hidden windows deserve extra attention.",
            "If it is not expected, preserve the report and investigate related Defender, browser, and service events before deleting anything.",
        ]
    elif category == "defender_malware_event":
        finding["plain_language"] = (
            "Microsoft Defender reported a malware or potentially unwanted software detection and attempted remediation. "
            "This does not always mean malware is still active, but it is high priority because Defender saw a named threat."
        )
        finding["recommended_actions"] = [
            "Open Windows Security > Protection history and confirm the action says removed, quarantined, or remediated successfully.",
            "Run a Defender full scan. Use Microsoft Defender Offline scan if the same threat repeats or the machine behaves strangely.",
            "Review the affected path and command line, then rotate passwords or API keys if the detection touched browsers, cloud config, or credential files.",
        ]
    elif category == "defender_sensitive_configuration_event":
        finding["plain_language"] = (
            "Defender logged a security-sensitive setting change, such as exclusions, real-time protection, tamper protection, or cloud protection behavior. "
            "These changes can be legitimate, but they can also weaken protection."
        )
        finding["recommended_actions"] = [
            "Open Windows Security and verify real-time protection, cloud protection, tamper protection, and exclusions.",
            "Confirm whether an admin, endpoint manager, or security product made the change.",
            "If unauthorized, restore the setting, preserve this report, and review nearby process and PowerShell events.",
        ]
    elif category == "defender_routine_configuration_event":
        finding["plain_language"] = (
            "Defender logged a routine configuration or internal hash change. On its own this is often caused by Microsoft Defender updates or normal Windows maintenance, "
            "but it is useful timeline context when malware or unauthorized admin activity appears nearby."
        )
        finding["recommended_actions"] = [
            "Check whether the timestamp lines up with Windows Update, Defender intelligence updates, or a reboot.",
            "Prioritize this only if it appears near malware detections, remote-tool installs, exclusions, or protection being disabled.",
            "Keep the event in the report for timeline context. It usually does not need cleanup by itself.",
        ]
    else:
        finding["plain_language"] = (
            "This matched a local RMM Hunter rule. It is a review signal, not proof by itself. Confirm ownership, timestamp, path, and whether the activity was expected."
        )
        finding["recommended_actions"] = [
            "Ask the device owner or IT provider whether this activity is expected.",
            "Compare the finding timestamp with known installs, support sessions, updates, or admin work.",
            "Preserve the report before making changes so the timeline remains available.",
        ]


def analyze_artifacts(collection: dict[str, Any]) -> dict[str, Any]:
    artifacts = collection.get("artifacts") or {}
    findings: list[dict[str, Any]] = []

    for app in artifacts.get("installed_programs", []):
        if not isinstance(app, dict):
            continue
        tool = match_remote_tool(app)
        if not tool:
            continue
        severity = "medium"
        reason = "Known remote access or RMM tool appears in installed programs."
        if path_is_suspicious(path_text(app)):
            severity = "high"
            reason = "Known remote access or RMM tool is installed from a user-writable or temporary path."
        make_finding(
            findings,
            severity=severity,
            category="known_rmm_installed_app",
            title=f"Known remote access tool installed: {tool}",
            reason=reason,
            source="installed_programs",
            artifact=app,
            tool=tool,
            confidence=0.82,
        )

    for service in artifacts.get("services", []):
        if not isinstance(service, dict):
            continue
        service_path = path_text(service)
        tool = match_remote_tool(service)
        if tool:
            severity = "medium"
            reason = "Known remote access or RMM tool appears as a Windows service."
            if path_is_suspicious(service_path):
                severity = "high"
                reason = "Known remote access or RMM service executable is under Downloads, Temp, or another suspicious path."
            make_finding(
                findings,
                severity=severity,
                category="known_rmm_service",
                title=f"Known remote access service: {tool}",
                reason=reason,
                source="services",
                artifact=service,
                tool=tool,
                confidence=0.86,
            )

        if service_path and path_is_suspicious(service_path):
            make_finding(
                findings,
                severity="high",
                category="service_from_user_writable_path",
                title="Windows service executable runs from Downloads or Temp",
                reason="Services should normally run from managed program directories, not user-writable download or temp paths.",
                source="services",
                artifact=service,
                tool=tool,
                confidence=0.9,
            )
        elif service_path and not path_is_standard(service_path) and signature_is_untrusted(service):
            make_finding(
                findings,
                severity="medium",
                category="unsigned_nonstandard_service",
                title="Unsigned service executable outside standard program paths",
                reason="Unsigned service binaries outside Windows or Program Files paths need ownership review.",
                source="services",
                artifact=service,
                tool=tool,
                confidence=0.72,
            )

    for event in artifacts.get("service_install_events", []):
        if not isinstance(event, dict):
            continue
        text = event_data_text(event)
        tool = match_remote_tool(event)
        if tool:
            make_finding(
                findings,
                severity="high",
                category="recent_rmm_service_install",
                title=f"Recent service creation for known remote tool: {tool}",
                reason="A recent service creation event for a remote access tool is high-priority evidence.",
                source="service_install_events",
                artifact=event,
                tool=tool,
                confidence=0.88,
            )
        elif path_is_suspicious(text):
            make_finding(
                findings,
                severity="high",
                category="recent_service_install_from_suspicious_path",
                title="Recent service creation references Downloads or Temp",
                reason="Service creation from a user-writable location is unusual and should be investigated.",
                source="service_install_events",
                artifact=event,
                confidence=0.84,
            )

    for task in artifacts.get("scheduled_tasks", []):
        if not isinstance(task, dict):
            continue
        task_text = artifact_text(task)
        tool = match_remote_tool(task)
        if tool:
            make_finding(
                findings,
                severity="medium",
                category="known_rmm_scheduled_task",
                title=f"Scheduled task references known remote tool: {tool}",
                reason="Scheduled persistence for a remote access tool needs authorization review.",
                source="scheduled_tasks",
                artifact=task,
                tool=tool,
                confidence=0.78,
            )
        if path_is_suspicious(task_text):
            make_finding(
                findings,
                severity="medium",
                category="scheduled_task_from_suspicious_path",
                title="Scheduled task references Downloads or Temp",
                reason="Scheduled tasks that execute from user-writable paths are commonly abused for persistence.",
                source="scheduled_tasks",
                artifact=task,
                tool=tool,
                confidence=0.75,
            )

    for entry in artifacts.get("startup_registry", []):
        if not isinstance(entry, dict):
            continue
        entry_text = artifact_text(entry)
        tool = match_remote_tool(entry)
        if tool:
            make_finding(
                findings,
                severity="medium",
                category="known_rmm_startup_registry",
                title=f"Startup registry entry references known remote tool: {tool}",
                reason="Startup persistence for a remote access tool needs authorization review.",
                source="startup_registry",
                artifact=entry,
                tool=tool,
                confidence=0.78,
            )
        if path_is_suspicious(entry_text):
            make_finding(
                findings,
                severity="medium",
                category="startup_registry_suspicious_path",
                title="Startup registry entry references Downloads or Temp",
                reason="Startup entries from user-writable paths are suspicious persistence artifacts.",
                source="startup_registry",
                artifact=entry,
                tool=tool,
                confidence=0.76,
            )

    for entry in artifacts.get("startup_folders", []):
        if not isinstance(entry, dict):
            continue
        tool = match_remote_tool(entry)
        if tool:
            make_finding(
                findings,
                severity="medium",
                category="known_rmm_startup_folder",
                title=f"Startup folder item references known remote tool: {tool}",
                reason="Startup folder persistence for a remote access tool needs authorization review.",
                source="startup_folders",
                artifact=entry,
                tool=tool,
                confidence=0.78,
            )
        if signature_is_untrusted(entry):
            make_finding(
                findings,
                severity="low",
                category="unsigned_startup_folder_item",
                title="Unsigned executable in startup folder",
                reason="Unsigned startup executables should be reviewed for ownership and purpose.",
                source="startup_folders",
                artifact=entry,
                tool=tool,
                confidence=0.65,
            )

    for recent in artifacts.get("recent_files", []):
        if not isinstance(recent, dict):
            continue
        recent_path = path_text(recent)
        tool = match_remote_tool(recent)
        if tool:
            severity = "medium"
            reason = "Recent installer or script resembles a known remote access tool."
            if path_is_suspicious(recent_path):
                severity = "medium"
                reason = "Recent remote access installer or script is present under Downloads or Temp."
            make_finding(
                findings,
                severity=severity,
                category="recent_remote_tool_file",
                title=f"Recent remote access installer or script: {tool}",
                reason=reason,
                source="recent_files",
                artifact=recent,
                tool=tool,
                confidence=0.76,
            )
        if path_is_suspicious(recent_path) and signature_is_untrusted(recent) and name_looks_odd(recent_path):
            make_finding(
                findings,
                severity="medium",
                category="odd_unsigned_recent_executable",
                title="Oddly named unsigned recent executable",
                reason="A recent unsigned executable with a random-looking name was found in a user-writable location.",
                source="recent_files",
                artifact=recent,
                tool=tool,
                confidence=0.7,
            )

    for event in artifacts.get("powershell_events", []):
        if not isinstance(event, dict):
            continue
        text = event_data_text(event)
        if is_self_generated_event_text(text):
            continue
        if any(pattern in text for pattern in ENCODED_POWERSHELL_PATTERNS):
            make_finding(
                findings,
                severity="high",
                category="encoded_powershell",
                title="Encoded PowerShell observed",
                reason="Encoded PowerShell is commonly used to hide script content and should be reviewed.",
                source="powershell_events",
                artifact=event,
                confidence=0.86,
            )
        elif any(pattern in text for pattern in POWERSHELL_DOWNLOAD_PATTERNS):
            make_finding(
                findings,
                severity="medium",
                category="powershell_download_cradle",
                title="PowerShell download behavior observed",
                reason="PowerShell appears to download content, which is common in intrusion chains and admin scripts.",
                source="powershell_events",
                artifact=event,
                confidence=0.72,
            )
        elif any(pattern in text for pattern in POWERSHELL_BYPASS_PATTERNS):
            make_finding(
                findings,
                severity="medium",
                category="powershell_policy_or_hidden_window",
                title="PowerShell bypass or hidden-window behavior observed",
                reason="Execution policy bypass or hidden-window PowerShell needs review in this context.",
                source="powershell_events",
                artifact=event,
                confidence=0.72,
            )

    for event in artifacts.get("process_creation_events", []):
        if not isinstance(event, dict):
            continue
        text = event_data_text(event)
        if is_self_generated_event_text(text):
            continue
        if any(term in text for term in MSIEXEC_TERMS):
            if path_is_suspicious(text) or any(browser in text for browser in BROWSER_TERMS):
                make_finding(
                    findings,
                    severity="medium",
                    category="msiexec_from_browser_or_download_path",
                    title="msiexec launched from browser, Downloads, or Temp context",
                    reason="MSI installation from browser or user-writable paths is common in support-scam and RMM abuse chains.",
                    source="process_creation_events",
                    artifact=event,
                    confidence=0.8,
                )
        if any(pattern in text for pattern in ENCODED_POWERSHELL_PATTERNS):
            make_finding(
                findings,
                severity="high",
                category="encoded_powershell_process",
                title="Encoded PowerShell process creation observed",
                reason="Process creation logs show encoded PowerShell execution.",
                source="process_creation_events",
                artifact=event,
                confidence=0.86,
            )

    for event in artifacts.get("wmi_events", []):
        if not isinstance(event, dict):
            continue
        text = event_data_text(event)
        if any(term in text for term in WMI_SUSPICIOUS_TERMS):
            make_finding(
                findings,
                severity="medium",
                category="suspicious_wmi_activity",
                title="Suspicious WMI activity observed",
                reason="WMI event consumer or command activity can indicate persistence or remote execution.",
                source="wmi_events",
                artifact=event,
                confidence=0.72,
            )

    for event in artifacts.get("defender_events", []):
        if not isinstance(event, dict):
            continue
        event_id = event.get("id")
        try:
            event_id = int(event_id)
        except (TypeError, ValueError):
            event_id = None
        if event_id in DEFENDER_HIGH_RISK_IDS:
            make_finding(
                findings,
                severity="high",
                category="defender_malware_event",
                title="Defender malware or remediation event observed",
                reason="Defender reported a malware detection or remediation event in the lookback window.",
                source="defender_events",
                artifact=event,
                confidence=0.88,
            )
        elif event_id in DEFENDER_CONFIG_IDS:
            is_sensitive_config = defender_config_is_sensitive(event)
            make_finding(
                findings,
                severity="medium" if is_sensitive_config else "low",
                category="defender_sensitive_configuration_event" if is_sensitive_config else "defender_routine_configuration_event",
                title="Defender protection setting changed" if is_sensitive_config else "Defender routine configuration change observed",
                reason=(
                    "A security-sensitive Defender setting appears to have changed and should be confirmed."
                    if is_sensitive_config
                    else "Defender logged an internal or routine configuration change. Keep it as timeline context, especially near malware or RMM activity."
                ),
                source="defender_events",
                artifact=event,
                confidence=0.72 if is_sensitive_config else 0.5,
            )

    category_scores: dict[str, int] = {}
    for finding in findings:
        category = str(finding["category"])
        category_scores[category] = max(category_scores.get(category, 0), SEVERITY_SCORE.get(finding["severity"], 0))

    score = min(100, sum(category_scores.values()))
    has_high = any(finding["severity"] == "high" for finding in findings)
    medium_or_higher_categories = sum(1 for value in category_scores.values() if value >= SEVERITY_SCORE["medium"])
    verdict = "clean"
    if has_high or (score >= 80 and medium_or_higher_categories >= 3):
        verdict = "high_risk"
    elif findings:
        verdict = "needs_review"

    for finding in findings:
        finding.pop("_dedupe_key", None)
        finding.pop("_dedupe_keys", None)
        finding.pop("_group_key", None)
        add_finding_guidance(finding)

    artifact_counts = {
        key: len(value) if isinstance(value, list) else 0
        for key, value in artifacts.items()
    }

    return {
        "schema_version": "1.0",
        "scanner": {
            "name": "RMM Hunter",
            "version": SCANNER_VERSION,
            "generated_at_utc": utc_now_iso(),
        },
        "collection_metadata": collection.get("scanner", {}),
        "collection": collection.get("collection", {}),
        "verdict": verdict,
        "risk_score": score,
        "summary": summarize_counts(verdict, findings, artifact_counts),
        "recommendations": build_recommendations(verdict, findings),
        "artifact_counts": artifact_counts,
        "findings": findings,
        "collection_errors": collection.get("collection_errors", []),
    }


def build_recommendations(verdict: str, findings: list[dict[str, Any]]) -> list[str]:
    if not findings:
        return [
            "No matching RMM or living-off-the-land indicators were found in the collected sources.",
            "Keep the JSON report as a baseline if this device is being reviewed after a support call or MSP handover.",
            "Run the app as Administrator for stronger event-log and service coverage if this scan was not elevated.",
        ]

    categories = {str(finding.get("category")) for finding in findings}
    severities = {str(finding.get("severity")) for finding in findings}
    recommendations: list[str] = []

    if verdict == "high_risk" or "high" in severities:
        recommendations.append(
            "Treat this as an incident triage case: preserve the report, avoid deleting artifacts immediately, and confirm the timeline before remediation."
        )
    else:
        recommendations.append(
            "Review each finding with the device owner or IT provider before deciding whether it is authorized."
        )

    if any("rmm" in category or "remote_tool" in category for category in categories):
        recommendations.append(
            "Confirm every remote access tool with the expected IT provider, including who installed it, when it was installed, and whether it is still needed."
        )

    if any("service" in category for category in categories):
        recommendations.append(
            "Review service names, executable paths, start mode, and creation timestamps. Services from Downloads or Temp should be escalated."
        )

    if any("defender_malware" in category for category in categories):
        recommendations.append(
            "Run a Microsoft Defender full scan or offline scan and review protection history for the same timestamps shown in this report."
        )

    if any("defender_sensitive_configuration" in category for category in categories):
        recommendations.append(
            "Review Defender configuration changes and verify whether they came from Windows, an admin tool, or an unauthorized process."
        )
    elif any("defender_routine_configuration" in category for category in categories):
        recommendations.append(
            "Keep routine Defender configuration changes in the timeline, but prioritize malware detections, remote-tool artifacts, and security-sensitive Defender setting changes."
        )

    if any("powershell" in category or "msiexec" in category or "wmi" in category for category in categories):
        recommendations.append(
            "Check whether PowerShell, msiexec, or WMI activity lines up with known admin work. Encoded PowerShell or browser-launched installers deserve priority review."
        )

    recommendations.append(
        "Export JSON for technical review and PDF for a non-technical handoff. Do not publish raw reports without checking paths, usernames, and event excerpts."
    )
    return recommendations


def summarize_counts(verdict: str, findings: list[dict[str, Any]], artifact_counts: dict[str, int]) -> str:
    severity_counts = {"high": 0, "medium": 0, "low": 0}
    matched_artifacts = 0
    for finding in findings:
        severity = finding.get("severity")
        if severity in severity_counts:
            severity_counts[severity] += 1
        matched_artifacts += int(finding.get("artifact_count") or len(finding.get("artifacts") or []) or 1)

    total_artifacts = sum(artifact_counts.values())
    return (
        f"Verdict {verdict}. "
        f"{len(findings)} grouped findings covering {matched_artifacts} matched artifacts "
        f"across {total_artifacts} collected artifacts "
        f"({severity_counts['high']} high, {severity_counts['medium']} medium, {severity_counts['low']} low)."
    )


def render_human_summary(report: dict[str, Any]) -> str:
    lines: list[str] = []
    metadata = report.get("collection_metadata") or {}
    collection = report.get("collection") or {}
    counts = report.get("artifact_counts") or {}

    lines.append("RMM Hunter Summary")
    lines.append("==================")
    lines.append(f"Verdict: {report.get('verdict')}")
    lines.append(f"Risk score: {report.get('risk_score')}/100")
    if metadata.get("hostname"):
        lines.append(f"Host: {metadata.get('hostname')}")
    if metadata.get("collected_at_utc"):
        lines.append(f"Collected at UTC: {metadata.get('collected_at_utc')}")
    if collection.get("lookback_days") is not None:
        lines.append(f"Lookback days: {collection.get('lookback_days')}")
    lines.append("")
    lines.append(report.get("summary", ""))
    lines.append("")

    recommendations = report.get("recommendations") or []
    if recommendations:
        lines.append("Recommended Next Steps")
        lines.append("----------------------")
        for recommendation in recommendations:
            lines.append(f"- {recommendation}")
        lines.append("")

    lines.append("Artifact Counts")
    lines.append("---------------")
    for key in sorted(counts):
        lines.append(f"- {key}: {counts[key]}")
    lines.append("")

    findings = report.get("findings") or []
    if findings:
        lines.append("Findings")
        lines.append("--------")
        for finding in findings:
            tool = f" [{finding['tool']}]" if finding.get("tool") else ""
            lines.append(f"- [{finding['severity'].upper()}] {finding['title']}{tool}")
            lines.append(f"  ID: {finding['id']}")
            lines.append(f"  Reason: {finding['reason']}")
            if finding.get("plain_language"):
                lines.append(f"  What this means: {single_line(finding['plain_language'])}")
            actions = finding.get("recommended_actions") or []
            if actions:
                lines.append("  Suggested actions:")
                for action in actions:
                    lines.append(f"    - {single_line(action)}")
            for artifact in finding.get("artifacts", []):
                lines.append("  Artifact:")
                for key, value in artifact.items():
                    if key == "source":
                        lines.append(f"    source: {value}")
                    elif key == "message_excerpt":
                        lines.append(f"    message_excerpt: {single_line(value)}")
                    elif key == "event_data":
                        compact = "; ".join(f"{k}={single_line(v)}" for k, v in value.items())
                        lines.append(f"    event_data: {compact[:1000]}")
                    elif key == "signature":
                        lines.append(f"    signature: {json.dumps(value, ensure_ascii=True)}")
                    else:
                        lines.append(f"    {key}: {single_line(value)}")
            lines.append("")
    else:
        lines.append("Findings")
        lines.append("--------")
        lines.append("- None")
        lines.append("")

    errors = report.get("collection_errors") or []
    if errors:
        lines.append("Collection Warnings")
        lines.append("-------------------")
        for error in errors:
            if isinstance(error, dict):
                lines.append(f"- {error.get('source')}: {error.get('message')}")
            else:
                lines.append(f"- {error}")
        lines.append("")

    lines.append("Reminder: RMM Hunter does not remove anything. Review findings before taking action.")
    return "\n".join(lines) + "\n"


def mapping_for_category(category: str) -> dict[str, Any]:
    mapping = RULE_MAPPINGS.get(category) or {
        "attack": {
            "techniques": [],
            "data_sources": [],
        },
        "d3fend": [],
    }
    return json.loads(json.dumps(mapping))


def sigma_tags_for_mapping(mapping: dict[str, Any]) -> list[str]:
    techniques = ((mapping.get("attack") or {}).get("techniques") or [])
    tags = []
    for technique in techniques:
        technique_id = str((technique or {}).get("id") or "").lower()
        if technique_id:
            tags.append(f"attack.{technique_id}")
    return tags


def stix_observable_hints(finding: dict[str, Any]) -> list[str]:
    sources = {str(artifact.get("source") or "") for artifact in finding.get("artifacts", []) if isinstance(artifact, dict)}
    hints: set[str] = set()
    if sources & {"installed_programs"}:
        hints.add("software")
    if sources & {"services", "process_creation_events", "powershell_events", "wmi_events"}:
        hints.add("process")
    if sources & {"recent_files", "startup_folders"}:
        hints.add("file")
    if sources & {"startup_registry"}:
        hints.add("windows-registry-key")
    if sources & {"scheduled_tasks"}:
        hints.add("x-windows-scheduled-task")
    if sources & {"defender_events", "service_install_events"}:
        hints.add("x-windows-event-log-entry")
    return sorted(hints)


def misp_attribute_hints(finding: dict[str, Any]) -> list[str]:
    hints: set[str] = set()
    for artifact in finding.get("artifacts", []):
        if not isinstance(artifact, dict):
            continue
        if any(key in artifact for key in ("path", "directory", "path_name", "executable_path", "install_location")):
            hints.add("filename")
        if artifact.get("signature"):
            hints.add("text")
        if artifact.get("message_excerpt") or artifact.get("event_data"):
            hints.add("comment")
    return sorted(hints)


def build_mapped_detection_export(report: dict[str, Any]) -> dict[str, Any]:
    mapped_findings = []
    for finding in report.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        category = str(finding.get("category") or "")
        mapping = mapping_for_category(category)
        artifacts = [
            artifact
            for artifact in finding.get("artifacts", [])
            if isinstance(artifact, dict)
        ]
        mapped_findings.append(
            {
                "finding_id": finding.get("id"),
                "rule_id": category,
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "tool": finding.get("tool"),
                "reason": finding.get("reason"),
                "plain_language": finding.get("plain_language"),
                "recommended_actions": finding.get("recommended_actions") or [],
                "artifact_count": finding.get("artifact_count") or len(artifacts),
                "mapping": mapping,
                "interoperability": {
                    "sigma_tags": sigma_tags_for_mapping(mapping),
                    "stix_observable_hints": stix_observable_hints(finding),
                    "misp_attribute_hints": misp_attribute_hints(finding),
                },
                "evidence": {
                    "artifact_sources": sorted({str(artifact.get("source")) for artifact in artifacts if artifact.get("source")}),
                    "artifacts": artifacts,
                },
            }
        )

    return {
        "schema_version": "1.0",
        "profile": "rmm-hunter.detection-mapping.v1",
        "scanner": report.get("scanner"),
        "source_report_schema_version": report.get("schema_version"),
        "verdict": report.get("verdict"),
        "risk_score": report.get("risk_score"),
        "summary": report.get("summary"),
        "finding_count": len(mapped_findings),
        "findings": mapped_findings,
    }


def single_line(value: Any) -> str:
    return " ".join(str(value).split())


def default_report_paths(base_dir: Path) -> tuple[Path, Path, Path]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    reports = base_dir / "reports"
    artifacts = reports / f"rmm_hunter_artifacts_{stamp}.json"
    json_report = reports / f"rmm_hunter_report_{stamp}.json"
    summary = reports / f"rmm_hunter_summary_{stamp}.txt"
    return artifacts, json_report, summary


def app_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parent


def default_output_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path.cwd()
    return app_base_dir()


def find_powershell() -> str | None:
    return shutil.which("pwsh") or shutil.which("powershell")


def run_collector(collector: Path, artifacts_out: Path, lookback_days: int, max_recent_files: int) -> dict[str, Any]:
    powershell = find_powershell()
    if not powershell:
        raise RuntimeError("Could not find pwsh or powershell on PATH. Use --input to analyze an existing artifact file.")

    artifacts_out.parent.mkdir(parents=True, exist_ok=True)
    command = [
        powershell,
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(collector),
        "-LookbackDays",
        str(lookback_days),
        "-MaxRecentFiles",
        str(max_recent_files),
        "-OutputPath",
        str(artifacts_out),
    ]

    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            "PowerShell collector failed with exit code "
            f"{result.returncode}.\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )

    return load_json(artifacts_out)


def parse_args(argv: list[str]) -> argparse.Namespace:
    default_artifacts, default_json_report, default_summary = default_report_paths(default_output_base_dir())

    parser = argparse.ArgumentParser(
        description="Standalone Windows scanner for unauthorized remote access tools and living-off-the-land traces."
    )
    parser.add_argument("--input", type=Path, help="Analyze an existing collector artifacts JSON file.")
    parser.add_argument("--collector", type=Path, default=app_base_dir() / "collect_windows.ps1", help="PowerShell collector path.")
    parser.add_argument("--lookback-days", type=int, default=14, help="Event and recent-file lookback window.")
    parser.add_argument("--max-recent-files", type=int, default=500, help="Maximum recent files to collect.")
    parser.add_argument("--artifacts-out", type=Path, default=default_artifacts, help="Raw collector artifact output path.")
    parser.add_argument("--json-out", type=Path, default=default_json_report, help="Final JSON report path.")
    parser.add_argument("--summary-out", type=Path, default=default_summary, help="Human summary output path.")
    parser.add_argument(
        "--mapped-out",
        type=Path,
        help="Optional mapped detection export path for SIEM/TI workflows. Does not change verdict calculation.",
    )
    parser.add_argument("--print-summary", action="store_true", help="Print the human summary to stdout.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])

    try:
        if args.input:
            collection = load_json(args.input)
        else:
            collection = run_collector(
                collector=args.collector,
                artifacts_out=args.artifacts_out,
                lookback_days=args.lookback_days,
                max_recent_files=args.max_recent_files,
            )

        report = analyze_artifacts(collection)
        summary = render_human_summary(report)
        write_json(args.json_out, report)
        write_text(args.summary_out, summary)
        if args.mapped_out:
            write_json(args.mapped_out, build_mapped_detection_export(report))

        if args.print_summary:
            print(summary, end="")
        else:
            print(f"Verdict: {report['verdict']}")
            print(f"JSON report: {args.json_out}")
            print(f"Summary: {args.summary_out}")
            if args.mapped_out:
                print(f"Mapped detection export: {args.mapped_out}")
            if not args.input:
                print(f"Raw artifacts: {args.artifacts_out}")
        return 0
    except Exception as exc:
        print(f"RMM Hunter failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
