#!/usr/bin/env python3
"""RMM Hunter CLI.

Collects Windows artifacts with PowerShell, then applies local triage rules.
The analyzer is intentionally conservative: it reports evidence and risk, but
does not claim to know whether a remote management tool is authorized.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCANNER_VERSION = "0.3.0"
LOGGER = logging.getLogger(__name__)

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

URL_PATTERN = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)

KAPE_TEXT_SUFFIXES = {".csv", ".tsv", ".json", ".txt", ".log"}
KAPE_MAX_SCAN_FILES = 2500
KAPE_MAX_TEXT_BYTES = 8_000_000
KAPE_SAMPLE_BYTES = 128_000
KAPE_MAX_RMM_ARTIFACTS = 250

KAPE_ARTIFACT_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("prefetch", ("prefetch", "\\pf\\", ".pf", "pecmd")),
    ("amcache", ("amcache", "amcacheparser")),
    ("shimcache", ("shimcache", "appcompatcache")),
    ("userassist", ("userassist", "regripper_userassist")),
    ("srum", ("srum", "srumecmd")),
    ("shellbags", ("shellbags", "shellbagsexplorer")),
    ("event_logs", ("winevent", "evtx", "eventlog", "event_logs")),
    ("registry", ("registry", "regripper", "software_", "system_")),
    ("scheduled_tasks", ("scheduledtasks", "scheduled_tasks", "tasks")),
    ("services", ("services", "windowsservices")),
)

KAPE_TIMESTAMP_KEY_TERMS = (
    "timestamp",
    "time",
    "date",
    "lastmodified",
    "last_modified",
    "created",
    "creation",
    "modified",
    "execution",
    "lastrun",
    "last_run",
)

CONNECTION_LOG_MARKERS = (
    "connection_trace",
    "connections",
    "session",
    "remotecontrol",
    "remote_control",
    "incoming",
    "outgoing",
)

EVIDENCE_STRENGTH_ORDER = {
    "weak": 1,
    "medium": 2,
    "strong": 3,
    "very_strong": 4,
    "critical": 5,
}

EVIDENCE_STRENGTH_BY_CATEGORY = {
    "recent_remote_tool_file": "weak",
    "known_rmm_installed_app": "medium",
    "known_rmm_service": "medium",
    "known_rmm_scheduled_task": "medium",
    "known_rmm_startup_registry": "medium",
    "known_rmm_startup_folder": "medium",
    "rmm_vendor_log": "strong",
    "rmm_connection_log": "very_strong",
    "kape_rmm_reference": "strong",
    "kape_execution_reference": "very_strong",
    "service_from_user_writable_path": "strong",
    "recent_rmm_service_install": "strong",
    "recent_service_install_from_suspicious_path": "strong",
    "encoded_powershell": "strong",
    "encoded_powershell_process": "strong",
    "defender_malware_event": "critical",
    "defender_sensitive_configuration_event": "strong",
    "defender_health_issue": "strong",
    "trust_validation_issue": "strong",
    "trusted_root_store_issue": "strong",
}

WATCH_SCHEMA_VERSION = "1.0"
WATCH_TASK_NAME = "RMM Hunter Watch"
WATCH_ALERT_CATEGORIES = {
    "known_rmm_service",
    "known_rmm_scheduled_task",
    "known_rmm_startup_registry",
    "known_rmm_startup_folder",
    "rmm_vendor_log",
    "rmm_connection_log",
    "service_from_user_writable_path",
    "recent_rmm_service_install",
    "recent_service_install_from_suspicious_path",
    "scheduled_task_from_suspicious_path",
    "startup_registry_suspicious_path",
    "recent_remote_tool_file",
    "odd_unsigned_recent_executable",
    "encoded_powershell",
    "encoded_powershell_process",
    "powershell_download_cradle",
    "powershell_policy_or_hidden_window",
    "msiexec_from_browser_or_download_path",
    "suspicious_wmi_activity",
    "defender_malware_event",
    "defender_sensitive_configuration_event",
    "defender_health_issue",
    "trust_validation_issue",
    "trusted_root_store_issue",
}

WATCH_CRITICAL_CATEGORIES = {"defender_malware_event"}
WATCH_SOFT_ACTIONS = {
    "preserve_evidence",
    "send_alert",
    "defender_quick_scan",
    "defender_full_scan",
    "open_protection_history",
    "recommend_kape_collection",
}
WATCH_HARD_ACTIONS = {
    "network_isolate",
    "release_network_isolation",
    "stop_process",
    "stop_service",
    "disable_scheduled_task",
    "block_suspicious_path",
}
WATCH_ACTIONS = {
    "preserve_evidence": {
        "label": "Preserve evidence snapshot",
        "type": "soft",
        "reversible": False,
        "description": "Write the alert packet and evidence context to the local Watch evidence folder.",
    },
    "send_alert": {
        "label": "Send configured alert",
        "type": "soft",
        "reversible": False,
        "description": "Send the alert to configured alert sinks such as Discord.",
    },
    "defender_quick_scan": {
        "label": "Start Defender quick scan",
        "type": "soft",
        "reversible": False,
        "description": "Ask Microsoft Defender Antivirus to start a quick scan.",
    },
    "defender_full_scan": {
        "label": "Start Defender full scan",
        "type": "soft",
        "reversible": False,
        "description": "Ask Microsoft Defender Antivirus to start a full scan.",
    },
    "open_protection_history": {
        "label": "Open Defender protection history",
        "type": "soft",
        "reversible": False,
        "description": "Show where to review Defender Protection History.",
    },
    "recommend_kape_collection": {
        "label": "Recommend KAPE collection",
        "type": "soft",
        "reversible": False,
        "description": "Tell the operator to preserve a KAPE collection for deeper DFIR review.",
    },
    "network_isolate": {
        "label": "Emergency network isolation",
        "type": "hard",
        "reversible": True,
        "description": "Add Windows Firewall rules that block inbound and outbound traffic except loopback.",
    },
    "release_network_isolation": {
        "label": "Release emergency network isolation",
        "type": "hard",
        "reversible": True,
        "description": "Remove RMM Hunter Watch emergency isolation firewall rules.",
    },
    "stop_process": {
        "label": "Stop suspicious process",
        "type": "hard",
        "reversible": False,
        "description": "Stop a suspicious process when a process ID exists in the alert evidence.",
    },
    "stop_service": {
        "label": "Stop suspicious service",
        "type": "hard",
        "reversible": True,
        "description": "Stop a suspicious service and record the service name for rollback guidance.",
    },
    "disable_scheduled_task": {
        "label": "Disable suspicious scheduled task",
        "type": "hard",
        "reversible": True,
        "description": "Disable a scheduled task and record its name for rollback guidance.",
    },
    "block_suspicious_path": {
        "label": "Block suspicious path",
        "type": "hard",
        "reversible": True,
        "description": "Reserve a local execution block for a suspicious path. Preview builds only report this action.",
    },
}

WATCH_DEFAULT_CONFIG: dict[str, Any] = {
    "schema_version": WATCH_SCHEMA_VERSION,
    "mode": "approval_required",
    "poll_interval_seconds": 15,
    "reconcile_interval_seconds": 300,
    "lookback_days": 1,
    "max_recent_files": 300,
    "approved_tools": [],
    "approved_providers": [],
    "dev_paths": [],
    "business_hours": {
        "timezone": "local",
        "start": "09:00",
        "end": "17:30",
        "weekdays": [1, 2, 3, 4, 5],
    },
    "alert_sinks": {
        "discord": {
            "enabled": False,
            "webhook_url": "",
        }
    },
    "auto_actions": {
        "daytime_auto": ["preserve_evidence", "send_alert", "defender_quick_scan"],
        "night_auto": ["preserve_evidence", "send_alert", "defender_quick_scan", "network_isolate"],
    },
    "enabled_actions": [
        "preserve_evidence",
        "send_alert",
        "defender_quick_scan",
        "defender_full_scan",
        "open_protection_history",
        "recommend_kape_collection",
        "network_isolate",
        "release_network_isolation",
        "stop_process",
        "stop_service",
        "disable_scheduled_task",
        "block_suspicious_path",
    ],
    "install_helpers": {
        "watch_task": "ask",
        "sysmon": "ask",
        "process_creation_audit": "ask",
    },
}

WATCH_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
WATCH_CONFIDENCE_ORDER = {"low": 1, "medium": 2, "high": 3}
WATCH_PROTECTED_PATH_MARKERS = (
    "\\windows\\",
    "\\program files\\",
    "\\program files (x86)\\",
    "\\microsoft defender\\",
    "\\windows defender\\",
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

DEFENDER_ROUTINE_CONFIG_TERMS = (
    "\\features\\ecsconfigs\\",
    "mpdisablepropbagnotification",
    "spynetreportinglocation",
    "toastorssotrigger",
    "wdconfighash",
)

DEFENDER_PROTECTION_FIELDS = (
    ("am_service_enabled", "Defender antimalware service"),
    ("antivirus_enabled", "Defender antivirus"),
    ("real_time_protection_enabled", "real-time protection"),
    ("behavior_monitor_enabled", "behavior monitoring"),
    ("ioav_protection_enabled", "download and attachment scanning"),
    ("on_access_protection_enabled", "on-access protection"),
    ("is_tamper_protected", "tamper protection"),
)

SUSPICIOUS_EXCLUSION_MARKERS = (
    "\\downloads",
    "\\appdata\\local\\temp",
    "\\temp",
    "%temp%",
    "*",
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
    "rmm_vendor_log": {
        "attack": {
            "techniques": [{"id": "T1219", "name": "Remote Access Software"}],
            "data_sources": ["File: File Metadata", "Application Log: Application Log Content"],
        },
        "d3fend": [{"id": "D3-FA", "name": "File Analysis"}],
    },
    "rmm_connection_log": {
        "attack": {
            "techniques": [{"id": "T1219", "name": "Remote Access Software"}],
            "data_sources": ["File: File Metadata", "Application Log: Application Log Content", "Network Traffic: Network Connection Creation"],
        },
        "d3fend": [{"id": "D3-FA", "name": "File Analysis"}],
    },
    "kape_rmm_reference": {
        "attack": {
            "techniques": [{"id": "T1219", "name": "Remote Access Software"}],
            "data_sources": ["File: File Metadata"],
        },
        "d3fend": [{"id": "D3-PM", "name": "Platform Monitoring"}],
    },
    "kape_execution_reference": {
        "attack": {
            "techniques": [
                {"id": "T1219", "name": "Remote Access Software"},
                {"id": "T1204.002", "name": "Malicious File"},
            ],
            "data_sources": ["Process: OS API Execution", "File: File Metadata"],
        },
        "d3fend": [{"id": "D3-PM", "name": "Platform Monitoring"}],
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
    "defender_health_issue": {
        "attack": {
            "techniques": [{"id": "T1562.001", "name": "Disable or Modify Tools"}],
            "data_sources": ["Sensor Health: Host Status"],
        },
        "d3fend": [{"id": "D3-PM", "name": "Platform Monitoring"}],
    },
    "trust_validation_issue": {
        "attack": {
            "techniques": [],
            "data_sources": ["File: File Metadata", "Sensor Health: Host Status"],
        },
        "d3fend": [{"id": "D3-SBV", "name": "Service Binary Verification"}],
    },
    "trusted_root_store_issue": {
        "attack": {
            "techniques": [{"id": "T1553.004", "name": "Install Root Certificate"}],
            "data_sources": ["Windows Registry: Windows Registry Key Modification"],
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


def evidence_strength_for(category: str, severity: str, confidence: float) -> str:
    strength = EVIDENCE_STRENGTH_BY_CATEGORY.get(category)
    if strength:
        return strength
    if severity == "high" and confidence >= 0.86:
        return "strong"
    if severity == "high":
        return "medium"
    if severity == "medium":
        return "medium"
    return "weak"


def confidence_label(confidence: float) -> str:
    if confidence >= 0.9:
        return "high"
    if confidence >= 0.7:
        return "medium"
    return "low"


def stronger_evidence(left: str | None, right: str | None) -> str:
    left = left or "weak"
    right = right or "weak"
    return left if EVIDENCE_STRENGTH_ORDER.get(left, 0) >= EVIDENCE_STRENGTH_ORDER.get(right, 0) else right


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


def compact_text(value: Any, limit: int = 500) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return f"{text[:limit]}...[truncated]"


def extract_urls(text: str, limit: int = 5) -> list[str]:
    urls: list[str] = []
    for match in URL_PATTERN.findall(text or ""):
        cleaned = match.rstrip(").,;]'\"")
        if cleaned not in urls:
            urls.append(cleaned)
        if len(urls) >= limit:
            break
    return urls


def domain_from_url(url: str) -> str:
    match = re.match(r"(?i)^https?://([^/:?#]+)", url)
    return match.group(1).lower() if match else ""


def extract_domains(urls: Iterable[str]) -> list[str]:
    domains: list[str] = []
    for url in urls:
        domain = domain_from_url(url)
        if domain and domain not in domains:
            domains.append(domain)
    return domains


def parse_registry_setting(value: Any) -> dict[str, str]:
    text = compact_text(value, 1000)
    if not text:
        return {}

    path_part, separator, data_part = text.partition("=")
    detail = {"path": compact_text(path_part.strip(), 500)}
    if separator:
        detail["value"] = compact_text(data_part.strip(), 500)
    return detail


def build_artifact_context(source: str, item: dict[str, Any]) -> dict[str, Any]:
    text = event_data_text(item)
    urls = extract_urls(text)
    domains = extract_domains(urls)
    context: dict[str, Any] = {}

    if urls and source != "defender_events":
        context["network_urls"] = urls
        context["network_domains"] = domains
        if "powershell" in source:
            context["detail"] = f"PowerShell referenced {', '.join(domains)}"

    data = item.get("data")
    if source == "defender_events" and isinstance(data, dict):
        threat_name = data.get("Threat Name")
        action_name = data.get("Action Name")
        error_description = data.get("Error Description")
        resource = data.get("Path") or data.get("Resource") or data.get("Resources")

        if threat_name:
            context["threat_name"] = compact_text(threat_name, 200)
        if action_name:
            context["defender_action"] = compact_text(action_name, 120)
        if error_description:
            context["defender_result"] = compact_text(error_description, 240)
        if data.get("Detection Time"):
            context["detection_time_utc"] = compact_text(data.get("Detection Time"), 80)
        if data.get("Source Name"):
            context["detection_source"] = compact_text(data.get("Source Name"), 120)
        if resource:
            context["affected_resource"] = compact_text(resource, 700)
            affected_urls = extract_urls(str(resource))
            if affected_urls:
                context["affected_urls"] = affected_urls
                context["affected_domains"] = extract_domains(affected_urls)

        old_setting = parse_registry_setting(data.get("Old Value"))
        new_setting = parse_registry_setting(data.get("New Value"))
        if old_setting:
            context["old_setting_path"] = old_setting.get("path")
            if old_setting.get("value"):
                context["old_setting_value"] = old_setting.get("value")
        if new_setting:
            context["new_setting_path"] = new_setting.get("path")
            if new_setting.get("value"):
                context["new_setting_value"] = new_setting.get("value")
            context.setdefault("detail", f"Defender setting changed: {new_setting.get('path')}")

        if threat_name and action_name:
            context.setdefault(
                "detail",
                f"Defender reported {compact_text(threat_name, 120)} and action was {compact_text(action_name, 80)}",
            )

    return {key: value for key, value in context.items() if value not in (None, "", [])}


def defender_config_is_sensitive(event: dict[str, Any]) -> bool:
    event_id = event.get("id")
    try:
        event_id = int(event_id)
    except (TypeError, ValueError) as exc:
        LOGGER.debug("Could not parse Defender event id %r: %s", event_id, exc)
        event_id = None
    if event_id in {5001, 5004, 5013}:
        return True
    text = event_data_text(event)
    if any(term in text for term in DEFENDER_ROUTINE_CONFIG_TERMS):
        return False
    return any(term in text for term in DEFENDER_SENSITIVE_CONFIG_TERMS)


def as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value or "").strip().lower()
    if text in {"true", "1", "yes", "enabled"}:
        return True
    if text in {"false", "0", "no", "disabled"}:
        return False
    return None


def parse_float(value: Any) -> float | None:
    try:
        if value in (None, ""):
            return None
        return float(value)
    except (TypeError, ValueError) as exc:
        LOGGER.debug("Could not parse float value %r: %s", value, exc)
        return None


def parse_datetime(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        LOGGER.debug("Could not parse datetime value %r: %s", value, exc)
        return None


def days_since(value: Any) -> float | None:
    timestamp = parse_datetime(value)
    if not timestamp:
        return None
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return round((datetime.now(timezone.utc) - timestamp.astimezone(timezone.utc)).total_seconds() / 86400, 2)


def listify(value: Any) -> list[Any]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return value
    return [value]


def artifact_items(artifacts: dict[str, Any], key: str) -> list[dict[str, Any]]:
    return [item for item in listify(artifacts.get(key)) if isinstance(item, dict)]


def make_trust_check(
    *,
    check: str,
    status: str,
    title: str,
    detail: str,
    recommended_action: str,
    finding_category: str | None = None,
    severity: str | None = None,
    confidence: float = 0.68,
    **extra: Any,
) -> dict[str, Any]:
    item = {
        "check": check,
        "status": status,
        "title": title,
        "detail": detail,
        "recommended_action": recommended_action,
        "confidence": round(confidence, 2),
    }
    if finding_category:
        item["finding_category"] = finding_category
    if severity:
        item["severity"] = severity
    for key, value in extra.items():
        if value not in (None, "", []):
            item[key] = value
    return item


def suspicious_exclusion_values(status: dict[str, Any]) -> list[str]:
    suspicious: list[str] = []
    for key in (
        "exclusion_path_samples",
        "exclusion_process_samples",
        "exclusion_extension_samples",
        "exclusion_ip_address_samples",
    ):
        for value in listify(status.get(key)):
            text = str(value)
            lowered = text.lower().replace("/", "\\")
            if any(marker in lowered for marker in SUSPICIOUS_EXCLUSION_MARKERS):
                if text not in suspicious:
                    suspicious.append(compact_text(text, 220))
            if len(suspicious) >= 8:
                return suspicious
    return suspicious


def build_system_trust_health(artifacts: dict[str, Any]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    defender_status = artifact_items(artifacts, "defender_status")
    if defender_status:
        status = defender_status[0]
        disabled = []
        for field, label in DEFENDER_PROTECTION_FIELDS:
            state = as_bool(status.get(field))
            if state is False:
                disabled.append(label)
        if as_bool(status.get("disable_realtime_monitoring")) is True and "real-time protection" not in disabled:
            disabled.append("real-time protection policy")

        if disabled:
            checks.append(
                make_trust_check(
                    check="defender_protection_state",
                    status="high_risk",
                    severity="high",
                    title="Defender protection is disabled or weakened",
                    detail=f"Disabled or weakened Defender components: {', '.join(disabled)}.",
                    recommended_action="Open Windows Security and restore the disabled protections, then confirm whether an admin or endpoint manager made the change.",
                    finding_category="defender_health_issue",
                    confidence=0.86,
                    affected_components=disabled,
                )
            )
        else:
            checks.append(
                make_trust_check(
                    check="defender_protection_state",
                    status="ok",
                    title="Defender core protections are enabled",
                    detail="Collected Defender status shows antivirus, real-time, behavior, IOAV, on-access, and tamper protections enabled where reported.",
                    recommended_action="Keep Defender enabled while reviewing scan evidence.",
                )
            )

        age = parse_float(status.get("antivirus_signature_age_days"))
        if age is None:
            age = days_since(status.get("antivirus_signature_last_updated_utc"))
        signature_version = status.get("antivirus_signature_version")
        if age is None:
            checks.append(
                make_trust_check(
                    check="defender_security_intelligence_age",
                    status="unknown",
                    title="Defender intelligence age could not be confirmed",
                    detail="The collector could not determine when Defender security intelligence was last updated.",
                    recommended_action="Open Windows Security and check for protection updates before relying on malware verdicts.",
                )
            )
        elif age >= 7:
            checks.append(
                make_trust_check(
                    check="defender_security_intelligence_age",
                    status="high_risk",
                    severity="high",
                    title="Defender security intelligence is stale",
                    detail=f"Defender antivirus security intelligence appears about {age:g} days old.",
                    recommended_action="Update Defender security intelligence, rerun the scan, and treat old detections with extra context until updates succeed.",
                    finding_category="defender_health_issue",
                    confidence=0.84,
                    age_days=age,
                    signature_version=signature_version,
                )
            )
        elif age >= 3:
            checks.append(
                make_trust_check(
                    check="defender_security_intelligence_age",
                    status="needs_review",
                    severity="medium",
                    title="Defender security intelligence may be stale",
                    detail=f"Defender antivirus security intelligence appears about {age:g} days old.",
                    recommended_action="Check for Defender protection updates before making final incident decisions.",
                    finding_category="defender_health_issue",
                    confidence=0.74,
                    age_days=age,
                    signature_version=signature_version,
                )
            )
        else:
            checks.append(
                make_trust_check(
                    check="defender_security_intelligence_age",
                    status="ok",
                    title="Defender security intelligence is recent",
                    detail=f"Defender antivirus security intelligence appears about {age:g} days old.",
                    recommended_action="Keep the update timestamp with the report as context for Defender detections.",
                    age_days=age,
                    signature_version=signature_version,
                )
            )

        suspicious_exclusions = suspicious_exclusion_values(status)
        if suspicious_exclusions:
            checks.append(
                make_trust_check(
                    check="defender_exclusions",
                    status="needs_review",
                    severity="medium",
                    title="Defender exclusions need review",
                    detail="One or more Defender exclusions point to broad, temporary, download, or user-writable locations.",
                    recommended_action="Confirm each exclusion with IT. Remove unauthorized exclusions only after preserving the report and timeline.",
                    finding_category="defender_health_issue",
                    confidence=0.78,
                    suspicious_exclusions=suspicious_exclusions,
                )
            )
        else:
            total_exclusions = sum(
                int(status.get(key) or 0)
                for key in (
                    "exclusion_path_count",
                    "exclusion_process_count",
                    "exclusion_extension_count",
                    "exclusion_ip_address_count",
                )
            )
            checks.append(
                make_trust_check(
                    check="defender_exclusions",
                    status="ok",
                    title="No broad Defender exclusions were flagged",
                    detail=f"Defender reported {total_exclusions} exclusion entries; none matched the current broad or user-writable exclusion checks.",
                    recommended_action="Review exclusions manually if this is a managed device or if malware detections appeared nearby.",
                    exclusion_count=total_exclusions,
                )
            )
    else:
        checks.append(
            make_trust_check(
                check="defender_status",
                status="unknown",
                title="Defender health was not collected",
                detail="The collector did not return Defender status. This can happen if Defender cmdlets are unavailable or access is restricted.",
                recommended_action="Run as Administrator or check Windows Security manually before relying on Defender event interpretation.",
            )
        )

    signature_items = artifact_items(artifacts, "code_signing_trust")
    if signature_items:
        invalid = [
            item for item in signature_items
            if str(item.get("status") or "").lower() != "valid"
        ]
        if invalid:
            names = [str(item.get("name") or item.get("path") or "Windows binary") for item in invalid[:5]]
            checks.append(
                make_trust_check(
                    check="windows_code_signing_validation",
                    status="high_risk",
                    severity="high",
                    title="Windows code-signing validation failed",
                    detail=f"Authenticode validation did not return Valid for: {', '.join(names)}.",
                    recommended_action="Update Windows and Defender, then verify the trust store before trusting signed software or scan evidence.",
                    finding_category="trust_validation_issue",
                    confidence=0.88,
                    affected_items=names,
                )
            )
        else:
            checks.append(
                make_trust_check(
                    check="windows_code_signing_validation",
                    status="ok",
                    title="Windows code-signing validation passed",
                    detail=f"Authenticode returned Valid for {len(signature_items)} known Windows binaries.",
                    recommended_action="Keep this as baseline evidence that local code-signing trust is functioning.",
                )
            )
    else:
        checks.append(
            make_trust_check(
                check="windows_code_signing_validation",
                status="unknown",
                title="Windows code-signing validation was not collected",
                detail="The collector could not validate known signed Windows binaries.",
                recommended_action="Run the scan again and verify Windows signature validation manually if Defender or installer trust looks wrong.",
            )
        )

    root_items = artifact_items(artifacts, "trusted_root_store")
    root_summaries = [item for item in root_items if item.get("check") == "trusted_root_store_summary"]
    private_roots = [item for item in root_items if item.get("check") == "root_certificate_with_private_key"]
    if private_roots:
        subjects = [compact_text(item.get("subject") or item.get("thumbprint") or "trusted root", 220) for item in private_roots[:5]]
        checks.append(
            make_trust_check(
                check="trusted_root_private_key",
                status="needs_review",
                severity="medium",
                title="Trusted root certificate with private key observed",
                detail="A trusted root store contains certificate entries with private keys, which should be rare on normal endpoints.",
                recommended_action="Confirm whether these roots were intentionally installed by enterprise PKI, development tooling, or security tooling.",
                finding_category="trusted_root_store_issue",
                confidence=0.76,
                affected_items=subjects,
            )
        )
    elif root_summaries:
        total_roots = sum(int(item.get("total_count") or 0) for item in root_summaries)
        current_user_roots = sum(
            int(item.get("total_count") or 0)
            for item in root_summaries
            if str(item.get("scope") or "") == "current_user"
        )
        checks.append(
            make_trust_check(
                check="trusted_root_store_review",
                status="ok",
                title="Trusted root store was readable",
                detail=f"The collector counted {total_roots} trusted root entries across readable stores; {current_user_roots} were in the current-user root store.",
                recommended_action="Review current-user roots manually if browser or code-signing trust behaves unexpectedly.",
                total_roots=total_roots,
                current_user_roots=current_user_roots,
            )
        )
    else:
        checks.append(
            make_trust_check(
                check="trusted_root_store_review",
                status="unknown",
                title="Trusted root store was not collected",
                detail="The collector could not summarize the Windows trusted root stores.",
                recommended_action="Run as Administrator or verify the Windows trust store manually if TLS or code-signing validation looks broken.",
            )
        )

    return checks


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
        "check",
        "status",
        "title",
        "detail",
        "recommended_action",
        "finding_category",
        "affected_components",
        "affected_items",
        "suspicious_exclusions",
        "age_days",
        "signature_version",
        "exclusion_count",
        "total_roots",
        "current_user_roots",
        "tool",
        "artifact_role",
        "artifact_kind",
        "evidence_question",
        "source_file",
        "source_path",
        "relative_path",
        "row_number",
        "row_context",
        "size_bytes",
        "line_count",
        "sample_lines",
        "observed_time_utc",
        "timestamp_type",
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
    artifact.update(build_artifact_context(source, item))
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
        "row_number",
        "relative_path",
        "source_path",
        "executable_path",
        "path",
        "path_name",
        "check",
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
    evidence_strength: str | None = None,
) -> None:
    dedupe_key = f"{category}|{source}|{artifact_identity(source, artifact)}"
    if any(
        existing.get("_dedupe_key") == dedupe_key or dedupe_key in existing.get("_dedupe_keys", set())
        for existing in findings
    ):
        return

    grouped_artifact = compact_artifact(source, artifact)
    group_key = f"{severity}|{category}|{title}|{tool or ''}"
    strength = evidence_strength or evidence_strength_for(category, severity, confidence)
    for existing in findings:
        if existing.get("_group_key") == group_key:
            existing["artifacts"].append(grouped_artifact)
            existing["artifact_count"] = len(existing["artifacts"])
            existing["confidence"] = max(float(existing.get("confidence") or 0), round(confidence, 2))
            existing["confidence_label"] = confidence_label(float(existing.get("confidence") or 0))
            existing["evidence_strength"] = stronger_evidence(str(existing.get("evidence_strength") or "weak"), strength)
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
            "confidence_label": confidence_label(confidence),
            "evidence_strength": strength,
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
    elif category in {"rmm_vendor_log", "rmm_connection_log"}:
        finding["plain_language"] = (
            f"RMM Hunter found a vendor-specific {tool} trace or log file. This is stronger than a loose installer because it can show the tool was configured, run, "
            "or used for a session, depending on the log type."
        )
        finding["recommended_actions"] = [
            f"Preserve the {tool} log path and compare its timestamps with services, scheduled tasks, downloads, and user reports.",
            "If the log contains session or connection entries, confirm each connection with the expected IT provider before removing the tool.",
            "Export JSON for technical review. Do not publish raw logs without checking IP addresses, device IDs, usernames, and session identifiers.",
        ]
    elif category in {"kape_rmm_reference", "kape_execution_reference"}:
        finding["plain_language"] = (
            "A KAPE output file references a known remote access tool. This does not replace the original forensic artifact, but it is useful triage evidence from a DFIR collection."
        )
        finding["recommended_actions"] = [
            "Open the original KAPE output file referenced in this card and verify the row or excerpt before reporting it as fact.",
            "Map the KAPE source to the investigation question: installed, executed, connected, persisted, recently changed, or user-accessed.",
            "Keep the KAPE collection intact so another analyst can reproduce the timeline and validate the parser output.",
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
    elif category == "defender_health_issue":
        finding["plain_language"] = (
            "RMM Hunter found a Defender health signal that can make security evidence less reliable, such as disabled protection, stale security intelligence, or broad exclusions. "
            "This matters because weak or outdated Defender state can create false confidence, noisy false positives, or missed detections."
        )
        finding["recommended_actions"] = [
            "Update Defender security intelligence and confirm core protections are enabled in Windows Security.",
            "Review Defender exclusions with the device owner or IT provider, especially entries under Downloads, Temp, AppData, or wildcard paths.",
            "Rerun the scan after Defender health is normal so malware and remediation events can be interpreted with better confidence.",
        ]
    elif category == "trust_validation_issue":
        finding["plain_language"] = (
            "Windows could not validate the signature of a known signed Windows binary during the trust-health check. "
            "This can indicate broken certificate trust, catalog-store problems, or a temporary platform issue that affects how signed software is judged."
        )
        finding["recommended_actions"] = [
            "Update Windows and Defender, then rerun the scan before treating all signature or malware evidence as final.",
            "Check whether TLS, installer verification, or code-signing validation is failing in other applications.",
            "Escalate to IT if known Microsoft binaries still fail Authenticode validation after updates.",
        ]
    elif category == "trusted_root_store_issue":
        finding["plain_language"] = (
            "The Windows trusted root store contains an unusual trust signal. Root certificates control which websites and signed software this profile can trust, "
            "so unexpected entries can weaken incident confidence even when no RMM tool is present."
        )
        finding["recommended_actions"] = [
            "Confirm whether the root certificate was installed by enterprise PKI, development tooling, security tooling, or another trusted administrator.",
            "Do not delete root certificates from this app. Preserve the report and review the certificate thumbprint, subject, issuer, and scope first.",
            "If the root is unknown, investigate nearby Defender, browser, installer, and PowerShell activity before making changes.",
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


def empty_artifacts() -> dict[str, list[dict[str, Any]]]:
    return {
        "installed_programs": [],
        "services": [],
        "service_install_events": [],
        "scheduled_tasks": [],
        "startup_registry": [],
        "startup_folders": [],
        "recent_files": [],
        "rmm_vendor_logs": [],
        "kape_artifact_sources": [],
        "kape_rmm_artifacts": [],
        "defender_status": [],
        "code_signing_trust": [],
        "trusted_root_store": [],
        "defender_events": [],
        "powershell_events": [],
        "process_creation_events": [],
        "wmi_events": [],
    }


def collection_from_artifacts(artifacts: dict[str, Any], *, name: str, source_path: Path | None = None) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "scanner": {
            "name": name,
            "version": SCANNER_VERSION,
            "collected_at_utc": utc_now_iso(),
            **({"source_path": str(source_path)} if source_path else {}),
        },
        "collection": {
            "lookback_days": None,
            **({"source": "kape_output"} if source_path else {}),
        },
        "artifacts": artifacts,
        "collection_errors": [],
    }


def merge_collections(primary: dict[str, Any], secondary: dict[str, Any]) -> dict[str, Any]:
    primary_artifacts = primary.setdefault("artifacts", {})
    for key, value in (secondary.get("artifacts") or {}).items():
        if not isinstance(value, list):
            continue
        primary_artifacts.setdefault(key, [])
        if isinstance(primary_artifacts[key], list):
            primary_artifacts[key].extend(value)

    primary_errors = primary.setdefault("collection_errors", [])
    if isinstance(primary_errors, list):
        primary_errors.extend(secondary.get("collection_errors") or [])
    return primary


def classify_kape_artifact_kind(path: Path) -> str | None:
    text = str(path).lower().replace("/", "\\")
    for kind, markers in KAPE_ARTIFACT_MARKERS:
        if any(marker in text for marker in markers):
            return kind
    return None


def evidence_question_for_kind(kind: str | None, path: Path) -> str:
    path_text_lower = str(path).lower()
    if kind in {"prefetch", "amcache", "shimcache", "userassist"}:
        return "executed"
    if kind == "srum":
        return "network_or_resource_usage"
    if kind == "shellbags":
        return "user_accessed_path"
    if kind in {"scheduled_tasks", "services"}:
        return "persisted"
    if kind == "event_logs":
        return "event_log_context"
    if any(marker in path_text_lower for marker in CONNECTION_LOG_MARKERS):
        return "connected"
    return "referenced"


def safe_relative_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError as exc:
        LOGGER.debug("Could not make %s relative to %s: %s", path, root, exc)
        return str(path)


def file_sample(path: Path, limit: int = KAPE_SAMPLE_BYTES) -> str:
    try:
        with path.open("rb") as handle:
            data = handle.read(limit)
        return data.decode("utf-8", errors="ignore")
    except OSError as exc:
        LOGGER.warning("Could not read KAPE sample from %s: %s", path, exc)
        return ""


def line_count_for_sample(text: str) -> int:
    if not text:
        return 0
    return len(text.splitlines())


def build_kape_artifact(
    *,
    root: Path,
    path: Path,
    tool: str,
    artifact_kind: str | None,
    row_number: int | None = None,
    row_context: dict[str, Any] | None = None,
    sample_text: str = "",
) -> dict[str, Any]:
    try:
        stat = path.stat()
        last_write = datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat().replace("+00:00", "Z")
        size = stat.st_size
    except OSError as exc:
        LOGGER.warning("Could not stat KAPE artifact %s: %s", path, exc)
        last_write = None
        size = None

    role = "connection_log" if any(marker in path.name.lower() for marker in CONNECTION_LOG_MARKERS) else "kape_output"
    artifact = {
        "tool": tool,
        "artifact_kind": artifact_kind or "unknown",
        "artifact_role": role,
        "evidence_question": evidence_question_for_kind(artifact_kind, path),
        "source_file": path.name,
        "source_path": str(path),
        "relative_path": safe_relative_path(path, root),
        "size_bytes": size,
        "last_write_time_utc": last_write,
    }
    if row_number is not None:
        artifact["row_number"] = row_number
    if row_context:
        artifact["row_context"] = {str(k): compact_text(v, 300) for k, v in row_context.items() if v not in (None, "")}
        row_timestamp = timestamp_from_record(row_context)
        if row_timestamp:
            artifact["observed_time_utc"] = row_timestamp["time_utc"]
            artifact["timestamp_type"] = row_timestamp["field"]
    elif sample_text:
        lines = [compact_text(line, 240) for line in sample_text.splitlines() if line.strip()]
        artifact["line_count"] = line_count_for_sample(sample_text)
        artifact["sample_lines"] = lines[:12]
    return {key: value for key, value in artifact.items() if value not in (None, "", [])}


def timestamp_from_record(record: dict[str, Any]) -> dict[str, str] | None:
    for key, value in record.items():
        lowered = str(key).lower().replace(" ", "").replace("_", "")
        if not any(term.replace("_", "") in lowered for term in KAPE_TIMESTAMP_KEY_TERMS):
            continue
        parsed = parse_datetime(value)
        if not parsed:
            continue
        return {
            "field": str(key),
            "time_utc": parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
    return None


def add_kape_source_summary(sources: list[dict[str, Any]], *, root: Path, path: Path, artifact_kind: str | None) -> None:
    if not artifact_kind:
        return
    relative = safe_relative_path(path, root)
    if any(source.get("relative_path") == relative for source in sources):
        return
    sources.append(
        {
            "artifact_kind": artifact_kind,
            "source_file": path.name,
            "source_path": str(path),
            "relative_path": relative,
            "evidence_question": evidence_question_for_kind(artifact_kind, path),
        }
    )


def import_kape_output(root: Path) -> dict[str, Any]:
    root = root.resolve()
    artifacts = empty_artifacts()
    errors: list[dict[str, str]] = []
    if not root.exists() or not root.is_dir():
        raise RuntimeError(f"KAPE output folder does not exist or is not a directory: {root}")

    files_checked = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        files_checked += 1
        if files_checked > KAPE_MAX_SCAN_FILES:
            errors.append({"source": "kape_import", "message": f"Stopped after {KAPE_MAX_SCAN_FILES} files to keep import bounded."})
            break

        suffix = path.suffix.lower()
        artifact_kind = classify_kape_artifact_kind(path)
        add_kape_source_summary(artifacts["kape_artifact_sources"], root=root, path=path, artifact_kind=artifact_kind)
        if suffix not in KAPE_TEXT_SUFFIXES:
            continue

        try:
            if path.stat().st_size > KAPE_MAX_TEXT_BYTES:
                continue
        except OSError as exc:
            LOGGER.warning("Could not stat KAPE output file %s: %s", path, exc)
            continue

        path_tool = match_remote_tool(str(path))
        if suffix in {".csv", ".tsv"}:
            delimiter = "\t" if suffix == ".tsv" else ","
            try:
                with path.open("r", encoding="utf-8-sig", errors="ignore", newline="") as handle:
                    reader = csv.DictReader(handle, delimiter=delimiter)
                    for row_index, row in enumerate(reader, start=2):
                        if len(artifacts["kape_rmm_artifacts"]) >= KAPE_MAX_RMM_ARTIFACTS:
                            break
                        row_tool = match_remote_tool(row)
                        tool = row_tool or path_tool
                        if not tool:
                            continue
                        artifacts["kape_rmm_artifacts"].append(
                            build_kape_artifact(
                                root=root,
                                path=path,
                                tool=tool,
                                artifact_kind=artifact_kind,
                                row_number=row_index,
                                row_context=row,
                            )
                        )
            except (OSError, csv.Error) as exc:
                LOGGER.warning("Could not parse KAPE CSV/TSV output file %s: %s", path, exc)
                errors.append({"source": f"kape_import:{path.name}", "message": str(exc)})
            continue

        sample = file_sample(path)
        tool = path_tool or match_remote_tool(sample)
        if tool and len(artifacts["kape_rmm_artifacts"]) < KAPE_MAX_RMM_ARTIFACTS:
            artifacts["kape_rmm_artifacts"].append(
                build_kape_artifact(
                    root=root,
                    path=path,
                    tool=tool,
                    artifact_kind=artifact_kind,
                    sample_text=sample,
                )
            )

    collection = collection_from_artifacts(artifacts, name="RMM Hunter KAPE Import", source_path=root)
    collection["collection_errors"] = errors
    return collection


def analyze_artifacts(collection: dict[str, Any]) -> dict[str, Any]:
    artifacts = collection.get("artifacts") or {}
    findings: list[dict[str, Any]] = []
    system_trust_health = build_system_trust_health(artifacts)

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

    for log in artifacts.get("rmm_vendor_logs", []):
        if not isinstance(log, dict):
            continue
        tool = str(log.get("tool") or "") or match_remote_tool(log)
        if not tool:
            continue
        role = str(log.get("artifact_role") or "").lower()
        is_connection_log = role == "connection_log" or any(marker in artifact_text(log) for marker in CONNECTION_LOG_MARKERS)
        category = "rmm_connection_log" if is_connection_log else "rmm_vendor_log"
        make_finding(
            findings,
            severity="medium",
            category=category,
            title=f"Remote access vendor log found: {tool}",
            reason=(
                "Vendor-specific connection or session log evidence was found."
                if is_connection_log
                else "Vendor-specific remote access log evidence was found."
            ),
            source="rmm_vendor_logs",
            artifact=log,
            tool=tool,
            confidence=0.9 if is_connection_log else 0.82,
        )

    for artifact in artifacts.get("kape_rmm_artifacts", []):
        if not isinstance(artifact, dict):
            continue
        tool = str(artifact.get("tool") or "") or match_remote_tool(artifact)
        if not tool:
            continue
        kind = str(artifact.get("artifact_kind") or "unknown")
        question = str(artifact.get("evidence_question") or "")
        execution_like = kind in {"prefetch", "amcache", "shimcache", "userassist"} or question == "executed"
        make_finding(
            findings,
            severity="medium",
            category="kape_execution_reference" if execution_like else "kape_rmm_reference",
            title=f"KAPE output references remote access tool: {tool}",
            reason=(
                f"KAPE {kind} output references {tool}, which may support execution or user-activity timeline review."
                if execution_like
                else f"KAPE output references {tool} in a collected or parsed artifact."
            ),
            source="kape_rmm_artifacts",
            artifact=artifact,
            tool=tool,
            confidence=0.86 if execution_like else 0.78,
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
        except (TypeError, ValueError) as exc:
            LOGGER.debug("Could not parse Defender event id %r: %s", event_id, exc)
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

    for check in system_trust_health:
        if not isinstance(check, dict):
            continue
        if check.get("status") not in {"needs_review", "high_risk"}:
            continue
        severity = str(check.get("severity") or ("high" if check.get("status") == "high_risk" else "medium"))
        make_finding(
            findings,
            severity=severity,
            category=str(check.get("finding_category") or "defender_health_issue"),
            title=str(check.get("title") or "System trust health needs review"),
            reason=str(check.get("detail") or "A Windows trust or Defender health signal needs review."),
            source="system_trust_health",
            artifact=check,
            confidence=float(check.get("confidence") or 0.68),
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
        key: len(value) if isinstance(value, list) else 1 if isinstance(value, dict) else 0
        for key, value in artifacts.items()
    }
    timeline = build_timeline(findings)

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
        "timeline": timeline,
        "system_trust_health": system_trust_health,
        "artifact_counts": artifact_counts,
        "findings": findings,
        "collection_errors": collection.get("collection_errors", []),
    }


def artifact_timestamp(artifact: dict[str, Any]) -> tuple[str, str] | None:
    for key, label in (
        ("detection_time_utc", "detection"),
        ("time_created_utc", "event"),
        ("observed_time_utc", "observed"),
        ("creation_time_utc", "created"),
        ("last_write_time_utc", "last_write"),
        ("last_access_time_utc", "last_access"),
    ):
        value = artifact.get(key)
        if not value:
            continue
        parsed = parse_datetime(value)
        if parsed:
            return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"), label
    return None


def artifact_summary(artifact: dict[str, Any]) -> str:
    for key in (
        "detail",
        "message_excerpt",
        "affected_resource",
        "path",
        "source_path",
        "relative_path",
        "name",
        "display_name",
        "task_name",
    ):
        value = artifact.get(key)
        if value:
            return compact_text(value, 220)
    row_context = artifact.get("row_context")
    if isinstance(row_context, dict):
        return compact_text(" ".join(str(value) for value in row_context.values() if value), 220)
    return "Evidence artifact"


def build_timeline(findings: list[dict[str, Any]], limit: int = 200) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        for artifact in finding.get("artifacts", []) or []:
            if not isinstance(artifact, dict):
                continue
            timestamp = artifact_timestamp(artifact)
            if not timestamp:
                continue
            time_utc, timestamp_type = timestamp
            entries.append(
                {
                    "time_utc": time_utc,
                    "timestamp_type": timestamp_type,
                    "finding_id": finding.get("id"),
                    "severity": finding.get("severity"),
                    "category": finding.get("category"),
                    "title": finding.get("title"),
                    "tool": finding.get("tool") or artifact.get("tool"),
                    "artifact_source": artifact.get("source"),
                    "artifact_summary": artifact_summary(artifact),
                }
            )

    entries.sort(key=lambda entry: parse_datetime(entry.get("time_utc")) or datetime.min.replace(tzinfo=timezone.utc))
    return entries[:limit]


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

    if categories & {"rmm_vendor_log", "rmm_connection_log"}:
        recommendations.append(
            "Review vendor logs for connection times, session IDs, peer IDs, usernames, and IP addresses. Treat connection logs as stronger evidence than loose installers."
        )

    if categories & {"kape_rmm_reference", "kape_execution_reference"}:
        recommendations.append(
            "Keep the KAPE output intact and verify the original row or excerpt before reporting it. Use KAPE evidence to support the timeline, not as a replacement for source artifacts."
        )

    if any("service" in category for category in categories):
        recommendations.append(
            "Review service names, executable paths, start mode, and creation timestamps. Services from Downloads or Temp should be escalated."
        )

    if any("defender_malware" in category for category in categories):
        recommendations.append(
            "Run a Microsoft Defender full scan or offline scan and review protection history for the same timestamps shown in this report."
        )

    if any(category in {"defender_health_issue", "trust_validation_issue", "trusted_root_store_issue"} for category in categories):
        recommendations.append(
            "Review System Trust Health before acting on Defender or signature evidence. Update Defender and Windows trust components, then rerun the scan if trust health is weak."
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

    trust_health = report.get("system_trust_health") or []
    if trust_health:
        lines.append("System Trust Health")
        lines.append("-------------------")
        for check in trust_health:
            if not isinstance(check, dict):
                continue
            lines.append(f"- [{str(check.get('status') or 'unknown').upper()}] {check.get('title')}")
            if check.get("detail"):
                lines.append(f"  Detail: {single_line(check.get('detail'))}")
            if check.get("recommended_action"):
                lines.append(f"  Action: {single_line(check.get('recommended_action'))}")
        lines.append("")

    timeline = report.get("timeline") or []
    if timeline:
        lines.append("Timeline")
        lines.append("--------")
        for entry in timeline[:30]:
            tool = f" [{entry.get('tool')}]" if entry.get("tool") else ""
            lines.append(
                f"- {entry.get('time_utc')} ({entry.get('timestamp_type')}): "
                f"{entry.get('title')}{tool} - {single_line(entry.get('artifact_summary'))}"
            )
        if len(timeline) > 30:
            lines.append(f"- ... {len(timeline) - 30} additional timeline entries omitted from text summary.")
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
            if finding.get("evidence_strength") or finding.get("confidence_label"):
                lines.append(
                    "  Evidence: "
                    f"{finding.get('evidence_strength', 'unknown')} strength, "
                    f"{finding.get('confidence_label', 'unknown')} confidence"
                )
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
    if sources & {"recent_files", "startup_folders", "rmm_vendor_logs", "kape_rmm_artifacts"}:
        hints.add("file")
    if sources & {"startup_registry"}:
        hints.add("windows-registry-key")
    if sources & {"scheduled_tasks"}:
        hints.add("x-windows-scheduled-task")
    if sources & {"defender_events", "service_install_events", "system_trust_health"}:
        hints.add("x-windows-event-log-entry")
    if sources & {"rmm_vendor_logs"}:
        hints.add("x-application-log-entry")
    return sorted(hints)


def misp_attribute_hints(finding: dict[str, Any]) -> list[str]:
    hints: set[str] = set()
    for artifact in finding.get("artifacts", []):
        if not isinstance(artifact, dict):
            continue
        if any(key in artifact for key in ("path", "directory", "path_name", "executable_path", "install_location", "source_path", "relative_path")):
            hints.add("filename")
        if artifact.get("signature"):
            hints.add("text")
        if artifact.get("message_excerpt") or artifact.get("event_data") or artifact.get("row_context") or artifact.get("sample_lines"):
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
                "confidence_label": finding.get("confidence_label"),
                "evidence_strength": finding.get("evidence_strength"),
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
        "timeline": report.get("timeline") or [],
        "finding_count": len(mapped_findings),
        "findings": mapped_findings,
    }


def clone_json(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


def deep_merge_dict(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = clone_json(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge_dict(merged[key], value)
        else:
            merged[key] = value
    return merged


def default_watch_root() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "RMM Hunter" / "watch"
    return app_base_dir() / "watch"


def default_watch_config_path() -> Path:
    return default_watch_root() / "watch-config.json"


def load_watch_config(path: Path | None = None) -> dict[str, Any]:
    config = clone_json(WATCH_DEFAULT_CONFIG)
    if path and path.exists():
        loaded = load_json(path)
        if isinstance(loaded, dict):
            config = deep_merge_dict(config, loaded)
    config["mode"] = normalize_watch_mode(config.get("mode"))
    config["enabled_actions"] = normalize_action_list(config.get("enabled_actions"))
    for mode in ("daytime_auto", "night_auto"):
        configured = ((config.get("auto_actions") or {}).get(mode))
        config.setdefault("auto_actions", {})[mode] = normalize_action_list(configured)
    for key in ("approved_tools", "approved_providers", "dev_paths"):
        config[key] = normalize_string_list(config.get(key))
    return config


def write_watch_config(path: Path, config: dict[str, Any]) -> None:
    write_json(path, load_watch_config_from_dict(config))


def load_watch_config_from_dict(config: dict[str, Any]) -> dict[str, Any]:
    return deep_merge_dict(WATCH_DEFAULT_CONFIG, config or {})


def normalize_watch_mode(value: Any) -> str:
    mode = str(value or "approval_required").strip().lower()
    if mode in {"alert_only", "approval_required", "daytime_auto", "night_auto"}:
        return mode
    return "approval_required"


def normalize_string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        value = [item.strip() for item in value.split(",")]
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def normalize_action_list(value: Any) -> list[str]:
    actions = normalize_string_list(value)
    return [action for action in actions if action in WATCH_ACTIONS]


def watch_paths(state_dir: Path | None = None) -> dict[str, Path]:
    root = (state_dir or default_watch_root()).resolve()
    return {
        "root": root,
        "checkpoint": root / "checkpoint.json",
        "alerts_jsonl": root / "alerts.jsonl",
        "actions_jsonl": root / "actions.jsonl",
        "history_db": root / "watch-history.sqlite3",
        "evidence": root / "evidence",
        "snapshots": root / "snapshots",
    }


def ensure_watch_state(state_dir: Path | None = None) -> dict[str, Path]:
    paths = watch_paths(state_dir)
    for key in ("root", "evidence", "snapshots"):
        paths[key].mkdir(parents=True, exist_ok=True)
    init_watch_db(paths["history_db"])
    return paths


def init_watch_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                time_utc TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                source TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'new',
                summary TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                time_utc TEXT NOT NULL,
                applied INTEGER NOT NULL,
                result_json TEXT NOT NULL
            )
            """
        )
        connection.commit()


def append_jsonl(path: Path, item: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(item, ensure_ascii=True, sort_keys=False) + "\n")


def load_watch_checkpoint(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"schema_version": WATCH_SCHEMA_VERSION, "seen_signatures": {}}
    try:
        checkpoint = load_json(path)
        if isinstance(checkpoint, dict):
            checkpoint.setdefault("schema_version", WATCH_SCHEMA_VERSION)
            checkpoint.setdefault("seen_signatures", {})
            return checkpoint
    except (OSError, json.JSONDecodeError) as exc:
        LOGGER.warning("Could not load Watch checkpoint %s: %s", path, exc)
    return {"schema_version": WATCH_SCHEMA_VERSION, "seen_signatures": {}}


def save_watch_checkpoint(path: Path, checkpoint: dict[str, Any]) -> None:
    checkpoint["updated_at_utc"] = utc_now_iso()
    write_json(path, checkpoint)


def update_watch_checkpoint(checkpoint: dict[str, Any], alerts: list[dict[str, Any]]) -> None:
    seen = checkpoint.setdefault("seen_signatures", {})
    for alert in alerts:
        signature = str(alert.get("dedupe_signature") or "")
        if signature:
            seen[signature] = alert.get("time_utc") or utc_now_iso()


def watch_alert_signature(finding: dict[str, Any]) -> str:
    artifacts = [artifact for artifact in finding.get("artifacts", []) if isinstance(artifact, dict)]
    first = artifacts[0] if artifacts else {}
    source = str(first.get("source") or finding.get("category") or "")
    raw = "|".join(
        [
            str(finding.get("category") or ""),
            str(finding.get("title") or ""),
            str(finding.get("tool") or first.get("tool") or ""),
            artifact_identity(source, first) if first else "",
        ]
    )
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()


def watch_alert_id(signature: str) -> str:
    return f"rmmw-{signature[:16]}"


def watch_alert_severity(finding: dict[str, Any]) -> str:
    category = str(finding.get("category") or "")
    if category in WATCH_CRITICAL_CATEGORIES:
        return "critical"
    severity = str(finding.get("severity") or "low").lower()
    return severity if severity in WATCH_SEVERITY_ORDER else "low"


def watch_alert_confidence(finding: dict[str, Any]) -> str:
    label = str(finding.get("confidence_label") or "").lower()
    if label in WATCH_CONFIDENCE_ORDER:
        return label
    try:
        return confidence_label(float(finding.get("confidence") or 0))
    except (TypeError, ValueError) as exc:
        LOGGER.debug("Could not parse Watch finding confidence %r: %s", finding.get("confidence"), exc)
        return "low"


def finding_source(finding: dict[str, Any]) -> str:
    for artifact in finding.get("artifacts", []) or []:
        if isinstance(artifact, dict) and artifact.get("source"):
            return str(artifact.get("source"))
    return str(finding.get("category") or "scanner")


def finding_to_watch_alert(finding: dict[str, Any], report: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    signature = watch_alert_signature(finding)
    evidence = [
        clone_json(artifact)
        for artifact in finding.get("artifacts", []) or []
        if isinstance(artifact, dict)
    ][:5]
    alert = {
        "schema_version": WATCH_SCHEMA_VERSION,
        "alert_id": watch_alert_id(signature),
        "dedupe_signature": signature,
        "time_utc": alert_time_from_finding(finding),
        "severity": watch_alert_severity(finding),
        "confidence": watch_alert_confidence(finding),
        "rule_id": str(finding.get("category") or "unknown_rule"),
        "source": finding_source(finding),
        "summary": str(finding.get("title") or finding.get("reason") or "RMM Hunter Watch alert"),
        "details": str(finding.get("plain_language") or finding.get("reason") or ""),
        "evidence": evidence,
        "finding": {
            "id": finding.get("id"),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "category": finding.get("category"),
            "tool": finding.get("tool"),
            "confidence": finding.get("confidence"),
            "confidence_label": finding.get("confidence_label"),
            "evidence_strength": finding.get("evidence_strength"),
            "artifact_count": finding.get("artifact_count"),
        },
        "recommended_actions": [],
        "mode": normalize_watch_mode(config.get("mode")),
        "deterministic_verdict": report.get("verdict"),
        "risk_score": report.get("risk_score"),
        "status": "new",
        "created_by": "deterministic_rules",
        "files_changed": 0,
    }
    alert["recommended_actions"] = recommended_watch_actions(alert, config)
    return alert


def alert_time_from_finding(finding: dict[str, Any]) -> str:
    for artifact in finding.get("artifacts", []) or []:
        if not isinstance(artifact, dict):
            continue
        timestamp = artifact_timestamp(artifact)
        if timestamp:
            return timestamp[0]
    return utc_now_iso()


def recommended_watch_actions(alert: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
    severity = str(alert.get("severity") or "low")
    rule_id = str(alert.get("rule_id") or "")
    candidates = ["preserve_evidence", "send_alert"]
    if rule_id == "defender_malware_event":
        candidates.extend(["defender_full_scan", "open_protection_history", "recommend_kape_collection"])
    elif "defender" in rule_id:
        candidates.append("open_protection_history")
    if "rmm" in rule_id or "service" in rule_id or severity in {"high", "critical"}:
        candidates.append("recommend_kape_collection")
    if severity == "critical":
        candidates.append("network_isolate")

    seen: set[str] = set()
    rows: list[dict[str, Any]] = []
    for action_id in candidates:
        if action_id in seen or action_id not in WATCH_ACTIONS:
            continue
        seen.add(action_id)
        decision = watch_action_decision(alert, action_id, config, manual_approval=False)
        action = WATCH_ACTIONS[action_id]
        rows.append(
            {
                "action_id": action_id,
                "label": action["label"],
                "type": action["type"],
                "reversible": action["reversible"],
                "auto_allowed": decision["allowed"],
                "approval_required": decision["approval_required"],
                "reason": decision["reason"],
            }
        )
    return rows


def new_watch_alerts(report: dict[str, Any], checkpoint: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
    seen = checkpoint.get("seen_signatures") if isinstance(checkpoint.get("seen_signatures"), dict) else {}
    alerts: list[dict[str, Any]] = []
    for finding in report.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        category = str(finding.get("category") or "")
        if category not in WATCH_ALERT_CATEGORIES:
            continue
        alert = finding_to_watch_alert(finding, report, config)
        if alert["dedupe_signature"] in seen:
            continue
        alerts.append(alert)
    alerts.sort(key=lambda alert: (WATCH_SEVERITY_ORDER.get(str(alert.get("severity")), 0), alert.get("time_utc", "")), reverse=True)
    return alerts


def record_watch_alerts(alerts: list[dict[str, Any]], state_dir: Path | None = None) -> None:
    if not alerts:
        return
    paths = ensure_watch_state(state_dir)
    with sqlite3.connect(paths["history_db"]) as connection:
        for alert in alerts:
            payload = json.dumps(alert, ensure_ascii=True, sort_keys=False)
            connection.execute(
                """
                INSERT OR IGNORE INTO alerts
                    (alert_id, time_utc, severity, confidence, rule_id, source, status, summary, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.get("alert_id"),
                    alert.get("time_utc"),
                    alert.get("severity"),
                    alert.get("confidence"),
                    alert.get("rule_id"),
                    alert.get("source"),
                    alert.get("status", "new"),
                    alert.get("summary"),
                    payload,
                ),
            )
            append_jsonl(paths["alerts_jsonl"], alert)
        connection.commit()


def load_recent_watch_alerts(state_dir: Path | None = None, limit: int = 30) -> list[dict[str, Any]]:
    paths = ensure_watch_state(state_dir)
    with sqlite3.connect(paths["history_db"]) as connection:
        rows = connection.execute(
            "SELECT payload_json FROM alerts ORDER BY time_utc DESC LIMIT ?",
            (limit,),
        ).fetchall()
    alerts = []
    for (payload,) in rows:
        try:
            alerts.append(json.loads(payload))
        except json.JSONDecodeError as exc:
            LOGGER.warning("Could not parse stored Watch alert: %s", exc)
    return alerts


def load_watch_alert(state_dir: Path | None, alert_id: str) -> dict[str, Any]:
    paths = ensure_watch_state(state_dir)
    with sqlite3.connect(paths["history_db"]) as connection:
        row = connection.execute("SELECT payload_json FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    if not row:
        raise RuntimeError(f"Watch alert was not found: {alert_id}")
    return json.loads(row[0])


def alert_text(alert: dict[str, Any]) -> str:
    return artifact_text(alert)


def alert_tool_is_approved(alert: dict[str, Any], config: dict[str, Any]) -> bool:
    approved = [item.lower() for item in normalize_string_list(config.get("approved_tools"))]
    if not approved:
        return False
    tool = str((alert.get("finding") or {}).get("tool") or "").lower()
    text = alert_text(alert)
    return any(item and (item in tool or item in text) for item in approved)


def alert_provider_is_approved(alert: dict[str, Any], config: dict[str, Any]) -> bool:
    approved = [item.lower() for item in normalize_string_list(config.get("approved_providers"))]
    text = alert_text(alert)
    return bool(approved and any(item and item in text for item in approved))


def alert_path_is_protected(alert: dict[str, Any]) -> bool:
    text = alert_text(alert).replace("/", "\\").lower()
    return any(marker in text for marker in WATCH_PROTECTED_PATH_MARKERS)


def watch_action_decision(
    alert: dict[str, Any],
    action_id: str,
    config: dict[str, Any] | None = None,
    *,
    manual_approval: bool = False,
) -> dict[str, Any]:
    config = load_watch_config_from_dict(config or {})
    mode = normalize_watch_mode(config.get("mode"))
    action = WATCH_ACTIONS.get(action_id)
    if not action:
        return {"allowed": False, "approval_required": True, "reason": "Unknown action ID."}
    if action_id not in normalize_action_list(config.get("enabled_actions")):
        return {"allowed": False, "approval_required": True, "reason": "Action is disabled in local policy."}
    if mode == "alert_only":
        if action_id in {"preserve_evidence", "send_alert"}:
            return {"allowed": True, "approval_required": False, "reason": "Alert-only mode permits evidence and alert records only."}
        return {"allowed": False, "approval_required": True, "reason": "Alert-only mode never performs containment actions."}

    severity = str(alert.get("severity") or "low")
    confidence = str(alert.get("confidence") or "low")
    is_hard = action_id in WATCH_HARD_ACTIONS

    if manual_approval:
        if action_id == "block_suspicious_path":
            return {"allowed": False, "approval_required": True, "reason": "Execution blocking is preview-only in this release."}
        return {"allowed": True, "approval_required": False, "reason": "Operator approval provided."}

    if action_id in WATCH_SOFT_ACTIONS and mode == "approval_required":
        return {"allowed": False, "approval_required": True, "reason": "Default mode records alerts and asks before running response actions."}

    if is_hard and mode not in {"daytime_auto", "night_auto"}:
        return {"allowed": False, "approval_required": True, "reason": "Hard containment requires an auto-response mode or explicit approval."}
    if WATCH_CONFIDENCE_ORDER.get(confidence, 0) < WATCH_CONFIDENCE_ORDER["high"]:
        return {"allowed": False, "approval_required": True, "reason": "Low or medium confidence requires approval."}
    if WATCH_SEVERITY_ORDER.get(severity, 0) < WATCH_SEVERITY_ORDER["high"]:
        return {"allowed": False, "approval_required": True, "reason": "Auto-response requires high or critical severity."}
    if alert_tool_is_approved(alert, config) or alert_provider_is_approved(alert, config):
        return {"allowed": False, "approval_required": True, "reason": "Approved tool or provider suppresses auto containment."}
    if is_hard and alert_path_is_protected(alert):
        return {"allowed": False, "approval_required": True, "reason": "Protected Windows or business-app path requires approval."}
    if action_id not in normalize_action_list((config.get("auto_actions") or {}).get(mode)):
        return {"allowed": False, "approval_required": True, "reason": f"Action is not configured for {mode}."}
    return {"allowed": True, "approval_required": False, "reason": f"Policy permits {mode} auto-response."}


AI_FORBIDDEN_ACTION_TEXT = (
    "powershell",
    "cmd.exe",
    "bash",
    "sh -c",
    "wmic",
    "reg add",
    "reg delete",
    "schtasks",
    "netsh",
    "del ",
    "remove-item",
    "rm ",
    "curl ",
    "invoke-webrequest",
)


def sanitize_alert_for_ai(alert: dict[str, Any]) -> dict[str, Any]:
    allowed_action_ids = [
        action.get("action_id")
        for action in alert.get("recommended_actions", [])
        if isinstance(action, dict) and action.get("action_id") in WATCH_ACTIONS
    ]
    return {
        "alert_id": alert.get("alert_id"),
        "time_utc": alert.get("time_utc"),
        "severity": alert.get("severity"),
        "confidence": alert.get("confidence"),
        "rule_id": alert.get("rule_id"),
        "source": alert.get("source"),
        "summary": compact_text(alert.get("summary"), 400),
        "details": compact_text(alert.get("details"), 700),
        "allowed_action_ids": allowed_action_ids,
        "evidence": clone_json(alert.get("evidence", [])[:3]),
    }


def extract_ai_action_ids(ai_choice: Any) -> list[str]:
    if isinstance(ai_choice, str):
        return [ai_choice]
    if isinstance(ai_choice, list):
        return [str(item) for item in ai_choice]
    if not isinstance(ai_choice, dict):
        return []
    if isinstance(ai_choice.get("action_ids"), list):
        return [str(item) for item in ai_choice["action_ids"]]
    if isinstance(ai_choice.get("actions"), list):
        return [
            str(item.get("action_id") if isinstance(item, dict) else item)
            for item in ai_choice["actions"]
        ]
    if ai_choice.get("action_id"):
        return [str(ai_choice["action_id"])]
    return []


def validate_ai_action_choice(alert: dict[str, Any], ai_choice: Any, config: dict[str, Any] | None = None) -> dict[str, Any]:
    serialized = json.dumps(ai_choice, ensure_ascii=True, default=str).lower()
    if any(term in serialized for term in AI_FORBIDDEN_ACTION_TEXT):
        return {
            "accepted": False,
            "reason": "AI output contained command-like text. Only action IDs are accepted.",
            "accepted_actions": [],
            "deterministic": {"severity": alert.get("severity"), "confidence": alert.get("confidence")},
        }

    action_ids = extract_ai_action_ids(ai_choice)
    if not action_ids:
        return {
            "accepted": False,
            "reason": "AI output did not choose an action ID.",
            "accepted_actions": [],
            "deterministic": {"severity": alert.get("severity"), "confidence": alert.get("confidence")},
        }

    unknown = [action_id for action_id in action_ids if action_id not in WATCH_ACTIONS]
    if unknown:
        return {
            "accepted": False,
            "reason": f"AI output included unknown action ID: {', '.join(unknown)}.",
            "accepted_actions": [],
            "deterministic": {"severity": alert.get("severity"), "confidence": alert.get("confidence")},
        }

    accepted = []
    rejected = []
    for action_id in action_ids:
        decision = watch_action_decision(alert, action_id, config, manual_approval=False)
        row = {"action_id": action_id, **decision}
        if decision["allowed"]:
            accepted.append(row)
        else:
            rejected.append(row)

    return {
        "accepted": bool(accepted),
        "reason": "Accepted pre-approved action IDs." if accepted else "No selected AI action passed deterministic policy gates.",
        "accepted_actions": accepted,
        "rejected_actions": rejected,
        "deterministic": {"severity": alert.get("severity"), "confidence": alert.get("confidence")},
    }


def discord_webhook_is_allowed(value: str) -> bool:
    try:
        url = urllib.parse.urlparse(value)
    except Exception as exc:
        LOGGER.info("Rejected Discord webhook URL: %s", exc)
        return False
    return url.scheme == "https" and url.netloc.lower() in {"discord.com", "discordapp.com"} and url.path.startswith("/api/webhooks/")


def send_discord_alert(alert: dict[str, Any], webhook_url: str) -> dict[str, Any]:
    if not webhook_url:
        return {"sent": False, "reason": "Discord webhook is not configured."}
    if not discord_webhook_is_allowed(webhook_url):
        return {"sent": False, "reason": "Discord webhook URL is not an allowed Discord webhook endpoint."}

    content = {
        "username": "RMM Hunter Watch",
        "embeds": [
            {
                "title": f"{str(alert.get('severity') or 'unknown').upper()} - {alert.get('summary')}",
                "description": compact_text(alert.get("details") or "Review RMM Hunter Watch alert history.", 900),
                "color": discord_color(alert.get("severity")),
                "fields": [
                    {"name": "Alert ID", "value": str(alert.get("alert_id")), "inline": True},
                    {"name": "Rule", "value": str(alert.get("rule_id")), "inline": True},
                    {"name": "Confidence", "value": str(alert.get("confidence")), "inline": True},
                ],
                "timestamp": alert.get("time_utc") or utc_now_iso(),
            }
        ],
    }
    payload = json.dumps(content).encode("utf-8")
    request = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": f"RMM-Hunter/{SCANNER_VERSION}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return {"sent": 200 <= response.status < 300, "status": response.status}
    except urllib.error.URLError as exc:
        LOGGER.warning("Discord Watch alert failed: %s", exc)
        return {"sent": False, "reason": str(exc)}


def discord_color(severity: Any) -> int:
    return {
        "critical": 0x8B0000,
        "high": 0xBC2E37,
        "medium": 0xA96500,
        "low": 0x315F9F,
    }.get(str(severity or "").lower(), 0x687386)


def build_watch_collection(args: argparse.Namespace, config: dict[str, Any]) -> dict[str, Any]:
    if getattr(args, "input", None):
        collection = load_json(args.input)
    elif getattr(args, "kape_root", None):
        collection = import_kape_output(args.kape_root)
    else:
        paths = watch_paths(getattr(args, "state_dir", None))
        artifacts_out = paths["snapshots"] / f"watch_artifacts_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
        collection = run_collector(
            collector=getattr(args, "collector", app_base_dir() / "collect_windows.ps1"),
            artifacts_out=artifacts_out,
            lookback_days=int(config.get("lookback_days") or 1),
            max_recent_files=int(config.get("max_recent_files") or 300),
        )

    if getattr(args, "input", None) and getattr(args, "kape_root", None):
        collection = merge_collections(collection, import_kape_output(args.kape_root))
    return collection


def run_watch_once(args: argparse.Namespace, config: dict[str, Any]) -> dict[str, Any]:
    paths = ensure_watch_state(getattr(args, "state_dir", None))
    checkpoint = load_watch_checkpoint(paths["checkpoint"])
    collection = build_watch_collection(args, config)
    report = analyze_artifacts(collection)
    alerts = new_watch_alerts(report, checkpoint, config)
    record_watch_alerts(alerts, paths["root"])
    update_watch_checkpoint(checkpoint, alerts)
    save_watch_checkpoint(paths["checkpoint"], checkpoint)
    result = {
        "schema_version": WATCH_SCHEMA_VERSION,
        "scanner": {
            "name": "RMM Hunter Watch",
            "version": SCANNER_VERSION,
            "generated_at_utc": utc_now_iso(),
        },
        "mode": normalize_watch_mode(config.get("mode")),
        "state_dir": str(paths["root"]),
        "alert_count": len(alerts),
        "alerts": alerts,
        "recent_alerts": load_recent_watch_alerts(paths["root"]),
        "report": report,
        "policy": public_watch_policy(config),
    }
    for alert in alerts:
        for action in alert.get("recommended_actions", []):
            if action.get("action_id") == "send_alert" and action.get("auto_allowed"):
                discord = ((config.get("alert_sinks") or {}).get("discord") or {})
                if discord.get("enabled"):
                    send_discord_alert(alert, str(discord.get("webhook_url") or ""))
    return result


def public_watch_policy(config: dict[str, Any]) -> dict[str, Any]:
    return {
        "mode": normalize_watch_mode(config.get("mode")),
        "poll_interval_seconds": int(config.get("poll_interval_seconds") or 15),
        "reconcile_interval_seconds": int(config.get("reconcile_interval_seconds") or 300),
        "approved_tools_count": len(normalize_string_list(config.get("approved_tools"))),
        "approved_providers_count": len(normalize_string_list(config.get("approved_providers"))),
        "dev_paths_count": len(normalize_string_list(config.get("dev_paths"))),
        "discord_enabled": bool(((config.get("alert_sinks") or {}).get("discord") or {}).get("enabled")),
        "enabled_actions": normalize_action_list(config.get("enabled_actions")),
    }


def run_watch_loop(args: argparse.Namespace, config: dict[str, Any]) -> int:
    interval = max(10, int(config.get("poll_interval_seconds") or 15))
    print(f"RMM Hunter Watch running every {interval} seconds. Press Ctrl+C to stop.")
    try:
        while True:
            result = run_watch_once(args, config)
            print(f"{utc_now_iso()} alerts={result['alert_count']} mode={result['mode']}")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("RMM Hunter Watch stopped.")
        return 0


def record_watch_action(state_dir: Path | None, alert_id: str, action_id: str, applied: bool, result: dict[str, Any]) -> None:
    paths = ensure_watch_state(state_dir)
    row = {
        "alert_id": alert_id,
        "action_id": action_id,
        "time_utc": utc_now_iso(),
        "applied": applied,
        "result": result,
    }
    append_jsonl(paths["actions_jsonl"], row)
    with sqlite3.connect(paths["history_db"]) as connection:
        connection.execute(
            """
            INSERT INTO actions (alert_id, action_id, time_utc, applied, result_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (alert_id, action_id, row["time_utc"], 1 if applied else 0, json.dumps(result, ensure_ascii=True)),
        )
        connection.commit()


def run_response_action(
    alert: dict[str, Any],
    action_id: str,
    config: dict[str, Any],
    state_dir: Path | None,
    *,
    apply: bool,
) -> dict[str, Any]:
    decision = watch_action_decision(alert, action_id, config, manual_approval=apply)
    if apply and not decision["allowed"]:
        result = {"applied": False, "decision": decision}
        record_watch_action(state_dir, str(alert.get("alert_id")), action_id, False, result)
        return result
    if not apply:
        result = {"applied": False, "dry_run": True, "decision": decision, "action": WATCH_ACTIONS.get(action_id)}
        record_watch_action(state_dir, str(alert.get("alert_id")), action_id, False, result)
        return result

    if action_id == "preserve_evidence":
        result = preserve_watch_evidence(alert, state_dir)
    elif action_id == "send_alert":
        discord = ((config.get("alert_sinks") or {}).get("discord") or {})
        result = send_discord_alert(alert, str(discord.get("webhook_url") or "")) if discord.get("enabled") else {"sent": False, "reason": "Discord is disabled."}
    elif action_id in {"defender_quick_scan", "defender_full_scan"}:
        result = start_defender_scan(action_id)
    elif action_id == "open_protection_history":
        result = open_defender_protection_history()
    elif action_id == "recommend_kape_collection":
        result = {"applied": True, "message": "Recommendation recorded. Collect KAPE output and import it into RMM Hunter for deeper review."}
    elif action_id == "network_isolate":
        result = set_network_isolation(True)
    elif action_id == "release_network_isolation":
        result = set_network_isolation(False)
    elif action_id == "stop_process":
        result = stop_alert_process(alert)
    elif action_id == "stop_service":
        result = stop_alert_service(alert)
    elif action_id == "disable_scheduled_task":
        result = disable_alert_task(alert)
    else:
        result = {"applied": False, "reason": "Action is not implemented in this preview."}
    record_watch_action(state_dir, str(alert.get("alert_id")), action_id, bool(result.get("applied") or result.get("sent")), result)
    return result


def preserve_watch_evidence(alert: dict[str, Any], state_dir: Path | None = None) -> dict[str, Any]:
    paths = ensure_watch_state(state_dir)
    output = paths["evidence"] / f"{alert.get('alert_id', 'alert')}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    write_json(output, alert)
    return {"applied": True, "path": str(output), "rollback": "Evidence snapshots are files. Delete manually only after retention policy allows it."}


def start_defender_scan(action_id: str) -> dict[str, Any]:
    scan_type = "FullScan" if action_id == "defender_full_scan" else "QuickScan"
    powershell = find_powershell()
    if not powershell:
        return {"applied": False, "reason": "PowerShell was not found."}
    command = [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", f"Start-MpScan -ScanType {scan_type}"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    return {
        "applied": result.returncode == 0,
        "scan_type": scan_type,
        "exit_code": result.returncode,
        "stdout": compact_text(result.stdout, 500),
        "stderr": compact_text(result.stderr, 500),
    }


def open_defender_protection_history() -> dict[str, Any]:
    try:
        subprocess.Popen(["cmd", "/c", "start", "", "windowsdefender:"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"applied": True, "message": "Opened Windows Security. Use Protection history to review Defender actions."}
    except OSError as exc:
        LOGGER.warning("Could not open Windows Security: %s", exc)
        return {"applied": False, "reason": str(exc)}


def set_network_isolation(enable: bool) -> dict[str, Any]:
    rule_names = [
        "RMM Hunter Watch Emergency Isolation Outbound",
        "RMM Hunter Watch Emergency Isolation Inbound",
    ]
    commands = (
        [
            ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_names[0]}", "dir=out", "action=block", "enable=yes"],
            ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_names[1]}", "dir=in", "action=block", "enable=yes"],
        ]
        if enable
        else [
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_names[0]}"],
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_names[1]}"],
        ]
    )
    results = []
    for command in commands:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        results.append({"command": command[:4], "exit_code": result.returncode, "stderr": compact_text(result.stderr, 300)})
    return {
        "applied": all(item["exit_code"] == 0 for item in results),
        "enabled": enable,
        "results": results,
        "rollback": "Use release_network_isolation to remove RMM Hunter Watch firewall isolation rules.",
    }


def first_alert_value(alert: dict[str, Any], keys: Iterable[str]) -> str:
    for artifact in alert.get("evidence", []) or []:
        if not isinstance(artifact, dict):
            continue
        value = first_present(artifact, keys)
        if value not in (None, "", []):
            return str(value)
    return ""


def stop_alert_process(alert: dict[str, Any]) -> dict[str, Any]:
    pid = first_alert_value(alert, ("process_id", "pid", "ProcessId"))
    if not re.fullmatch(r"\d{1,10}", pid or ""):
        return {"applied": False, "reason": "Alert did not include a process ID."}
    result = subprocess.run(["taskkill", "/PID", pid, "/T", "/F"], capture_output=True, text=True, timeout=30)
    return {"applied": result.returncode == 0, "pid": pid, "exit_code": result.returncode, "stderr": compact_text(result.stderr, 300)}


def stop_alert_service(alert: dict[str, Any]) -> dict[str, Any]:
    service = first_alert_value(alert, ("service_name", "name", "Name"))
    if not re.fullmatch(r"[A-Za-z0-9_. -]{1,120}", service or ""):
        return {"applied": False, "reason": "Alert did not include a safe service name."}
    powershell = find_powershell()
    if not powershell:
        return {"applied": False, "reason": "PowerShell was not found."}
    result = subprocess.run(
        [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Stop-Service -Name $args[0] -ErrorAction Stop", service],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return {"applied": result.returncode == 0, "service": service, "exit_code": result.returncode, "stderr": compact_text(result.stderr, 300), "rollback": "Start the service again if containment was not needed."}


def disable_alert_task(alert: dict[str, Any]) -> dict[str, Any]:
    task = first_alert_value(alert, ("task_name", "TaskName", "name"))
    if not task or len(task) > 260:
        return {"applied": False, "reason": "Alert did not include a scheduled task name."}
    result = subprocess.run(["schtasks", "/Change", "/TN", task, "/Disable"], capture_output=True, text=True, timeout=30)
    return {"applied": result.returncode == 0, "task": task, "exit_code": result.returncode, "stderr": compact_text(result.stderr, 300), "rollback": "Re-enable the scheduled task if it was authorized."}


def install_watch_task(config_path: Path, state_dir: Path | None = None) -> dict[str, Any]:
    state = ensure_watch_state(state_dir)
    cli = Path(sys.executable if getattr(sys, "frozen", False) else __file__).resolve()
    if getattr(sys, "frozen", False):
        command = f'"{cli}" watch --config "{config_path}" --state-dir "{state["root"]}"'
    else:
        command = f'"{sys.executable}" "{cli}" watch --config "{config_path}" --state-dir "{state["root"]}"'
    result = subprocess.run(
        ["schtasks", "/Create", "/TN", WATCH_TASK_NAME, "/SC", "ONLOGON", "/RL", "LIMITED", "/F", "/TR", command],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return {"applied": result.returncode == 0, "task_name": WATCH_TASK_NAME, "exit_code": result.returncode, "stderr": compact_text(result.stderr, 500), "command": command}


def remove_watch_task() -> dict[str, Any]:
    result = subprocess.run(["schtasks", "/Delete", "/TN", WATCH_TASK_NAME, "/F"], capture_output=True, text=True, timeout=30)
    return {"applied": result.returncode == 0, "task_name": WATCH_TASK_NAME, "exit_code": result.returncode, "stderr": compact_text(result.stderr, 500)}


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
    parser.add_argument("--kape-root", type=Path, help="Import RMM-related evidence from a KAPE output folder.")
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


def parse_watch_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="rmm-hunter watch",
        description="Run RMM Hunter Watch preview for always-on alerting and policy-gated response."
    )
    parser.add_argument("--config", type=Path, default=None, help="Watch policy JSON path.")
    parser.add_argument("--state-dir", type=Path, default=default_watch_root(), help="Local Watch checkpoint and history directory.")
    parser.add_argument("--input", type=Path, help="Analyze an existing collector artifacts JSON file instead of live collection.")
    parser.add_argument("--kape-root", type=Path, help="Include KAPE output when generating Watch alerts.")
    parser.add_argument("--collector", type=Path, default=app_base_dir() / "collect_windows.ps1", help="PowerShell collector path.")
    parser.add_argument("--once", action="store_true", help="Run one Watch delta check and exit.")
    parser.add_argument("--install-task", action="store_true", help="Install the current Watch policy as a Windows scheduled task.")
    parser.add_argument("--remove-task", action="store_true", help="Remove the RMM Hunter Watch scheduled task.")
    parser.add_argument("--json-out", type=Path, help="Write Watch result JSON.")
    parser.add_argument("--print-alerts", action="store_true", help="Print generated alerts to stdout as JSON.")
    return parser.parse_args(argv)


def parse_respond_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="rmm-hunter respond",
        description="Dry-run or apply a pre-approved RMM Hunter Watch response action."
    )
    parser.add_argument("--config", type=Path, default=None, help="Watch policy JSON path.")
    parser.add_argument("--state-dir", type=Path, default=default_watch_root(), help="Local Watch checkpoint and history directory.")
    parser.add_argument("--alert-id", required=True, help="Watch alert ID.")
    parser.add_argument("--action", required=True, dest="action_id", help="Action ID to dry-run or apply.")
    parser.add_argument("--dry-run", action="store_true", help="Show what would happen without applying the action.")
    parser.add_argument("--apply", action="store_true", help="Apply the action as an operator-approved response.")
    parser.add_argument("--json-out", type=Path, help="Write response result JSON.")
    return parser.parse_args(argv)


def main_watch(argv: list[str]) -> int:
    args = parse_watch_args(argv)
    try:
        config = load_watch_config(args.config)
        if args.install_task:
            config_path = args.config or default_watch_config_path()
            if not config_path.exists():
                write_json(config_path, config)
            result = install_watch_task(config_path, args.state_dir)
            write_optional_result(args.json_out, result)
            print(json.dumps(result, indent=2))
            return 0 if result.get("applied") else 1
        if args.remove_task:
            result = remove_watch_task()
            write_optional_result(args.json_out, result)
            print(json.dumps(result, indent=2))
            return 0 if result.get("applied") else 1
        if args.once:
            result = run_watch_once(args, config)
            write_optional_result(args.json_out, result)
            if args.print_alerts:
                print(json.dumps(result["alerts"], indent=2))
            else:
                print(f"Watch alerts: {result['alert_count']}")
                print(f"Watch state: {result['state_dir']}")
            return 0
        return run_watch_loop(args, config)
    except Exception as exc:
        print(f"RMM Hunter Watch failed: {exc}", file=sys.stderr)
        return 1


def main_respond(argv: list[str]) -> int:
    args = parse_respond_args(argv)
    try:
        if args.apply and args.dry_run:
            raise RuntimeError("Use either --dry-run or --apply, not both.")
        apply_action = bool(args.apply)
        config = load_watch_config(args.config)
        alert = load_watch_alert(args.state_dir, args.alert_id)
        result = run_response_action(alert, args.action_id, config, args.state_dir, apply=apply_action)
        write_optional_result(args.json_out, result)
        print(json.dumps(result, indent=2))
        return 0 if not apply_action or result.get("applied") or result.get("sent") else 1
    except Exception as exc:
        print(f"RMM Hunter response failed: {exc}", file=sys.stderr)
        return 1


def write_optional_result(path: Path | None, result: dict[str, Any]) -> None:
    if path:
        write_json(path, result)


def main(argv: list[str] | None = None) -> int:
    raw_args = argv or sys.argv[1:]
    if raw_args:
        command = raw_args[0].lower()
        if command == "watch":
            return main_watch(raw_args[1:])
        if command == "respond":
            return main_respond(raw_args[1:])

    args = parse_args(raw_args)

    try:
        if args.input:
            collection = load_json(args.input)
        elif args.kape_root:
            collection = import_kape_output(args.kape_root)
        else:
            collection = run_collector(
                collector=args.collector,
                artifacts_out=args.artifacts_out,
                lookback_days=args.lookback_days,
                max_recent_files=args.max_recent_files,
            )

        if args.input and args.kape_root:
            collection = merge_collections(collection, import_kape_output(args.kape_root))

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
            if args.kape_root:
                print(f"KAPE import: {args.kape_root}")
            if not args.input and not args.kape_root:
                print(f"Raw artifacts: {args.artifacts_out}")
        return 0
    except Exception as exc:
        print(f"RMM Hunter failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
