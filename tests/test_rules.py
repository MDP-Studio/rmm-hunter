import importlib.util
import json
from pathlib import Path
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

    def test_mapped_detection_export_preserves_verdict_and_mappings(self):
        sample = json.loads((ROOT / "tests" / "sample_artifacts_high_risk.json").read_text(encoding="utf-8"))
        report = rmm_hunter.analyze_artifacts(sample)
        mapped = rmm_hunter.build_mapped_detection_export(report)

        self.assertEqual(mapped["profile"], "rmm-hunter.detection-mapping.v1")
        self.assertEqual(mapped["verdict"], report["verdict"])
        self.assertEqual(mapped["risk_score"], report["risk_score"])
        rule_ids = {finding["rule_id"] for finding in mapped["findings"]}
        self.assertIn("known_rmm_service", rule_ids)
        sigma_tags = {
            tag
            for finding in mapped["findings"]
            for tag in finding["interoperability"]["sigma_tags"]
        }
        self.assertIn("attack.t1219", sigma_tags)
        self.assertIn("attack.t1059.001", sigma_tags)


if __name__ == "__main__":
    unittest.main()
