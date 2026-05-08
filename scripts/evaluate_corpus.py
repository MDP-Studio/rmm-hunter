#!/usr/bin/env python3
"""Evaluate RMM Hunter against a seeded artifact corpus."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "rmm_hunter.py"


def load_scanner():
    spec = importlib.util.spec_from_file_location("rmm_hunter", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    if spec.loader is None:
        raise RuntimeError("Could not load rmm_hunter.py")
    spec.loader.exec_module(module)
    return module


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")


def evaluate_case(scanner: Any, case: dict[str, Any]) -> dict[str, Any]:
    artifact_path = ROOT / str(case["path"])
    report = scanner.analyze_artifacts(load_json(artifact_path))
    expected_categories = set(case.get("expected_categories") or [])
    observed_categories = {str(finding.get("category")) for finding in report.get("findings", [])}
    errors = []

    if report.get("verdict") != case.get("expected_verdict"):
        errors.append(f"expected verdict {case.get('expected_verdict')}, got {report.get('verdict')}")

    missing_categories = sorted(expected_categories - observed_categories)
    if missing_categories:
        errors.append(f"missing categories: {', '.join(missing_categories)}")

    expected_positive = case.get("expected_verdict") != "clean"
    observed_positive = report.get("verdict") != "clean"

    return {
        "id": case.get("id"),
        "path": case.get("path"),
        "expected_verdict": case.get("expected_verdict"),
        "observed_verdict": report.get("verdict"),
        "expected_positive": expected_positive,
        "observed_positive": observed_positive,
        "risk_score": report.get("risk_score"),
        "finding_count": len(report.get("findings") or []),
        "observed_categories": sorted(observed_categories),
        "missing_categories": missing_categories,
        "passed": not errors,
        "errors": errors,
    }


def safe_rate(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 1.0
    return round(numerator / denominator, 4)


def build_scorecard(results: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(results)
    passed = sum(1 for result in results if result["passed"])
    true_positive = sum(1 for result in results if result["expected_positive"] and result["observed_positive"])
    false_positive = sum(1 for result in results if not result["expected_positive"] and result["observed_positive"])
    true_negative = sum(1 for result in results if not result["expected_positive"] and not result["observed_positive"])
    false_negative = sum(1 for result in results if result["expected_positive"] and not result["observed_positive"])

    return {
        "schema_version": "1.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scanner": "RMM Hunter",
        "total_cases": total,
        "passed_cases": passed,
        "failed_cases": total - passed,
        "exact_verdict_accuracy": safe_rate(passed, total),
        "review_or_high_precision": safe_rate(true_positive, true_positive + false_positive),
        "review_or_high_recall": safe_rate(true_positive, true_positive + false_negative),
        "confusion": {
            "true_positive": true_positive,
            "false_positive": false_positive,
            "true_negative": true_negative,
            "false_negative": false_negative,
        },
        "cases": results,
    }


def render_markdown(scorecard: dict[str, Any]) -> str:
    lines = [
        "# RMM Hunter Coverage Scorecard",
        "",
        f"Generated at UTC: `{scorecard['generated_at_utc']}`",
        "",
        "This scorecard is a seeded regression check, not a claim of broad endpoint-security efficacy.",
        "",
        "## Summary",
        "",
        f"- Total cases: {scorecard['total_cases']}",
        f"- Passed cases: {scorecard['passed_cases']}",
        f"- Failed cases: {scorecard['failed_cases']}",
        f"- Exact verdict accuracy: {scorecard['exact_verdict_accuracy']}",
        f"- Review-or-high precision: {scorecard['review_or_high_precision']}",
        f"- Review-or-high recall: {scorecard['review_or_high_recall']}",
        "",
        "## Cases",
        "",
        "| Case | Expected | Observed | Categories | Result |",
        "| --- | --- | --- | --- | --- |",
    ]
    for case in scorecard["cases"]:
        result = "pass" if case["passed"] else "fail"
        categories = ", ".join(case["observed_categories"]) or "none"
        lines.append(
            f"| {case['id']} | {case['expected_verdict']} | {case['observed_verdict']} | {categories} | {result} |"
        )
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate RMM Hunter against the seeded test corpus.")
    parser.add_argument("--manifest", type=Path, default=ROOT / "tests" / "corpus" / "manifest.json")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--markdown-out", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    scanner = load_scanner()
    manifest = load_json(args.manifest if args.manifest.is_absolute() else ROOT / args.manifest)
    results = [evaluate_case(scanner, case) for case in manifest.get("cases", [])]
    scorecard = build_scorecard(results)

    if args.json_out:
        write_json(args.json_out, scorecard)
    if args.markdown_out:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.write_text(render_markdown(scorecard), encoding="utf-8")

    print(
        f"Corpus evaluation: {scorecard['passed_cases']}/{scorecard['total_cases']} passed; "
        f"exact accuracy {scorecard['exact_verdict_accuracy']}; "
        f"review/high precision {scorecard['review_or_high_precision']}; "
        f"review/high recall {scorecard['review_or_high_recall']}"
    )

    for result in results:
        if not result["passed"]:
            print(f"{result['id']}: {'; '.join(result['errors'])}", file=sys.stderr)

    return 0 if scorecard["failed_cases"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
