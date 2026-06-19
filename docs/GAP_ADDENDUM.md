# RMM Hunter Gap Addendum

Date: 2026-05-18

This addendum captures the highest-leverage gaps to close before expanding RMM Hunter's detector breadth or platform scope.

## Priority Summary

| Gap | Priority | Confidence | Next slice |
| --- | --- | --- | --- |
| Release trust and provenance | P1 | High | Complete code-signing path and publish verification instructions alongside release assets. |
| Detection interoperability | P1 | Medium | Add an optional mapped output profile without changing the deterministic verdict model. |
| Coverage measurement | P2 | High | Add a repeatable eval harness and release scorecard. |
| ATT&CK and D3FEND mapping | P2 | Medium | Ship an evidence source to rule to technique matrix. |

## Implementation Status

| Gap | Status through 0.2.0 | Remaining work |
| --- | --- | --- |
| Release trust and provenance | Partially addressed with workflow-generated `SHA256SUMS.txt`, `rmm-hunter-release-manifest.json`, `VERIFY_RELEASE.md`, installer update flow, conditional SignPath workflow support, and release artifact verification gates. | Complete SignPath approval and repository secret/variable setup, then test SmartScreen and install friction on 3 clean Windows hosts. |
| Detection interoperability | Addressed for the second slice with `--mapped-out`, profile `rmm-hunter.detection-mapping.v1`, evidence strength, confidence labels, timeline export, optional STIX 2.1 custom-object bundle export, and optional MISP event JSON export. | Validate 20 representative findings in one SIEM or TI workflow before adding connector-specific upload automation. |
| Coverage measurement | Addressed for the first slice with `scripts/evaluate_corpus.py`, `tests/corpus/manifest.json`, `docs/COVERAGE_SCORECARD.md`, and an AnyDesk connection-trace corpus case. | Expand the seeded corpus and publish scorecard deltas in release notes. |
| ATT&CK and D3FEND mapping | Addressed for current native and imported RMM rules with `docs/DETECTION_MAPPING.md` and matching mappings in the mapped export. | Review mappings with an external analyst and remove any label that is not grounded in actual evidence. |

## 0.2.0 Addendum

The next investigation-readiness slices are now implemented:

- Native RMM vendor log collection for common Windows locations.
- KAPE output import mode for RMM references in parsed artifact collections.
- Evidence strength and confidence labels in findings and exports.
- Timeline output for JSON, text, PDF, GUI, and AI-safe summaries.
- RMM artifact source matrix and investigation cheat sheet.
- Optional `--stix-out` and `--misp-out` CTI package exports derived after
  deterministic verdict calculation.

These changes improve operator confidence and follow-up investigation quality. They do not remove the remaining release-trust gap: public Windows builds still need a trusted code-signing path before broad distribution.

## Release Trust And Provenance

Why it matters: security tools are more likely to be blocked, quarantined, or distrusted when they are unsigned and lack clear build provenance.

Fastest validation:

- Produce one signed release candidate.
- Test download, install, launch, and scan friction on 3 clean Windows hosts.
- Record SmartScreen, Defender, browser download, and installer warnings.

Next slice:

- Complete SignPath Foundation approval and configure the release workflow secret/variables.
- Publish release verification instructions beside release assets, including SHA256 hashes and Authenticode checks.
- Keep release notes explicit about whether artifacts are unsigned, SignPath-signed, or signed under an MDP Studio publisher identity.

Avoid:

- Expanding detector breadth before release trust is fixed.
- Claiming broad public trust while artifacts are still unsigned.

## Detection Interoperability

Why it matters: SOC and incident-response teams adopt faster when findings can move into existing detection, case-management, and threat-intelligence workflows.

Fastest validation:

- Export 20 representative findings into a normalized schema.
- Test ingestion into one SIEM or threat-intelligence workflow.
- Confirm the output preserves artifact evidence, severity, timestamp context, and rule identity.

Next slice:

- Validate 20 representative findings in one SIEM or threat-intelligence workflow.
- Add connector-specific upload automation only after the JSON handoff format has been exercised by a real responder.
- Keep the core `clean`, `needs_review`, and `high_risk` verdict model deterministic and unchanged.

Avoid:

- Overbuilding SIEM or threat-intelligence integrations before there is a stable schema contract.
- Letting interoperability exports change rule behavior or verdict calculation.

## Coverage Measurement

Why it matters: RMM abuse and living-off-the-land tradecraft change quickly, including legitimate-tool abuse and SimpleHelp-style RMM incidents. RMM Hunter needs regression evidence, not broad efficacy claims.

Fastest validation:

- Maintain a seeded corpus with clean, benign-admin, suspicious, and malicious-like traces.
- Track precision, recall, false positives, and false negatives for every release.
- Include at least one recent-RMM-abuse regression case per release cycle when safe, public evidence exists.

Next slice:

- Add a repeatable eval harness for known sample artifact JSON files.
- Publish a compact scorecard in release notes.
- Add new rules only when they improve measured outcomes or cover a documented blind spot.

Avoid:

- Claiming broad endpoint security coverage without measured regressions.
- Treating one noisy high-risk result as proof of better detection.

## ATT&CK And D3FEND Mapping

Why it matters: analysts and buyers trust tools more when evidence maps to explicit techniques, data sources, and defensive concepts.

Fastest validation:

- Map current rules to ATT&CK data sources and relevant techniques.
- Review the mapping with one external analyst or practitioner.
- Confirm each mapping points to actual collected evidence, not generic marketing language.

Next slice:

- Ship a compact matrix:
  - evidence source
  - collector artifact
  - rule identifier
  - severity behavior
  - ATT&CK data source or technique
  - optional D3FEND defensive concept

Avoid:

- Adding ATT&CK labels that are not grounded in the actual artifact and rule logic.
- Presenting technique mappings as proof of detection quality without eval results.

## Working Order

1. Finish release trust and provenance.
2. Add verification instructions and keep release artifacts reproducible.
3. Freeze a normalized finding schema.
4. Add interoperability exports against that schema.
5. Build the seeded corpus and eval harness.
6. Publish scorecards and technique mapping together, so coverage claims have evidence behind them.

## References

- CISA, NSA, and MS-ISAC advisory on malicious use of legitimate RMM software: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a
- CISA advisory on SimpleHelp RMM exploitation: https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-163a
- MITRE ATT&CK data sources: https://attack.mitre.org/datasources/
- MITRE D3FEND: https://d3fend.mitre.org/
