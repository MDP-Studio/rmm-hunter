# Code Signing Policy

RMM Hunter is an open-source Windows endpoint scanner published from:

```text
https://github.com/MDP-Studio/rmm-hunter
```

## Current Status

Current RMM Hunter beta artifacts are unsigned builds. They are suitable for testing, but Windows may show `Unknown publisher` or Microsoft Defender SmartScreen warnings.

The release workflow is conditional:

- if SignPath credentials and project variables are configured, SignPath signing is required and release verification must see Authenticode `Status : Valid`;
- if SignPath is not configured, the workflow may create unsigned beta artifacts, but the manifest must record `unsigned-beta` mode and public docs must keep the SmartScreen and `Unknown publisher` warning.

Signed releases also require two public repository variables:

- `WINDOWS_PUBLISHER_SUBJECT`: the exact X.509 subject expected on both files
- `WINDOWS_PUBLISHER_CERTIFICATE_SHA256`: one or more approved certificate
  SHA-256 fingerprints, separated by commas during a documented rotation

The release manifest publishes these values under `signing.expected_publisher`.
The verification gate fails if a signed artifact is valid but belongs to another
publisher or certificate. Certificate rotation must briefly list both old and
new fingerprints, then remove the old fingerprint after the transition release.

The project intends to use SignPath Foundation for free open-source Windows code signing if accepted. When enabled, release artifacts will state:

```text
Free code signing provided by SignPath.io, certificate by SignPath Foundation.
```

## What Will Be Signed

The intended signed artifacts are:

- `RMM-Hunter-Setup-*-x64.exe`
- `RMM-Hunter-Portable-*-x64.exe`

The GitHub Actions workflow builds these artifacts from the public source repository on GitHub-hosted Windows runners.

## Maintainer Roles

Project maintainer, committer, reviewer, and signing approver:

- Meidie, MDP Studio

Repository owners:

- `https://github.com/orgs/MDP-Studio/people?query=role%3Aowner`

All maintainers and signing approvers must keep multi-factor authentication enabled for GitHub and SignPath accounts.

## Release Integrity

Release builds must pass the project verification gate before publication:

- JavaScript syntax checks
- Python compile and unit tests
- `npm audit --audit-level=moderate`
- `pip-audit -r requirements-build.txt`
- Windows package build
- release artifact verification for Authenticode state, SHA256 checksums, release manifest, `latest.yml`, and `VERIFY_RELEASE.md`
- published-release verification against GitHub asset digests and the public tag commit
- manual smoke test where practical

Signing credentials, SignPath API tokens, certificate material, AI provider keys, and other secrets must never be committed to the repository.

## Security Tool Scope

RMM Hunter detects suspicious remote management tools and breach traces on a Windows device that the user owns, administers, or has permission to inspect.

It does not exploit systems, bypass security controls, attack services, scan networks, remove files, uninstall tools, stop services, quarantine artifacts, or change Windows settings by default.

## Privacy

RMM Hunter does not transfer scan reports, artifacts, telemetry, analytics, or usage data by default.

See `PRIVACY.md` for the full privacy policy.
