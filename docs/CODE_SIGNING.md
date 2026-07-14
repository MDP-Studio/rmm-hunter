# Windows Code Signing

Public `v0.3.4` is a historical unsigned beta. The repository now blocks every new Windows release until a trusted SignPath signing route is configured.

## Required Repository Settings

- secret `SIGNPATH_API_TOKEN`
- variable `SIGNPATH_ORGANIZATION_ID`
- variable `SIGNPATH_PROJECT_SLUG`
- variable `SIGNPATH_SIGNING_POLICY_SLUG`
- variable `WINDOWS_PUBLISHER_SUBJECT`
- variable `WINDOWS_PUBLISHER_CERTIFICATE_SHA256`

The certificate variable accepts one or more comma-separated SHA-256 fingerprints for a documented certificate rotation. Do not commit signing credentials or certificate private keys.

## Fail-Closed Release Sequence

1. Build the Python scanner and unpacked Electron application.
2. Submit `RMM Hunter.exe` and `rmm-hunter-cli.exe` to SignPath.
3. Replace the unsigned inner files and verify `Status : Valid`, the exact subject, and an approved certificate fingerprint.
4. Package setup and portable executables from the signed unpacked application.
5. Submit both distributable executables to SignPath.
6. Replace and verify the signed outputs, then regenerate `latest.yml`, the blockmap, checksums, and release manifest.
7. Create a draft release only after every gate passes.

Missing configuration is an error. There is no unsigned fallback in `.github/workflows/release.yml`.

## Electron Builder Configuration

`signAndEditExecutable` stays `false` because SignPath performs external signing in the controlled two-stage workflow. `verifyUpdateCodeSignature` is `true`, so future installed builds reject update installers whose signer does not match the installed application.

Local `npm.cmd run dist` output is unsigned developer output. It must not be uploaded, tagged, or distributed as a release.

## Verification

The workflow uses `scripts/verify-authenticode.ps1` for inner executables and `scripts/verify-release-artifacts.ps1 -RequireSigned` for final artifacts. Manual verification remains:

```powershell
Get-AuthenticodeSignature .\release\RMM-Hunter-Setup-*-x64.exe
Get-AuthenticodeSignature .\release\RMM-Hunter-Portable-*-x64.exe
```

Expected result is `Status : Valid` and the signer must match `signing.expected_publisher` in `rmm-hunter-release-manifest.json`.

Do not use a self-signed certificate for public releases.

## References

- Microsoft Windows code-signing options: https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options
- Electron Builder Windows signing: https://www.electron.build/code-signing-win.html
- SignPath Foundation: https://signpath.org/
- CA/Browser Forum code-signing requirements: https://cabforum.org/working-groups/code-signing/requirements/
