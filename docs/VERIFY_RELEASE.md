# Verify A Release

Use these checks before trusting a downloaded RMM Hunter Windows artifact.

## Recommended: Run The Published-Release Verifier

From a clean clone of the public repository, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-published-release.ps1 -Tag v0.3.4 -ReportPath .\rmm-hunter-v0.3.4-verification.json
```

The verifier obtains release metadata and the tag commit from GitHub, downloads
every required asset into a temporary directory, and fails unless all of these
checks agree:

- GitHub release asset name, byte size, and SHA-256 digest
- `SHA256SUMS.txt` and `rmm-hunter-release-manifest.json`
- the manifest source repository, tag, and full commit SHA
- the `latest.yml` installer SHA-512 and byte size
- the actual Authenticode state of both Windows executables
- the pinned publisher subject and certificate SHA-256 for future signed builds

The optional JSON report is machine-readable and contains no scan data. The
temporary executable downloads are removed after verification.

Release `v0.3.4` uses the legacy `1.0` manifest. It records `NotSigned` on both
executables but predates the top-level `signing.mode` field. The verifier accepts
that legacy release only when both executable entries and both downloaded files
are exactly `NotSigned`. Manifest schema `1.1` and newer must explicitly declare
`unsigned-beta` or `signpath`.

## Manual Flow: 1. Download Release Files

Download the release asset you want to test from GitHub Releases, plus:

- `SHA256SUMS.txt`
- `rmm-hunter-release-manifest.json`
- `VERIFY_RELEASE.md`
- `latest.yml` if you are verifying installed-app auto-update metadata

## 2. Verify SHA256

From the folder containing the downloaded files:

```powershell
Get-FileHash .\RMM-Hunter-Setup-<version>-x64.exe -Algorithm SHA256
Get-FileHash .\RMM-Hunter-Portable-<version>-x64.exe -Algorithm SHA256
```

Compare the hashes with `SHA256SUMS.txt` and the matching entries in `rmm-hunter-release-manifest.json`. Installed Windows builds also use the `sha512` value in `latest.yml` for Electron auto-update integrity checks. The release workflow verifies these values before uploading assets.

## 3. Verify Authenticode Signature

```powershell
Get-AuthenticodeSignature .\RMM-Hunter-Setup-<version>-x64.exe | Format-List
Get-AuthenticodeSignature .\RMM-Hunter-Portable-<version>-x64.exe | Format-List
```

Current unsigned beta builds are expected to show:

```text
Status : NotSigned
```

Future signed builds should show:

```text
Status : Valid
```

For a signed manifest, compare the actual certificate SHA-256 and subject with
`signing.expected_publisher`:

```powershell
$signature = Get-AuthenticodeSignature .\RMM-Hunter-Setup-<version>-x64.exe
$sha256 = [System.Security.Cryptography.SHA256]::Create()
try {
  $certificateSha256 = -join ($sha256.ComputeHash($signature.SignerCertificate.RawData) | ForEach-Object { $_.ToString('x2') })
} finally {
  $sha256.Dispose()
}
$signature.SignerCertificate.Subject
$certificateSha256
```

If SignPath Foundation signing is enabled, release notes should also state:

```text
Free code signing provided by SignPath.io, certificate by SignPath Foundation.
```

## 4. Check Build Provenance

Open `rmm-hunter-release-manifest.json` and compare:

- `source.repository`
- `source.ref`
- `source.sha`
- `source.workflow_run_url`
- `signing.mode`
- `signing.expected_publisher.subject`
- `signing.expected_publisher.certificate_sha256`

The source SHA should match the release tag in the public repository.
If `signing.mode` is `signpath`, the setup and portable executables should have Authenticode `Status : Valid`. If it is `unsigned-beta`, `Status : NotSigned` is expected and the release should be treated as beta only.

## 5. Verify In Windows Explorer

1. Right-click the downloaded installer and choose **Properties**.
2. For the current unsigned beta, confirm there is no **Digital Signatures**
   tab. If Windows opens a consent prompt, the publisher should be shown as
   **Unknown publisher**. Cancel unless you have completed the checksum checks.
3. For a future signed release, open **Digital Signatures**, select the
   signature, choose **Details**, then **View Certificate**.
4. Confirm Windows reports the signature as valid and compare the certificate
   subject and SHA-256 fingerprint with `signing.expected_publisher` in the
   release manifest. A valid signature from a different publisher is a failure.
5. Never click **Run anyway** merely because the file came from the project
   website. The website is a pointer; the GitHub release evidence is the trust
   source.

## 6. Expected Windows Friction

Unsigned beta builds may show `Unknown publisher`, browser download warnings, or Microsoft Defender SmartScreen prompts.

Do not treat an unsigned build as a broadly trusted public security tool. Use it for testing, then prefer a signed release once the project has an approved signing path.
