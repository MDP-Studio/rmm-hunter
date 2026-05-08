# Verify A Release

Use these checks before trusting a downloaded RMM Hunter Windows artifact.

## 1. Download Release Files

Download the release asset you want to test from GitHub Releases, plus:

- `SHA256SUMS.txt`
- `rmm-hunter-release-manifest.json`
- `VERIFY_RELEASE.md`

## 2. Verify SHA256

From the folder containing the downloaded files:

```powershell
Get-FileHash .\RMM-Hunter-Setup-0.1.1-x64.exe -Algorithm SHA256
Get-FileHash .\RMM-Hunter-Portable-0.1.1-x64.exe -Algorithm SHA256
```

Compare the hashes with `SHA256SUMS.txt` and the matching entries in `rmm-hunter-release-manifest.json`.

## 3. Verify Authenticode Signature

```powershell
Get-AuthenticodeSignature .\RMM-Hunter-Setup-0.1.1-x64.exe | Format-List
Get-AuthenticodeSignature .\RMM-Hunter-Portable-0.1.1-x64.exe | Format-List
```

Current unsigned beta builds are expected to show:

```text
Status : NotSigned
```

Future signed builds should show:

```text
Status : Valid
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

The source SHA should match the release tag in the public repository.

## 5. Expected Windows Friction

Unsigned beta builds may show `Unknown publisher`, browser download warnings, or Microsoft Defender SmartScreen prompts.

Do not treat an unsigned build as a broadly trusted public security tool. Use it for testing, then prefer a signed release once the project has an approved signing path.
