# Windows Code Signing

RMM Hunter currently builds unsigned Windows artifacts. This is expected until MDP Studio has a public code-signing option.

Unsigned artifacts:

- show `Unknown publisher`
- can trigger Microsoft Defender SmartScreen
- can still be used for testing and draft releases

## Recommended Path

For free open-source signing, apply to SignPath Foundation first. The project policy is documented in `docs/CODE_SIGNING_POLICY.md`.

The GitHub release workflow is SignPath-ready. It checks for these repository settings without printing their values:

- secret `SIGNPATH_API_TOKEN`
- variable `SIGNPATH_ORGANIZATION_ID`
- variable `SIGNPATH_PROJECT_SLUG`
- variable `SIGNPATH_SIGNING_POLICY_SLUG`

When all four are present, the workflow uploads the unsigned setup and portable executables to SignPath, waits for the signing request, replaces the release executables with the signed outputs, refreshes `latest.yml` and the setup blockmap, regenerates `SHA256SUMS.txt` and `rmm-hunter-release-manifest.json`, then requires `Status : Valid` from `Get-AuthenticodeSignature`.

When any setting is absent, the workflow records `unsigned-beta` signing mode and requires release docs to stay honest about `NotSigned` artifacts.

Use Microsoft Artifact Signing when MDP Studio is ready to publish broadly under its own publisher identity. It is the cleanest paid path for GitHub Actions because signing happens through a managed Microsoft service instead of a local certificate file or USB token.

Traditional OV code-signing certificates from a certificate authority are also valid, but modern public code-signing private keys generally require hardware-backed storage or a managed signing service.

Do not use a self-signed certificate for public releases. It is useful only for local testing or enterprise environments that explicitly trust your certificate.

## Electron Builder Configuration

Keep signing disabled until the certificate or managed signing service exists:

```json
"win": {
  "icon": "gui/assets/icon.ico",
  "signAndEditExecutable": false,
  "verifyUpdateCodeSignature": false
}
```

After Microsoft Artifact Signing is configured, enable signing and add Azure signing options:

```json
"win": {
  "icon": "gui/assets/icon.ico",
  "signAndEditExecutable": true,
  "verifyUpdateCodeSignature": true,
  "azureSignOptions": {
    "publisherName": "Exact certificate publisher name",
    "endpoint": "https://YOUR-ENDPOINT.codesigning.azure.net",
    "certificateProfileName": "YOUR_PROFILE",
    "codeSigningAccountName": "YOUR_ACCOUNT"
  }
}
```

Never commit Microsoft, certificate authority, or signing credentials to the repository. Store them as GitHub Actions secrets or environment variables.

## Verification

After a signed build:

```powershell
Get-AuthenticodeSignature .\release\RMM-Hunter-Setup-*-x64.exe
Get-AuthenticodeSignature .\release\RMM-Hunter-Portable-*-x64.exe
```

Expected result:

```text
Status : Valid
```

Release builds also generate `SHA256SUMS.txt`, `rmm-hunter-release-manifest.json`, and `VERIFY_RELEASE.md` beside the Windows artifacts. The release workflow runs `scripts/verify-release-artifacts.ps1` to confirm those files match the final executables. See `docs/VERIFY_RELEASE.md` for the full download verification workflow.

## Icon

The Windows app icon is tracked in:

```text
gui/assets/icon.ico
```

Source files:

```text
gui/assets/icon.svg
gui/assets/icon.png
```

Regenerate with ImageMagick:

```powershell
magick .\gui\assets\icon.svg -resize 1024x1024 .\gui\assets\icon.png
magick .\gui\assets\icon.png -define icon:auto-resize=256,128,64,48,32,16 .\gui\assets\icon.ico
```

## References

- Microsoft Windows code-signing options: https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options
- Electron Builder Windows signing: https://www.electron.build/code-signing-win.html
- SignPath Foundation: https://signpath.org/
- CA/Browser Forum code-signing requirements: https://cabforum.org/working-groups/code-signing/requirements/
