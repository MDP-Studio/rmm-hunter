# Windows Code Signing

RMM Hunter currently builds unsigned Windows artifacts. This is expected until MDP Studio has a public code-signing option.

Unsigned artifacts:

- show `Unknown publisher`
- can trigger Microsoft Defender SmartScreen
- can still be used for testing and draft releases

## Recommended Path

Use Microsoft Artifact Signing when MDP Studio is ready to publish broadly. It is the cleanest path for GitHub Actions because signing happens through a managed Microsoft service instead of a local certificate file or USB token.

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
Get-AuthenticodeSignature .\release\RMM-Hunter-Setup-0.1.0-x64.exe
Get-AuthenticodeSignature .\release\RMM-Hunter-Portable-0.1.0-x64.exe
```

Expected result:

```text
Status : Valid
```

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
- CA/Browser Forum code-signing requirements: https://cabforum.org/working-groups/code-signing/requirements/
