param(
    [string]$ReleaseDir = "release",
    [string]$SourceRef = $env:GITHUB_REF_NAME,
    [string]$SourceSha = $env:GITHUB_SHA,
    [string]$Repository = $env:GITHUB_REPOSITORY,
    [string]$RunId = $env:GITHUB_RUN_ID,
    [string]$RunUrl = ""
)

$ErrorActionPreference = "Stop"

$releasePath = Resolve-Path -LiteralPath $ReleaseDir
$artifactPatterns = @(
    "RMM-Hunter-Setup-*.exe",
    "RMM-Hunter-Setup-*.exe.blockmap",
    "latest.yml",
    "RMM-Hunter-Portable-*.exe"
)

$files = foreach ($pattern in $artifactPatterns) {
    Get-ChildItem -LiteralPath $releasePath -File -Filter $pattern
}

if (-not $files) {
    throw "No release artifacts found in $releasePath"
}

$artifacts = @()
$shaLines = @()

foreach ($file in ($files | Sort-Object Name)) {
    $hash = Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256
    $signature = $null
    if ($file.Extension -ieq ".exe") {
        try {
            $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
        } catch {
            $signature = $null
        }
    }

    $authenticode = [ordered]@{
        status = if ($file.Extension -ine ".exe") { "NotApplicable" } elseif ($signature) { $signature.Status.ToString() } else { "Unavailable" }
        status_message = if ($signature -and $signature.StatusMessage) { $signature.StatusMessage } else { "" }
        signer_subject = if ($signature -and $signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { "" }
        thumbprint = if ($signature -and $signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint } else { "" }
    }

    $artifacts += [ordered]@{
        name = $file.Name
        size_bytes = $file.Length
        sha256 = $hash.Hash.ToLowerInvariant()
        authenticode = $authenticode
    }
    $shaLines += "$($hash.Hash.ToLowerInvariant())  $($file.Name)"
}

$manifest = [ordered]@{
    schema_version = "1.0"
    project = "RMM Hunter"
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    source = [ordered]@{
        repository = $Repository
        ref = $SourceRef
        sha = $SourceSha
        workflow_run_id = $RunId
        workflow_run_url = $RunUrl
    }
    artifacts = $artifacts
}

$manifestPath = Join-Path $releasePath "rmm-hunter-release-manifest.json"
$shaPath = Join-Path $releasePath "SHA256SUMS.txt"
$verifySource = Join-Path $PSScriptRoot "..\docs\VERIFY_RELEASE.md"
$verifyTarget = Join-Path $releasePath "VERIFY_RELEASE.md"

$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding utf8
$shaLines | Set-Content -LiteralPath $shaPath -Encoding ascii

if (Test-Path -LiteralPath $verifySource) {
    Copy-Item -LiteralPath $verifySource -Destination $verifyTarget -Force
}

Write-Host "Wrote $manifestPath"
Write-Host "Wrote $shaPath"
if (Test-Path -LiteralPath $verifyTarget) {
    Write-Host "Wrote $verifyTarget"
}
