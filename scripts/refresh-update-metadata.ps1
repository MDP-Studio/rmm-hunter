param(
    [string]$ReleaseDir = "release"
)

$ErrorActionPreference = "Stop"

$releasePath = Resolve-Path -LiteralPath $ReleaseDir
$setupArtifacts = @(
    Get-ChildItem -LiteralPath $releasePath -File -Filter "RMM-Hunter-Setup-*.exe" |
        Sort-Object Name
)

if ($setupArtifacts.Count -ne 1) {
    throw "Expected exactly one setup artifact in $releasePath; found $($setupArtifacts.Count)."
}

$setup = $setupArtifacts[0]
$packageJson = Get-Content -LiteralPath (Join-Path $PSScriptRoot "..\package.json") -Raw | ConvertFrom-Json
$sha512Provider = [System.Security.Cryptography.SHA512]::Create()
try {
    $sha512 = [Convert]::ToBase64String(
        $sha512Provider.ComputeHash([System.IO.File]::ReadAllBytes($setup.FullName))
    )
} finally {
    $sha512Provider.Dispose()
}

$latestPath = Join-Path $releasePath "latest.yml"
$releaseDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
@"
version: $($packageJson.version)
files:
  - url: $($setup.Name)
    sha512: $sha512
    size: $($setup.Length)
path: $($setup.Name)
sha512: $sha512
releaseDate: '$releaseDate'
"@ | Set-Content -LiteralPath $latestPath -Encoding utf8

$appBuilder = & node -e "process.stdout.write(require('app-builder-bin').appBuilderPath)"
if (-not $appBuilder -or -not (Test-Path -LiteralPath $appBuilder)) {
    throw "app-builder-bin is not available. Run npm ci before refreshing release metadata."
}

$blockmapPath = "$($setup.FullName).blockmap"
& $appBuilder blockmap --input $setup.FullName --output $blockmapPath
if ($LASTEXITCODE -ne 0) {
    throw "app-builder blockmap generation failed with exit code $LASTEXITCODE."
}

Write-Host "Refreshed $latestPath"
Write-Host "Refreshed $blockmapPath"
