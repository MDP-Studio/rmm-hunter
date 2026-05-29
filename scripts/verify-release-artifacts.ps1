param(
    [string]$ReleaseDir = "release",
    [switch]$RequireSigned
)

$ErrorActionPreference = "Stop"

function Fail($Message) {
    throw "[release-verify] $Message"
}

function Get-Sha256Lower($Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-Sha512Base64($Path) {
    $sha512Provider = [System.Security.Cryptography.SHA512]::Create()
    try {
        return [Convert]::ToBase64String(
            $sha512Provider.ComputeHash([System.IO.File]::ReadAllBytes($Path))
        )
    } finally {
        $sha512Provider.Dispose()
    }
}

$releasePath = Resolve-Path -LiteralPath $ReleaseDir
$requiredSidecars = @("SHA256SUMS.txt", "rmm-hunter-release-manifest.json", "VERIFY_RELEASE.md", "latest.yml")
foreach ($name in $requiredSidecars) {
    if (-not (Test-Path -LiteralPath (Join-Path $releasePath $name))) {
        Fail "Missing required release sidecar: $name"
    }
}

$setupArtifacts = @(Get-ChildItem -LiteralPath $releasePath -File -Filter "RMM-Hunter-Setup-*.exe" | Sort-Object Name)
$portableArtifacts = @(Get-ChildItem -LiteralPath $releasePath -File -Filter "RMM-Hunter-Portable-*.exe" | Sort-Object Name)
if ($setupArtifacts.Count -ne 1) {
    Fail "Expected exactly one setup artifact; found $($setupArtifacts.Count)."
}
if ($portableArtifacts.Count -ne 1) {
    Fail "Expected exactly one portable artifact; found $($portableArtifacts.Count)."
}

$blockmapPath = "$($setupArtifacts[0].FullName).blockmap"
if (-not (Test-Path -LiteralPath $blockmapPath)) {
    Fail "Missing setup blockmap: $(Split-Path -Path $blockmapPath -Leaf)"
}

$shaEntries = @{}
foreach ($line in Get-Content -LiteralPath (Join-Path $releasePath "SHA256SUMS.txt")) {
    if (-not $line.Trim()) {
        continue
    }
    if ($line -notmatch "^([a-fA-F0-9]{64})\s+\s(.+)$") {
        Fail "Malformed SHA256SUMS line: $line"
    }
    $shaEntries[$Matches[2]] = $Matches[1].ToLowerInvariant()
}

$manifestPath = Join-Path $releasePath "rmm-hunter-release-manifest.json"
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.schema_version -ne "1.0") {
    Fail "Unexpected manifest schema version: $($manifest.schema_version)"
}
if (-not $manifest.source.repository -or -not $manifest.source.sha) {
    Fail "Manifest source metadata is incomplete."
}

$manifestArtifacts = @{}
foreach ($artifact in $manifest.artifacts) {
    $manifestArtifacts[$artifact.name] = $artifact
}

$expectedArtifactNames = @(
    $setupArtifacts[0].Name,
    $portableArtifacts[0].Name,
    (Split-Path -Path $blockmapPath -Leaf),
    "latest.yml"
)

foreach ($name in $expectedArtifactNames) {
    $path = Join-Path $releasePath $name
    if (-not (Test-Path -LiteralPath $path)) {
        Fail "Missing expected artifact: $name"
    }
    if (-not $shaEntries.ContainsKey($name)) {
        Fail "SHA256SUMS.txt does not contain $name"
    }
    if (-not $manifestArtifacts.ContainsKey($name)) {
        Fail "Release manifest does not contain $name"
    }
    $actualSha = Get-Sha256Lower $path
    if ($shaEntries[$name] -ne $actualSha) {
        Fail "SHA256SUMS hash mismatch for $name"
    }
    if ($manifestArtifacts[$name].sha256 -ne $actualSha) {
        Fail "Release manifest hash mismatch for $name"
    }
    if ([int64]$manifestArtifacts[$name].size_bytes -ne (Get-Item -LiteralPath $path).Length) {
        Fail "Release manifest size mismatch for $name"
    }
}

foreach ($exe in @($setupArtifacts[0], $portableArtifacts[0])) {
    $signature = Get-AuthenticodeSignature -LiteralPath $exe.FullName
    $status = $signature.Status.ToString()
    $manifestStatus = $manifestArtifacts[$exe.Name].authenticode.status
    if ($manifestStatus -ne $status) {
        Fail "Manifest Authenticode status for $($exe.Name) is $manifestStatus, actual is $status."
    }
    if ($RequireSigned) {
        if ($status -ne "Valid") {
            Fail "$($exe.Name) must be signed, but Authenticode status is $status."
        }
    } elseif ($status -notin @("NotSigned", "Valid")) {
        Fail "$($exe.Name) has unexpected Authenticode status for beta release: $status."
    }
}

$latestText = Get-Content -LiteralPath (Join-Path $releasePath "latest.yml") -Raw
$setupName = $setupArtifacts[0].Name
$setupSha512 = Get-Sha512Base64 $setupArtifacts[0].FullName
if ($latestText -notmatch [regex]::Escape($setupName)) {
    Fail "latest.yml does not reference $setupName"
}
if ($latestText -notmatch [regex]::Escape("sha512: $setupSha512")) {
    Fail "latest.yml sha512 does not match $setupName"
}
if ($latestText -notmatch [regex]::Escape("size: $($setupArtifacts[0].Length)")) {
    Fail "latest.yml size does not match $setupName"
}

$verifyText = Get-Content -LiteralPath (Join-Path $releasePath "VERIFY_RELEASE.md") -Raw
if ($verifyText -notmatch "Get-AuthenticodeSignature" -or $verifyText -notmatch "SHA256SUMS") {
    Fail "VERIFY_RELEASE.md is missing signature or checksum instructions."
}
if ($RequireSigned -and $verifyText -notmatch "Status : Valid") {
    Fail "VERIFY_RELEASE.md does not document the expected signed state."
}

$mode = if ($RequireSigned) { "signed required" } else { "unsigned beta allowed" }
Write-Host "Release verification passed ($mode): $releasePath"
