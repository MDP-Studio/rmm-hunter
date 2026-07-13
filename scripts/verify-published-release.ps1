param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")]
    [string]$Tag,
    [string]$Repository = "MDP-Studio/rmm-hunter",
    [string]$ReleaseDir = "",
    [string]$ReleaseMetadataPath = "",
    [string]$TagCommit = "",
    [string]$ReportPath = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$temporaryReleaseDir = $false

function Fail($Message) {
    throw "[published-release-verify] $Message"
}

function Get-Sha256Lower($Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Invoke-GitHubApi($Uri, $Headers) {
    return Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers
}

function Resolve-TagCommit($RepositoryName, $TagName, $Headers) {
    $encodedTag = [Uri]::EscapeDataString($TagName)
    $target = (Invoke-GitHubApi "https://api.github.com/repos/$RepositoryName/git/ref/tags/$encodedTag" $Headers).object
    while ($target.type -eq "tag") {
        $target = (Invoke-GitHubApi $target.url $Headers).object
    }
    if ($target.type -ne "commit" -or $target.sha -notmatch "^[a-fA-F0-9]{40}$") {
        Fail "Release tag does not resolve to a full commit SHA."
    }
    return $target.sha.ToLowerInvariant()
}

function Get-ReleaseAsset($AssetMap, $Name) {
    if (-not $AssetMap.ContainsKey($Name)) {
        Fail "Published release is missing required asset: $Name"
    }
    return $AssetMap[$Name]
}

function Receive-ReleaseAsset($Asset, $Destination, $Headers) {
    $name = [string]$Asset.name
    if ([System.IO.Path]::GetFileName($name) -ne $name) {
        Fail "Release asset name is not a safe filename: $name"
    }
    Invoke-WebRequest -Method Get -Uri $Asset.browser_download_url -Headers $Headers -OutFile $Destination -UseBasicParsing
}

try {
    $headers = @{
        Accept = "application/vnd.github+json"
        "X-GitHub-Api-Version" = "2022-11-28"
        "User-Agent" = "RMM-Hunter-Release-Verifier"
    }
    if (-not [string]::IsNullOrWhiteSpace($env:GH_TOKEN)) {
        $headers.Authorization = "Bearer $($env:GH_TOKEN)"
    }

    if ($ReleaseMetadataPath) {
        if (-not (Test-Path -LiteralPath $ReleaseMetadataPath -PathType Leaf)) {
            Fail "Release metadata file not found: $ReleaseMetadataPath"
        }
        $releaseMetadata = Get-Content -LiteralPath $ReleaseMetadataPath -Raw | ConvertFrom-Json
    } else {
        $encodedTag = [Uri]::EscapeDataString($Tag)
        $releaseMetadata = Invoke-GitHubApi "https://api.github.com/repos/$Repository/releases/tags/$encodedTag" $headers
    }

    if ($releaseMetadata.tag_name -ne $Tag) {
        Fail "Release metadata tag '$($releaseMetadata.tag_name)' does not match '$Tag'."
    }
    if ($releaseMetadata.draft -ne $false) {
        Fail "Release is absent or still a draft."
    }

    if ($ReleaseDir) {
        if (-not (Test-Path -LiteralPath $ReleaseDir -PathType Container)) {
            Fail "Release directory not found: $ReleaseDir"
        }
        $releasePath = Resolve-Path -LiteralPath $ReleaseDir
    } else {
        $releasePath = Join-Path ([System.IO.Path]::GetTempPath()) "rmm-hunter-release-$([Guid]::NewGuid().ToString('N'))"
        New-Item -ItemType Directory -Path $releasePath | Out-Null
        $temporaryReleaseDir = $true
    }

    $assetMap = @{}
    foreach ($asset in @($releaseMetadata.assets)) {
        $name = [string]$asset.name
        if ($assetMap.ContainsKey($name)) {
            Fail "Release metadata contains duplicate asset: $name"
        }
        $assetMap[$name] = $asset
    }

    $sidecarNames = @("rmm-hunter-release-manifest.json", "SHA256SUMS.txt", "VERIFY_RELEASE.md")
    foreach ($name in $sidecarNames) {
        $asset = Get-ReleaseAsset $assetMap $name
        $destination = Join-Path $releasePath $name
        if (-not $ReleaseDir) {
            Receive-ReleaseAsset $asset $destination $headers
        }
        if (-not (Test-Path -LiteralPath $destination -PathType Leaf)) {
            Fail "Downloaded release sidecar is missing: $name"
        }
    }

    $manifestPath = Join-Path $releasePath "rmm-hunter-release-manifest.json"
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.schema_version -notin @("1.0", "1.1")) {
        Fail "Unsupported release manifest schema: $($manifest.schema_version)"
    }
    if ($manifest.project -ne "RMM Hunter") {
        Fail "Release manifest project identity is invalid."
    }
    if ($manifest.source.repository -ne $Repository -or $manifest.source.ref -ne $Tag) {
        Fail "Release manifest repository or tag does not match the requested release."
    }
    if ($manifest.source.sha -notmatch "^[a-fA-F0-9]{40}$") {
        Fail "Release manifest source SHA is missing or not a full commit SHA."
    }

    $manifestSigningMode = [string]$manifest.signing.mode
    if (-not $manifestSigningMode -and $manifest.schema_version -eq "1.0") {
        $legacyExecutableStatuses = @(
            $manifest.artifacts |
                Where-Object { $_.name -like "*.exe" } |
                ForEach-Object { [string]$_.authenticode.status }
        )
        if ($legacyExecutableStatuses.Count -eq 2 -and @($legacyExecutableStatuses | Where-Object { $_ -ne "NotSigned" }).Count -eq 0) {
            $manifestSigningMode = "unsigned-beta"
        }
    }
    if ($manifestSigningMode -notin @("unsigned-beta", "signpath")) {
        Fail "Manifest does not contain a machine-verifiable signing mode."
    }

    if ($TagCommit) {
        if ($TagCommit -notmatch "^[a-fA-F0-9]{40}$") {
            Fail "Provided tag commit is not a full 40-character SHA."
        }
        $resolvedTagCommit = $TagCommit.ToLowerInvariant()
    } elseif ($ReleaseMetadataPath) {
        Fail "Offline verification requires -TagCommit."
    } else {
        $resolvedTagCommit = Resolve-TagCommit $Repository $Tag $headers
    }
    if ($manifest.source.sha.ToLowerInvariant() -ne $resolvedTagCommit) {
        Fail "Manifest source SHA does not match the public tag commit."
    }

    $requiredNames = @($sidecarNames)
    foreach ($artifact in @($manifest.artifacts)) {
        $name = [string]$artifact.name
        if ([System.IO.Path]::GetFileName($name) -ne $name) {
            Fail "Manifest artifact name is not a safe filename: $name"
        }
        $requiredNames += $name
        $asset = Get-ReleaseAsset $assetMap $name
        $destination = Join-Path $releasePath $name
        if (-not $ReleaseDir) {
            Receive-ReleaseAsset $asset $destination $headers
        }
        if (-not (Test-Path -LiteralPath $destination -PathType Leaf)) {
            Fail "Downloaded release artifact is missing: $name"
        }
    }

    if (($requiredNames | Select-Object -Unique).Count -ne $requiredNames.Count) {
        Fail "Release manifest and sidecars contain duplicate asset names."
    }

    $verifiedAssets = @()
    foreach ($name in $requiredNames) {
        $asset = Get-ReleaseAsset $assetMap $name
        $path = Join-Path $releasePath $name
        $file = Get-Item -LiteralPath $path
        if ([int64]$asset.size -ne $file.Length) {
            Fail "GitHub release size mismatch for $name."
        }
        if ([string]$asset.digest -notmatch "^sha256:([a-fA-F0-9]{64})$") {
            Fail "GitHub release metadata has no SHA-256 digest for $name."
        }
        $actualSha = Get-Sha256Lower $path
        if ($actualSha -ne $Matches[1].ToLowerInvariant()) {
            Fail "GitHub release digest mismatch for $name."
        }
        $manifestArtifact = @($manifest.artifacts | Where-Object { $_.name -eq $name })
        $authenticodeStatus = if ($manifestArtifact.Count -eq 1) {
            [string]$manifestArtifact[0].authenticode.status
        } else {
            "NotApplicable"
        }
        $verifiedAssets += [ordered]@{
            name = $name
            size_bytes = $file.Length
            sha256 = $actualSha
            authenticode_status = $authenticodeStatus
        }
    }

    $requireSigned = $manifestSigningMode -eq "signpath"
    & (Join-Path $PSScriptRoot "verify-release-artifacts.ps1") -ReleaseDir $releasePath -RequireSigned:$requireSigned

    $result = [ordered]@{
        schema_version = "1.0"
        project = "RMM Hunter"
        repository = $Repository
        release_url = [string]$releaseMetadata.html_url
        tag = $Tag
        source_sha = $resolvedTagCommit
        signing = [ordered]@{
            mode = $manifestSigningMode
            expected_publisher = $manifest.signing.expected_publisher
        }
        checks = [ordered]@{
            published_release_metadata = "verified"
            github_asset_digests = "verified"
            sha256_manifest = "verified"
            source_tag_commit = "verified"
            authenticode_policy = "verified"
        }
        artifacts = $verifiedAssets
    }

    if ($ReportPath) {
        $reportParent = Split-Path -Parent $ReportPath
        if ($reportParent -and -not (Test-Path -LiteralPath $reportParent)) {
            New-Item -ItemType Directory -Path $reportParent | Out-Null
        }
        $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ReportPath -Encoding utf8
        Write-Host "Wrote verification result to $ReportPath"
    }

    Write-Host "Published release verification passed: $Repository $Tag ($manifestSigningMode)"
} finally {
    if ($temporaryReleaseDir -and $releasePath -and (Test-Path -LiteralPath $releasePath)) {
        $resolvedTempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
        $resolvedReleasePath = [System.IO.Path]::GetFullPath([string]$releasePath)
        if (-not $resolvedReleasePath.StartsWith($resolvedTempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to remove verification directory outside the system temporary directory."
        }
        Remove-Item -LiteralPath $resolvedReleasePath -Recurse -Force
    }
}
