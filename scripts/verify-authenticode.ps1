param(
    [Parameter(Mandatory = $true)]
    [string[]]$ArtifactPath,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedPublisherSubject,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedPublisherCertificateSha256
)

$ErrorActionPreference = "Stop"

$expectedHashes = @(
    $ExpectedPublisherCertificateSha256 -split "[,;]" |
        ForEach-Object { $_.Trim().Replace(" ", "").ToLowerInvariant() } |
        Where-Object { $_ }
)
if ([string]::IsNullOrWhiteSpace($ExpectedPublisherSubject)) {
    throw "Expected publisher subject is required."
}
if ($expectedHashes.Count -eq 0 -or @($expectedHashes | Where-Object { $_ -notmatch "^[a-f0-9]{64}$" }).Count -gt 0) {
    throw "Expected publisher certificate SHA-256 must contain one or more 64-character hexadecimal hashes."
}

$artifacts = @(
    foreach ($pattern in $ArtifactPath) {
        Get-Item -Path $pattern -ErrorAction Stop
    }
) | Sort-Object FullName -Unique
if ($artifacts.Count -eq 0) {
    throw "No Authenticode artifacts were provided."
}

foreach ($artifact in $artifacts) {
    if (-not $artifact.PSIsContainer -and $artifact.Extension -ieq ".exe") {
        $signature = Get-AuthenticodeSignature -LiteralPath $artifact.FullName
        if ($signature.Status -ne "Valid" -or -not $signature.SignerCertificate) {
            throw "$($artifact.Name) must have a valid Authenticode signature; actual status is $($signature.Status)."
        }
        if ($signature.SignerCertificate.Subject -ne $ExpectedPublisherSubject) {
            throw "$($artifact.Name) signer subject does not match the pinned publisher identity."
        }

        $sha256Provider = [System.Security.Cryptography.SHA256]::Create()
        try {
            $certificateSha256 = -join (
                $sha256Provider.ComputeHash($signature.SignerCertificate.RawData) |
                    ForEach-Object { $_.ToString("x2") }
            )
        } finally {
            $sha256Provider.Dispose()
        }
        if ($certificateSha256 -notin $expectedHashes) {
            throw "$($artifact.Name) signer certificate SHA-256 is not approved."
        }
        Write-Host "Verified signed artifact: $($artifact.FullName)"
    } else {
        throw "Authenticode verification only accepts executable files: $($artifact.FullName)"
    }
}
