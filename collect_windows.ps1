[CmdletBinding()]
param(
    [int]$LookbackDays = 14,
    [int]$MaxRecentFiles = 500,
    [string]$OutputPath,
    [switch]$Pretty
)

$ErrorActionPreference = "Continue"
$CollectionErrors = @()
$StartTime = (Get-Date).AddDays(-1 * [Math]::Abs($LookbackDays))

function Add-CollectionError {
    param(
        [string]$Source,
        [string]$Message
    )

    $script:CollectionErrors += [ordered]@{
        source = $Source
        message = $Message
    }
}

function ConvertTo-IsoUtc {
    param($Value)

    if ($null -eq $Value) {
        return $null
    }

    try {
        return ([datetime]$Value).ToUniversalTime().ToString("o")
    }
    catch {
        return [string]$Value
    }
}

function Limit-Text {
    param(
        [AllowNull()][string]$Value,
        [int]$Max = 4000
    )

    if ([string]::IsNullOrEmpty($Value)) {
        return $Value
    }

    if ($Value.Length -le $Max) {
        return $Value
    }

    return ($Value.Substring(0, $Max) + "...[truncated]")
}

function Test-IsAdmin {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Test-PathAccessible {
    param([string]$Path)

    try {
        return (Test-Path -LiteralPath $Path -ErrorAction Stop)
    }
    catch {
        return $false
    }
}

function Convert-InstallDate {
    param($Value)

    if ($null -eq $Value) {
        return $null
    }

    $text = [string]$Value
    if ($text -match "^\d{8}$") {
        try {
            return ([datetime]::ParseExact($text, "yyyyMMdd", $null)).ToString("yyyy-MM-dd")
        }
        catch {
            return $text
        }
    }

    return $text
}

function Get-ExecutablePathFromCommand {
    param([AllowNull()][string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return $null
    }

    $trimmed = $CommandLine.Trim()
    if ($trimmed.StartsWith('"')) {
        $closingQuote = $trimmed.IndexOf('"', 1)
        if ($closingQuote -gt 1) {
            return $trimmed.Substring(1, $closingQuote - 1)
        }
    }

    $match = [regex]::Match($trimmed, '(?i)[a-z]:\\[^"]+?\.(exe|com|dll|bat|cmd|ps1|msi|msp|scr)')
    if ($match.Success) {
        return $match.Value.Trim()
    }

    return $null
}

function Get-SignatureSummary {
    param([AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $subject = $null
        $issuer = $null
        $thumbprint = $null

        if ($null -ne $signature.SignerCertificate) {
            $subject = $signature.SignerCertificate.Subject
            $issuer = $signature.SignerCertificate.Issuer
            $thumbprint = $signature.SignerCertificate.Thumbprint
        }

        return [ordered]@{
            status = [string]$signature.Status
            status_message = [string]$signature.StatusMessage
            signer_subject = $subject
            signer_issuer = $issuer
            thumbprint = $thumbprint
        }
    }
    catch {
        Add-CollectionError -Source "authenticode" -Message ("Failed to read signature for {0}: {1}" -f $Path, $_.Exception.Message)
        return $null
    }
}

function Get-ShortcutSummary {
    param(
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or -not $Path.ToLowerInvariant().EndsWith(".lnk")) {
        return $null
    }

    try {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($Path)
        $targetPath = [string]$shortcut.TargetPath
        $targetSignature = $null

        if (-not [string]::IsNullOrWhiteSpace($targetPath) -and (Test-Path -LiteralPath $targetPath -PathType Leaf)) {
            $targetExtension = [System.IO.Path]::GetExtension($targetPath).ToLowerInvariant()
            if (@(".exe", ".msi", ".msp", ".dll", ".scr") -contains $targetExtension) {
                $targetSignature = Get-SignatureSummary $targetPath
            }
        }

        return [ordered]@{
            target_path = $targetPath
            arguments = [string]$shortcut.Arguments
            working_directory = [string]$shortcut.WorkingDirectory
            icon_location = [string]$shortcut.IconLocation
            target_signature = $targetSignature
        }
    }
    catch {
        Add-CollectionError -Source "shortcut:$Path" -Message $_.Exception.Message
        return $null
    }
}

function Get-ObjectPropertyValue {
    param(
        [AllowNull()]$Object,
        [string]$Name
    )

    if ($null -eq $Object) {
        return $null
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function ConvertTo-AgeDays {
    param($Value)

    if ($null -eq $Value) {
        return $null
    }

    try {
        $timestamp = ([datetime]$Value).ToUniversalTime()
        return [Math]::Round(((Get-Date).ToUniversalTime() - $timestamp).TotalDays, 2)
    }
    catch {
        return $null
    }
}

function Get-LimitedStringArray {
    param(
        [AllowNull()]$Value,
        [int]$Max = 20
    )

    $items = @()
    if ($null -eq $Value) {
        return @()
    }

    foreach ($item in @($Value)) {
        $text = [string]$item
        if (-not [string]::IsNullOrWhiteSpace($text)) {
            $items += Limit-Text $text 1000
        }
    }

    return @($items | Select-Object -First $Max)
}

function Get-ValueCount {
    param([AllowNull()]$Value)

    if ($null -eq $Value) {
        return 0
    }

    return @($Value | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count
}

function Get-DefenderStatusArtifacts {
    $items = @()

    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $preference = $null
        try {
            $preference = Get-MpPreference -ErrorAction Stop
        }
        catch {
            Add-CollectionError -Source "defender_preference" -Message $_.Exception.Message
        }

        $items += [ordered]@{
            check = "defender_status"
            source_command = "Get-MpComputerStatus"
            am_service_enabled = Get-ObjectPropertyValue $status "AMServiceEnabled"
            antivirus_enabled = Get-ObjectPropertyValue $status "AntivirusEnabled"
            real_time_protection_enabled = Get-ObjectPropertyValue $status "RealTimeProtectionEnabled"
            behavior_monitor_enabled = Get-ObjectPropertyValue $status "BehaviorMonitorEnabled"
            ioav_protection_enabled = Get-ObjectPropertyValue $status "IoavProtectionEnabled"
            on_access_protection_enabled = Get-ObjectPropertyValue $status "OnAccessProtectionEnabled"
            is_tamper_protected = Get-ObjectPropertyValue $status "IsTamperProtected"
            nis_enabled = Get-ObjectPropertyValue $status "NISEnabled"
            computer_state = [string](Get-ObjectPropertyValue $status "ComputerState")
            product_status = [string](Get-ObjectPropertyValue $status "ProductStatus")
            am_product_version = [string](Get-ObjectPropertyValue $status "AMProductVersion")
            am_engine_version = [string](Get-ObjectPropertyValue $status "AMEngineVersion")
            am_service_version = [string](Get-ObjectPropertyValue $status "AMServiceVersion")
            antivirus_signature_version = [string](Get-ObjectPropertyValue $status "AntivirusSignatureVersion")
            antivirus_signature_last_updated_utc = ConvertTo-IsoUtc (Get-ObjectPropertyValue $status "AntivirusSignatureLastUpdated")
            antivirus_signature_age_days = ConvertTo-AgeDays (Get-ObjectPropertyValue $status "AntivirusSignatureLastUpdated")
            antispyware_signature_version = [string](Get-ObjectPropertyValue $status "AntispywareSignatureVersion")
            antispyware_signature_last_updated_utc = ConvertTo-IsoUtc (Get-ObjectPropertyValue $status "AntispywareSignatureLastUpdated")
            nis_signature_version = [string](Get-ObjectPropertyValue $status "NISSignatureVersion")
            nis_signature_last_updated_utc = ConvertTo-IsoUtc (Get-ObjectPropertyValue $status "NISSignatureLastUpdated")
            quick_scan_age_days = Get-ObjectPropertyValue $status "QuickScanAge"
            full_scan_age_days = Get-ObjectPropertyValue $status "FullScanAge"
            pua_protection = Get-ObjectPropertyValue $preference "PUAProtection"
            cloud_block_level = Get-ObjectPropertyValue $preference "CloudBlockLevel"
            maps_reporting = Get-ObjectPropertyValue $preference "MAPSReporting"
            submit_samples_consent = Get-ObjectPropertyValue $preference "SubmitSamplesConsent"
            disable_realtime_monitoring = Get-ObjectPropertyValue $preference "DisableRealtimeMonitoring"
            exclusion_path_count = Get-ValueCount (Get-ObjectPropertyValue $preference "ExclusionPath")
            exclusion_path_samples = Get-LimitedStringArray (Get-ObjectPropertyValue $preference "ExclusionPath") 20
            exclusion_process_count = Get-ValueCount (Get-ObjectPropertyValue $preference "ExclusionProcess")
            exclusion_process_samples = Get-LimitedStringArray (Get-ObjectPropertyValue $preference "ExclusionProcess") 20
            exclusion_extension_count = Get-ValueCount (Get-ObjectPropertyValue $preference "ExclusionExtension")
            exclusion_extension_samples = Get-LimitedStringArray (Get-ObjectPropertyValue $preference "ExclusionExtension") 20
            exclusion_ip_address_count = Get-ValueCount (Get-ObjectPropertyValue $preference "ExclusionIpAddress")
            exclusion_ip_address_samples = Get-LimitedStringArray (Get-ObjectPropertyValue $preference "ExclusionIpAddress") 20
        }
    }
    catch {
        Add-CollectionError -Source "defender_status" -Message $_.Exception.Message
    }

    return @($items)
}

function Get-CodeSigningTrustArtifacts {
    $items = @()
    $candidatePaths = @(
        (Join-Path $env:WINDIR "System32\notepad.exe"),
        (Join-Path $env:WINDIR "System32\cmd.exe"),
        (Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe")
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

    foreach ($candidatePath in $candidatePaths) {
        try {
            if (-not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
                continue
            }

            $signature = Get-AuthenticodeSignature -LiteralPath $candidatePath -ErrorAction Stop
            $subject = $null
            $issuer = $null
            $thumbprint = $null
            if ($null -ne $signature.SignerCertificate) {
                $subject = $signature.SignerCertificate.Subject
                $issuer = $signature.SignerCertificate.Issuer
                $thumbprint = $signature.SignerCertificate.Thumbprint
            }

            $items += [ordered]@{
                check = "windows_binary_signature"
                path = [string]$candidatePath
                name = [IO.Path]::GetFileName($candidatePath)
                status = [string]$signature.Status
                status_message = [string]$signature.StatusMessage
                signer_subject = $subject
                signer_issuer = $issuer
                thumbprint = $thumbprint
            }
        }
        catch {
            Add-CollectionError -Source "code_signing_trust:$candidatePath" -Message $_.Exception.Message
        }
    }

    return @($items)
}

function Get-TrustedRootStoreArtifacts {
    $items = @()
    $stores = @(
        @{ name = "LocalMachine\Root"; path = "Cert:\LocalMachine\Root"; scope = "local_machine" },
        @{ name = "CurrentUser\Root"; path = "Cert:\CurrentUser\Root"; scope = "current_user" }
    )

    foreach ($store in $stores) {
        try {
            $certificates = @(Get-ChildItem -Path $store.path -ErrorAction Stop)
            $expired = @($certificates | Where-Object { $_.NotAfter -lt (Get-Date) })
            $privateKeyRoots = @($certificates | Where-Object { $_.HasPrivateKey })

            $items += [ordered]@{
                check = "trusted_root_store_summary"
                store = $store.name
                scope = $store.scope
                total_count = $certificates.Count
                expired_count = $expired.Count
                private_key_count = $privateKeyRoots.Count
            }

            foreach ($certificate in @($privateKeyRoots | Select-Object -First 25)) {
                $items += [ordered]@{
                    check = "root_certificate_with_private_key"
                    store = $store.name
                    scope = $store.scope
                    subject = Limit-Text ([string]$certificate.Subject) 1000
                    issuer = Limit-Text ([string]$certificate.Issuer) 1000
                    thumbprint = [string]$certificate.Thumbprint
                    not_before_utc = ConvertTo-IsoUtc $certificate.NotBefore
                    not_after_utc = ConvertTo-IsoUtc $certificate.NotAfter
                    signature_algorithm = [string]$certificate.SignatureAlgorithm.FriendlyName
                    has_private_key = $certificate.HasPrivateKey
                }
            }
        }
        catch {
            Add-CollectionError -Source "trusted_root_store:$($store.name)" -Message $_.Exception.Message
        }
    }

    return @($items)
}

function Get-UninstallEntries {
    $sources = @(
        @{ hive = "HKLM"; path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" },
        @{ hive = "HKLM"; path = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" },
        @{ hive = "HKCU"; path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" }
    )

    $items = @()
    foreach ($source in $sources) {
        try {
            $entries = Get-ItemProperty -Path $source.path -ErrorAction Stop
            foreach ($entry in $entries) {
                if ([string]::IsNullOrWhiteSpace($entry.DisplayName)) {
                    continue
                }

                $basePath = $source.path.Replace("\*", "")
                $items += [ordered]@{
                    display_name = [string]$entry.DisplayName
                    display_version = [string]$entry.DisplayVersion
                    publisher = [string]$entry.Publisher
                    install_date = Convert-InstallDate $entry.InstallDate
                    install_location = [string]$entry.InstallLocation
                    uninstall_string = Limit-Text ([string]$entry.UninstallString) 1000
                    quiet_uninstall_string = Limit-Text ([string]$entry.QuietUninstallString) 1000
                    registry_hive = $source.hive
                    registry_path = (Join-Path $basePath $entry.PSChildName)
                }
            }
        }
        catch {
            Add-CollectionError -Source "installed_programs:$($source.path)" -Message $_.Exception.Message
        }
    }

    return @($items | Sort-Object display_name, registry_path)
}

function Get-ServiceArtifacts {
    $items = @()

    try {
        $services = Get-CimInstance Win32_Service -ErrorAction Stop
        foreach ($service in $services) {
            $exePath = Get-ExecutablePathFromCommand $service.PathName
            $items += [ordered]@{
                name = [string]$service.Name
                display_name = [string]$service.DisplayName
                state = [string]$service.State
                status = [string]$service.Status
                start_mode = [string]$service.StartMode
                start_name = [string]$service.StartName
                path_name = Limit-Text ([string]$service.PathName) 2000
                executable_path = $exePath
                process_id = $service.ProcessId
                description = Limit-Text ([string]$service.Description) 1000
                signature = Get-SignatureSummary $exePath
            }
        }
    }
    catch {
        Add-CollectionError -Source "services" -Message $_.Exception.Message
    }

    return @($items | Sort-Object name)
}

function Get-ScheduledTaskArtifacts {
    $items = @()

    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop
        foreach ($task in $tasks) {
            $actions = @()
            foreach ($action in $task.Actions) {
                $actions += [ordered]@{
                    execute = [string]$action.Execute
                    arguments = Limit-Text ([string]$action.Arguments) 2000
                    working_directory = [string]$action.WorkingDirectory
                }
            }

            $lastRunTime = $null
            $nextRunTime = $null
            try {
                $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
                $lastRunTime = ConvertTo-IsoUtc $info.LastRunTime
                $nextRunTime = ConvertTo-IsoUtc $info.NextRunTime
            }
            catch {
                $null = $null
            }

            $items += [ordered]@{
                task_name = [string]$task.TaskName
                task_path = [string]$task.TaskPath
                state = [string]$task.State
                author = [string]$task.Author
                description = Limit-Text ([string]$task.Description) 1000
                actions = $actions
                last_run_time_utc = $lastRunTime
                next_run_time_utc = $nextRunTime
            }
        }
    }
    catch {
        Add-CollectionError -Source "scheduled_tasks" -Message $_.Exception.Message
    }

    return @($items | Sort-Object task_path, task_name)
}

function Get-StartupRegistryArtifacts {
    $sources = @(
        @{ hive = "HKLM"; path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" },
        @{ hive = "HKLM"; path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" },
        @{ hive = "HKLM"; path = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" },
        @{ hive = "HKLM"; path = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce" },
        @{ hive = "HKCU"; path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" },
        @{ hive = "HKCU"; path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" }
    )

    $skipNames = @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")
    $items = @()

    foreach ($source in $sources) {
        try {
            if (-not (Test-Path -LiteralPath $source.path)) {
                continue
            }

            $props = Get-ItemProperty -LiteralPath $source.path -ErrorAction Stop
            foreach ($prop in $props.PSObject.Properties) {
                if ($skipNames -contains $prop.Name) {
                    continue
                }

                $items += [ordered]@{
                    hive = $source.hive
                    registry_path = $source.path
                    value_name = [string]$prop.Name
                    value = Limit-Text ([string]$prop.Value) 2000
                    executable_path = Get-ExecutablePathFromCommand ([string]$prop.Value)
                }
            }
        }
        catch {
            Add-CollectionError -Source "startup_registry:$($source.path)" -Message $_.Exception.Message
        }
    }

    return @($items | Sort-Object registry_path, value_name)
}

function Get-StartupFolderArtifacts {
    $dirs = @(
        [Environment]::GetFolderPath("Startup"),
        (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\StartUp")
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

    $items = @()
    foreach ($dir in $dirs) {
        try {
            if (-not (Test-Path -LiteralPath $dir)) {
                continue
            }

            $files = Get-ChildItem -LiteralPath $dir -File -ErrorAction Stop
            foreach ($file in $files) {
                $shortcut = Get-ShortcutSummary $file.FullName
                $items += [ordered]@{
                    name = [string]$file.Name
                    path = [string]$file.FullName
                    extension = [string]$file.Extension
                    length = $file.Length
                    creation_time_utc = ConvertTo-IsoUtc $file.CreationTimeUtc
                    last_write_time_utc = ConvertTo-IsoUtc $file.LastWriteTimeUtc
                    signature = Get-SignatureSummary $file.FullName
                    shortcut = $shortcut
                }
            }
        }
        catch {
            Add-CollectionError -Source "startup_folder:$dir" -Message $_.Exception.Message
        }
    }

    return @($items | Sort-Object path)
}

function Get-RecentFileArtifacts {
    $extensions = @(".exe", ".msi", ".msp", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".hta", ".zip", ".7z", ".rar", ".scr", ".lnk")
    $signedExtensions = @(".exe", ".msi", ".msp", ".dll", ".scr")
    $dirs = @()

    try {
        $profiles = Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object {
            -not $_.Special -and -not [string]::IsNullOrWhiteSpace($_.LocalPath)
        }

        foreach ($profile in $profiles) {
            $dirs += (Join-Path $profile.LocalPath "Downloads")
            $dirs += (Join-Path $profile.LocalPath "AppData\Local\Temp")
        }
    }
    catch {
        Add-CollectionError -Source "user_profiles" -Message $_.Exception.Message
    }

    if (-not [string]::IsNullOrWhiteSpace($env:TEMP)) {
        $dirs += $env:TEMP
    }
    if (-not [string]::IsNullOrWhiteSpace($env:TMP)) {
        $dirs += $env:TMP
    }
    if (-not [string]::IsNullOrWhiteSpace($env:WINDIR)) {
        $dirs += (Join-Path $env:WINDIR "Temp")
    }

    $dirs = $dirs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-PathAccessible $_) } | Select-Object -Unique
    $items = @()
    $seen = @{}

    foreach ($dir in $dirs) {
        try {
            $candidateFiles = @()
            $candidateFiles += Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue
            $childDirs = Get-ChildItem -LiteralPath $dir -Directory -ErrorAction SilentlyContinue
            foreach ($childDir in $childDirs) {
                $candidateFiles += Get-ChildItem -LiteralPath $childDir.FullName -File -ErrorAction SilentlyContinue
            }

            foreach ($file in $candidateFiles) {
                if ($items.Count -ge $MaxRecentFiles) {
                    break
                }

                if ($file.LastWriteTime -lt $StartTime -and $file.CreationTime -lt $StartTime) {
                    continue
                }

                if ($extensions -notcontains $file.Extension.ToLowerInvariant()) {
                    continue
                }

                $key = $file.FullName.ToLowerInvariant()
                if ($seen.ContainsKey($key)) {
                    continue
                }
                $seen[$key] = $true

                $signature = $null
                if ($signedExtensions -contains $file.Extension.ToLowerInvariant()) {
                    $signature = Get-SignatureSummary $file.FullName
                }

                $items += [ordered]@{
                    name = [string]$file.Name
                    path = [string]$file.FullName
                    directory = [string]$file.DirectoryName
                    extension = [string]$file.Extension
                    length = $file.Length
                    creation_time_utc = ConvertTo-IsoUtc $file.CreationTimeUtc
                    last_write_time_utc = ConvertTo-IsoUtc $file.LastWriteTimeUtc
                    signature = $signature
                }
            }
        }
        catch {
            Add-CollectionError -Source "recent_files:$dir" -Message $_.Exception.Message
        }
    }

    return @($items | Sort-Object last_write_time_utc -Descending)
}

function Join-OptionalPath {
    param(
        [AllowNull()][string]$Base,
        [string]$Child
    )

    if ([string]::IsNullOrWhiteSpace($Base)) {
        return $null
    }

    return (Join-Path $Base $Child)
}

function Get-FileTailSample {
    param(
        [string]$Path,
        [int]$MaxLines = 20
    )

    try {
        return @(Get-Content -LiteralPath $Path -Tail $MaxLines -ErrorAction Stop | ForEach-Object {
            Limit-Text ([string]$_) 1000
        })
    }
    catch {
        return @()
    }
}

function Get-RmmVendorLogArtifacts {
    $programFilesX86 = ${env:ProgramFiles(x86)}
    $specs = @(
        @{
            tool = "AnyDesk"
            patterns = @(
                (Join-OptionalPath $env:ProgramData "AnyDesk\connection_trace.txt"),
                (Join-OptionalPath $env:ProgramData "AnyDesk\ad_svc.trace"),
                (Join-OptionalPath $env:APPDATA "AnyDesk\connection_trace.txt"),
                (Join-OptionalPath $env:APPDATA "AnyDesk\ad.trace")
            )
        },
        @{
            tool = "TeamViewer"
            patterns = @(
                (Join-OptionalPath $env:ProgramFiles "TeamViewer\*.log"),
                (Join-OptionalPath $programFilesX86 "TeamViewer\*.log"),
                (Join-OptionalPath $env:ProgramData "TeamViewer\*.log"),
                (Join-OptionalPath $env:APPDATA "TeamViewer\*.log")
            )
        },
        @{
            tool = "ScreenConnect / ConnectWise Control"
            patterns = @(
                (Join-OptionalPath $env:ProgramFiles "ScreenConnect Client*\*.log"),
                (Join-OptionalPath $programFilesX86 "ScreenConnect Client*\*.log"),
                (Join-OptionalPath $env:ProgramData "ScreenConnect Client*\*.log"),
                (Join-OptionalPath $env:ProgramData "ConnectWise*\*.log")
            )
        },
        @{
            tool = "RustDesk"
            patterns = @(
                (Join-OptionalPath $env:APPDATA "RustDesk\log\*.log"),
                (Join-OptionalPath $env:APPDATA "RustDesk\config\*.toml"),
                (Join-OptionalPath $env:ProgramData "RustDesk\log\*.log")
            )
        },
        @{
            tool = "Splashtop"
            patterns = @(
                (Join-OptionalPath $env:ProgramData "Splashtop\*\*.log"),
                (Join-OptionalPath $programFilesX86 "Splashtop\*\*.log"),
                (Join-OptionalPath $env:APPDATA "Splashtop\*\*.log")
            )
        },
        @{
            tool = "Atera"
            patterns = @(
                (Join-OptionalPath $env:ProgramFiles "ATERA Networks\AteraAgent\*.log"),
                (Join-OptionalPath $programFilesX86 "ATERA Networks\AteraAgent\*.log"),
                (Join-OptionalPath $env:ProgramData "ATERA Networks\*.log")
            )
        },
        @{
            tool = "MeshAgent"
            patterns = @(
                (Join-OptionalPath $env:ProgramFiles "Mesh Agent\*.log"),
                (Join-OptionalPath $programFilesX86 "Mesh Agent\*.log"),
                (Join-OptionalPath $env:ProgramData "Mesh Agent\*.log")
            )
        },
        @{
            tool = "DWAgent"
            patterns = @(
                (Join-OptionalPath $env:ProgramFiles "DWAgent\log\*.log"),
                (Join-OptionalPath $programFilesX86 "DWAgent\log\*.log"),
                (Join-OptionalPath $env:ProgramData "DWAgent\log\*.log")
            )
        }
    )

    $items = @()
    $seen = @{}
    $connectionMarkers = @("connection_trace", "connections", "session", "remotecontrol", "remote_control", "incoming", "outgoing")

    foreach ($spec in $specs) {
        foreach ($pattern in @($spec.patterns | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
            try {
                $files = @(Get-ChildItem -Path $pattern -File -ErrorAction SilentlyContinue)
                foreach ($file in $files) {
                    if ($items.Count -ge 250) {
                        break
                    }

                    $key = $file.FullName.ToLowerInvariant()
                    if ($seen.ContainsKey($key)) {
                        continue
                    }
                    $seen[$key] = $true

                    $combined = ($file.Name + " " + $file.FullName).ToLowerInvariant()
                    $role = "vendor_log"
                    foreach ($marker in $connectionMarkers) {
                        if ($combined.Contains($marker)) {
                            $role = "connection_log"
                            break
                        }
                    }

                    $items += [ordered]@{
                        tool = [string]$spec.tool
                        artifact_role = $role
                        evidence_question = $(if ($role -eq "connection_log") { "connected" } else { "configured_or_ran" })
                        name = [string]$file.Name
                        path = [string]$file.FullName
                        directory = [string]$file.DirectoryName
                        extension = [string]$file.Extension
                        size_bytes = $file.Length
                        creation_time_utc = ConvertTo-IsoUtc $file.CreationTimeUtc
                        last_write_time_utc = ConvertTo-IsoUtc $file.LastWriteTimeUtc
                        last_access_time_utc = ConvertTo-IsoUtc $file.LastAccessTimeUtc
                        sample_lines = Get-FileTailSample -Path $file.FullName
                    }
                }
            }
            catch {
                Add-CollectionError -Source "rmm_vendor_logs:$pattern" -Message $_.Exception.Message
            }
        }
    }

    return @($items | Sort-Object last_write_time_utc -Descending)
}

function Convert-EventRecord {
    param($Event)

    $eventData = [ordered]@{}
    try {
        [xml]$xml = $Event.ToXml()
        $index = 0
        foreach ($node in $xml.Event.EventData.Data) {
            $name = $node.Name
            if ([string]::IsNullOrWhiteSpace($name)) {
                $name = "Data$index"
            }
            $eventData[$name] = Limit-Text ([string]$node."#text") 2000
            $index += 1
        }
    }
    catch {
        $eventData = [ordered]@{}
    }

    return [ordered]@{
        log_name = [string]$Event.LogName
        id = $Event.Id
        time_created_utc = ConvertTo-IsoUtc $Event.TimeCreated
        provider = [string]$Event.ProviderName
        level = [string]$Event.LevelDisplayName
        message = Limit-Text ([string]$Event.Message) 4000
        data = $eventData
    }
}

function Get-EventArtifacts {
    param(
        [string]$LogName,
        [int[]]$Ids,
        [int]$MaxEvents = 200
    )

    try {
        $filter = @{
            LogName = $LogName
            StartTime = $StartTime
        }

        if ($Ids -and $Ids.Count -gt 0) {
            $filter["Id"] = $Ids
        }

        return @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop | ForEach-Object {
            Convert-EventRecord $_
        })
    }
    catch {
        Add-CollectionError -Source "event_log:$LogName" -Message $_.Exception.Message
        return @()
    }
}

function Test-EventContainsAnyTerm {
    param(
        $Event,
        [string[]]$Terms
    )

    $dataText = ""
    if ($null -ne $Event.data) {
        $dataText = (($Event.data.GetEnumerator() | ForEach-Object { [string]$_.Value }) -join " ")
    }

    $text = (([string]$Event.message) + " " + $dataText).ToLowerInvariant()
    foreach ($term in $Terms) {
        if ($text.Contains($term.ToLowerInvariant())) {
            return $true
        }
    }

    return $false
}

$remoteToolTerms = @(
    "screenconnect", "connectwise control", "simplehelp", "anydesk", "teamviewer",
    "meshagent", "meshcentral", "tacticalrmm", "tactical rmm", "atera",
    "splashtop", "rustdesk", "dwagent", "dwservice"
)

$processTerms = $remoteToolTerms + @(
    "msiexec", "powershell", "pwsh", "wmic", "wmiprvse", "regsvr32", "rundll32",
    "bitsadmin", "certutil", "mshta", "encodedcommand", " -enc "
)

$defenderEvents = Get-EventArtifacts -LogName "Microsoft-Windows-Windows Defender/Operational" -Ids @(1116, 1117, 1118, 1119, 1120, 1121, 1122, 5001, 5004, 5007, 5013) -MaxEvents 250
$powershellOperationalEvents = Get-EventArtifacts -LogName "Microsoft-Windows-PowerShell/Operational" -Ids @(4103, 4104) -MaxEvents 500
$windowsPowerShellEvents = Get-EventArtifacts -LogName "Windows PowerShell" -Ids @(400, 403, 600) -MaxEvents 250
$serviceInstallEvents = Get-EventArtifacts -LogName "System" -Ids @(7045) -MaxEvents 250
$wmiEvents = Get-EventArtifacts -LogName "Microsoft-Windows-WMI-Activity/Operational" -Ids @(5857, 5858, 5859, 5860, 5861) -MaxEvents 250
$processEventsRaw = Get-EventArtifacts -LogName "Security" -Ids @(4688) -MaxEvents 1500
$processEvents = @($processEventsRaw | Where-Object { Test-EventContainsAnyTerm -Event $_ -Terms $processTerms })

$report = [ordered]@{
    schema_version = "1.0"
    scanner = [ordered]@{
        name = "RMM Hunter Windows Collector"
        version = "0.1.0"
        collected_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        hostname = $env:COMPUTERNAME
        username = [Environment]::UserName
        powershell_version = $PSVersionTable.PSVersion.ToString()
        is_admin = Test-IsAdmin
    }
    collection = [ordered]@{
        lookback_days = [Math]::Abs($LookbackDays)
        start_time_utc = ConvertTo-IsoUtc $StartTime
        max_recent_files = $MaxRecentFiles
    }
    artifacts = [ordered]@{
        installed_programs = Get-UninstallEntries
        services = Get-ServiceArtifacts
        service_install_events = $serviceInstallEvents
        scheduled_tasks = Get-ScheduledTaskArtifacts
        startup_registry = Get-StartupRegistryArtifacts
        startup_folders = Get-StartupFolderArtifacts
        recent_files = Get-RecentFileArtifacts
        rmm_vendor_logs = Get-RmmVendorLogArtifacts
        defender_status = @(Get-DefenderStatusArtifacts)
        code_signing_trust = @(Get-CodeSigningTrustArtifacts)
        trusted_root_store = @(Get-TrustedRootStoreArtifacts)
        defender_events = $defenderEvents
        powershell_events = @($powershellOperationalEvents + $windowsPowerShellEvents)
        process_creation_events = $processEvents
        wmi_events = $wmiEvents
    }
    collection_errors = $CollectionErrors
}

$depth = 12
if ($Pretty) {
    $json = $report | ConvertTo-Json -Depth $depth
}
else {
    $json = $report | ConvertTo-Json -Depth $depth -Compress
}

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $parent = Split-Path -Parent $OutputPath
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    Set-Content -LiteralPath $OutputPath -Value $json -Encoding UTF8
}
else {
    $json
}
