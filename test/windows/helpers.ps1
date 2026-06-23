# helpers.ps1 - Windows-side oracle helpers for the device-type filter tests.
#
# Dot-source this on the Windows client, or invoke individual functions over WinRM
# from the pytest harness. All functions are intentionally small and composable so
# the harness can assert on each oracle independently.
#
# Assumes usbip.exe is on PATH (or pass -UsbipExe).

$ErrorActionPreference = 'Stop'

function Set-FilterPolicy {
    # Examples:
    #   Set-FilterPolicy -DenyAll
    #   Set-FilterPolicy -Disable
    #   Set-FilterPolicy -Allow 'hid','mass_storage'
    param(
        [string[]] $Allow,
        [switch]   $DenyAll,
        [switch]   $Disable,
        [string]   $UsbipExe = 'usbip.exe'
    )
    if ($Disable) { & $UsbipExe filter --disable; return }
    if ($DenyAll) { & $UsbipExe filter --deny-all; return }
    if ($Allow)   { & $UsbipExe filter --allow ($Allow -join ','); return }
    & $UsbipExe filter   # show
}

function Invoke-Attach {
    # Returns @{ Ok=<bool>; ExitCode=<int>; Output=<string> }.
    param(
        [Parameter(Mandatory)] [string] $Server,
        [Parameter(Mandatory)] [string] $BusId,
        [string] $UsbipExe = 'usbip.exe'
    )
    $out = & $UsbipExe attach -r $Server -b $BusId 2>&1 | Out-String
    [pscustomobject]@{ Ok = ($LASTEXITCODE -eq 0); ExitCode = $LASTEXITCODE; Output = $out }
}

function Test-PnpPresent {
    # True if a device with the given VID/PID is currently enumerated by Windows.
    # This is the security-critical oracle: on DENY it must be $false.
    #
    # The PID parameter is named $ProductId rather than $Pid: PowerShell has a
    # built-in, read-only automatic variable $PID (current process ID), and a
    # parameter literally named $Pid collides with it ("Cannot overwrite
    # variable Pid because it is read-only or constant") as soon as the caller
    # binds an argument to it.
    param(
        [Parameter(Mandatory)] [string] $Vid,        # e.g. '16C0'
        [Parameter(Mandatory)] [string] $ProductId   # e.g. '03EA'
    )
    $match = "VID_${Vid}&PID_${ProductId}"
    $null -ne (Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
               Where-Object { $_.InstanceId -match $match })
}

function Get-FilterRejectionEvents {
    # Recent System-log entries from the usbip2_ude event source.
    param([int] $MaxEvents = 10)
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'usbip2_ude' } `
        -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
}

function Test-RejectionLogged {
    # True if a recent usbip2_ude event mentions the given hex token (e.g. the PID
    # '03EA' or a class byte). Tolerant by design: the current driver inserts only
    # VID/PID/iface/class, not the textual reason.
    param(
        [Parameter(Mandatory)] [string] $Contains,
        [int] $MaxEvents = 10,
        [datetime] $Since = [datetime]::MinValue
    )
    $evts = Get-FilterRejectionEvents -MaxEvents $MaxEvents
    if ($Since -gt [datetime]::MinValue) {
        $evts = $evts | Where-Object { $_.TimeCreated -ge $Since }
    }
    [bool]($evts | Where-Object { $_.Message -match [regex]::Escape($Contains) })
}

function Get-PresentHidInstanceIds {
    # Instance IDs of currently-present HID-class devices. The TOCTOU test takes a
    # baseline before attach and diffs after, so the VM's own keyboard/mouse are
    # excluded and only a smuggled HID interface shows up as "new".
    (Get-PnpDevice -PresentOnly -Class 'HIDClass' -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty InstanceId) -join "`n"
}

function Get-RemovableMarker {
    # Read a marker file from any removable drive. Proves the mass-storage channel
    # is live (the payload seeded on the server image is readable on the client).
    param([Parameter(Mandatory)] [string] $FileName)
    foreach ($d in Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2') {
        $p = Join-Path $d.DeviceID $FileName
        if (Test-Path $p) { return (Get-Content $p -Raw) }
    }
    return $null
}

function Test-PublicMarker {
    # True if the BadUSB keystroke payload dropped its marker (=> code executed).
    param([Parameter(Mandatory)] [string] $Token)
    Test-Path "C:\Users\Public\ub_$Token.txt"
}

function Remove-PublicMarker {
    param([Parameter(Mandatory)] [string] $Token)
    Remove-Item "C:\Users\Public\ub_$Token.txt" -ErrorAction SilentlyContinue
}

function Get-PresentNetAdapterNames {
    # Names of network adapters that are actually present (not 'Not Present').
    # The efficacy NIC test baselines this, attaches, then diffs for a rogue NIC.
    (Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object Status -ne 'Not Present' |
        Select-Object -ExpandProperty Name) -join "`n"
}

function Clear-UsbipState {
    # Detach everything and reset the filter so each test starts clean.
    param([string] $UsbipExe = 'usbip.exe')
    & $UsbipExe detach --all=closeonly 2>&1 | Out-Null
    & $UsbipExe filter --disable        2>&1 | Out-Null
}
