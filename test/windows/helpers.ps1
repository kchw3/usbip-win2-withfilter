# helpers.ps1 - Windows-side oracle helpers for the device-type filter tests.
#
# Dot-source this on the Windows client, or invoke individual functions over WinRM
# from the pytest harness. All functions are intentionally small and composable so
# the harness can assert on each oracle independently.
#
# Assumes usbip.exe is on PATH (or pass -UsbipExe).

$ErrorActionPreference = 'Stop'


function Join-NativeArguments {
    param([string[]] $Arguments)
    (($Arguments | ForEach-Object {
        '"' + ($_ -replace '"', '\"') + '"'
    }) -join ' ')
}

function Invoke-NativeWithTimeout {
    param(
        [Parameter(Mandatory)] [string]   $FilePath,
        [Parameter(Mandatory)] [string[]] $Arguments,
        [int] $TimeoutSeconds = 30,
        [switch] $ThrowOnNonZero
    )
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $FilePath
    $psi.Arguments = Join-NativeArguments -Arguments $Arguments
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    $p = [System.Diagnostics.Process]::new()
    $p.StartInfo = $psi

    $null = $p.Start()
    # DataReceivedEventHandler scriptblocks run on .NET worker threads. Under
    # WinRM those threads have no PowerShell runspace, so invoking the callback
    # can terminate the remote pipeline with a truncated "#< CLIXML" error.
    # Task-based reads drain both pipes without executing PowerShell callbacks.
    $stdoutTask = $p.StandardOutput.ReadToEndAsync()
    $stderrTask = $p.StandardError.ReadToEndAsync()

    $timedOut = -not $p.WaitForExit($TimeoutSeconds * 1000)
    if ($timedOut) {
        try {
            $p.Kill($true)
        } catch {
            try { $p.Kill() } catch {}
        }
        # Give a killed process a short bounded window to close redirected pipes.
        try { $null = $p.WaitForExit(5000) } catch {}
    }

    # Process exit closes both redirected streams; wait only a bounded interval
    # for the task continuations to publish the captured text.
    try { $null = $stdoutTask.Wait(5000) } catch {}
    try { $null = $stderrTask.Wait(5000) } catch {}

    $stdoutText = ''
    $stderrText = ''
    if ($stdoutTask.IsCompleted) {
        try { $stdoutText = $stdoutTask.GetAwaiter().GetResult() } catch {}
    }
    if ($stderrTask.IsCompleted) {
        try { $stderrText = $stderrTask.GetAwaiter().GetResult() } catch {}
    }

    $text = ($stdoutText + $stderrText).TrimEnd()
    $code = if ($timedOut) { -1 } else { $p.ExitCode }

    if ($timedOut) {
        $text = "timed out after ${TimeoutSeconds}s: $FilePath $($Arguments -join ' ')`n$text"
    }
    if ($ThrowOnNonZero -and $code -ne 0) {
        throw "$FilePath $($Arguments -join ' ') failed with exit $code`n$text"
    }
    [pscustomobject]@{
        ExitCode = $code
        TimedOut = $timedOut
        Output = $text
    }
}

function Invoke-UsbipChecked {
    # PowerShell does not turn a non-zero native executable exit code into a
    # terminating error. Capture it explicitly so a failed policy mutation or
    # query cannot silently continue and make the test exercise a stale policy.
    param(
        [Parameter(Mandatory)] [string] $UsbipExe,
        [Parameter(Mandatory)] [string[]] $Arguments,
        [int] $TimeoutSeconds = 30
    )
    (Invoke-NativeWithTimeout -FilePath $UsbipExe -Arguments $Arguments `
        -TimeoutSeconds $TimeoutSeconds -ThrowOnNonZero).Output
}

function Get-FilterPolicyState {
    # Read the policy back from the driver and return stable machine-readable
    # JSON rather than making Python parse the CLI's human formatting.
    param([string] $UsbipExe = 'usbip.exe')
    $out = Invoke-UsbipChecked -UsbipExe $UsbipExe -Arguments @('filter')
    $mode = if ($out -match 'Device-type filter:\s+DISABLED') { 'disabled' } else { 'whitelist' }
    $categories = @()
    foreach ($line in ($out -split "`r?`n")) {
        if ($line -match '^\s*\[x\]\s+(\S+)') { $categories += $Matches[1] }
    }
    [pscustomobject]@{
        Mode       = $mode
        Categories = @($categories | Sort-Object -Unique)
    } | ConvertTo-Json -Compress
}

function Set-FilterPolicy {
    # Mutate, then independently read back from the driver. Returns exactly one
    # JSON object from Get-FilterPolicyState; callers compare it with the intended
    # mode/categories before attaching any device.
    param(
        [string[]] $Allow,
        [switch]   $DenyAll,
        [switch]   $Disable,
        [string]   $UsbipExe = 'usbip.exe'
    )
    if ($Disable) {
        $null = Invoke-UsbipChecked -UsbipExe $UsbipExe -Arguments @('filter', '--disable')
    } elseif ($DenyAll) {
        $null = Invoke-UsbipChecked -UsbipExe $UsbipExe -Arguments @('filter', '--deny-all')
    } elseif ($Allow) {
        $null = Invoke-UsbipChecked -UsbipExe $UsbipExe `
            -Arguments @('filter', '--allow', ($Allow -join ','))
    } else {
        throw 'Set-FilterPolicy requires -Disable, -DenyAll, or non-empty -Allow'
    }
    Get-FilterPolicyState -UsbipExe $UsbipExe
}

function Invoke-Attach {
    # Returns @{ Ok=<bool>; ExitCode=<int>; Output=<string> }.
    param(
        [Parameter(Mandatory)] [string] $Server,
        [Parameter(Mandatory)] [string] $BusId,
        [string] $UsbipExe = 'usbip.exe'
    )
    $r = Invoke-NativeWithTimeout -FilePath $UsbipExe `
        -Arguments @('attach', '-r', $Server, '-b', $BusId) -TimeoutSeconds 30
    [pscustomobject]@{ Ok = ($r.ExitCode -eq 0); ExitCode = $r.ExitCode; Output = $r.Output }
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
    # Require the device to be present AND started (Status 'OK'). A node that is
    # merely present but failed to start is not a successful enumeration, and on
    # DENY it must not count as "present". (Stale phantom nodes left by a dropped
    # usbip2_ude session can report Status 'OK' too -- those are reaped by
    # Clear-UsbipState between tests; this status gate is the second line.)
    $null -ne (Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
               Where-Object { $_.InstanceId -match $match -and $_.Status -eq 'OK' })
}

function Get-PnpExposure {
    # Return ANY currently-present PnP node matching VID/PID, regardless of
    # Status. For a denied device even a failed-start node is exposure: Windows
    # observed/published the device, violating the pre-enumeration boundary.
    param(
        [Parameter(Mandatory)] [string] $Vid,
        [Parameter(Mandatory)] [string] $ProductId
    )
    $match = "VID_${Vid}&PID_${ProductId}"
    Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
        Where-Object { $_.InstanceId -match $match } |
        ForEach-Object {
            [pscustomobject]@{
                InstanceId = $_.InstanceId
                Status     = "$($_.Status)"
                Class      = "$($_.Class)"
            } | ConvertTo-Json -Compress
        }
}

function Get-PnpNodeDetails {
    # Detailed VID/PID-correlated PnP diagnostics for devices that attach but do
    # not start a function-driver child. This intentionally includes failed-start
    # nodes and selected driver-matching properties so a class-driver limitation
    # is visible in the xfail reason instead of being reduced to "no Net child".
    param(
        [Parameter(Mandatory)] [string] $Vid,
        [Parameter(Mandatory)] [string] $ProductId
    )
    $match = "VID_${Vid}&PID_${ProductId}"

    function PropData($InstanceId, $KeyName) {
        $p = Get-PnpDeviceProperty -InstanceId $InstanceId `
            -KeyName $KeyName -ErrorAction SilentlyContinue
        if ($null -eq $p) { return $null }
        return $p.Data
    }

    Get-PnpDevice -ErrorAction SilentlyContinue |
        Where-Object { $_.InstanceId -match $match } |
        ForEach-Object {
            [pscustomobject]@{
                InstanceId    = $_.InstanceId
                Class         = "$($_.Class)"
                Status        = "$($_.Status)"
                FriendlyName  = "$($_.FriendlyName)"
                Problem       = "$(PropData $_.InstanceId 'DEVPKEY_Device_ProblemCode')"
                Service       = "$(PropData $_.InstanceId 'DEVPKEY_Device_Service')"
                ClassGuid     = "$(PropData $_.InstanceId 'DEVPKEY_Device_ClassGuid')"
                Enumerator    = "$(PropData $_.InstanceId 'DEVPKEY_Device_EnumeratorName')"
                HardwareIds   = @(PropData $_.InstanceId 'DEVPKEY_Device_HardwareIds')
                CompatibleIds = @(PropData $_.InstanceId 'DEVPKEY_Device_CompatibleIds')
            } | ConvertTo-Json -Compress
        }
}

function Get-FilterEventCursor {
    # RecordId is monotonic within a Windows event log. Taking this cursor just
    # before attach makes it impossible for a stale event with the same PID to
    # satisfy the rejection oracle.
    $evt = Get-WinEvent -FilterHashtable @{
        LogName = 'System'; ProviderName = 'usbip2_ude'
    } -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($null -eq $evt) { 0 } else { [long]$evt.RecordId }
}

function Find-FilterRejectionAfter {
    # Return one correlated rejection newer than the supplied cursor. Match both
    # VID and PID, and optionally busid; returns empty output if none exists.
    # Some Windows event-message render paths truncate insertion strings around
    # the whitelist/VID/PID/busid suffix. If the rejection text is present and
    # the message ends while spelling that suffix, accept the event as a
    # truncated match rather than losing a valid denial oracle.
    param(
        [Parameter(Mandatory)] [long] $AfterRecordId,
        [Parameter(Mandatory)] [string] $Vid,
        [Parameter(Mandatory)] [string] $ProductId,
        [string] $BusId
    )
    $vidToken = "VID_$Vid"
    $pidToken = "PID_$ProductId"
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'System'; ProviderName = 'usbip2_ude'
    } -MaxEvents 100 -ErrorAction SilentlyContinue |
        Where-Object {
            $msg = $_.Message
            $isRejection = $msg -match 'Device blocked by the device-type filter'
            $vidPidMatches = (
                $msg -match [regex]::Escape($vidToken) -and
                $msg -match [regex]::Escape($pidToken)
            )
            $vidPidSuffixTruncated = (
                $isRejection -and
                $msg -match ';\s*(?:V|VI|VID_?[0-9A-Fa-f]*(?:&(?:P|PI|PID(?:_[0-9A-Fa-f]*)?)?)?)?$'
            )
            $whitelistTruncated = (
                $isRejection -and
                $msg -match 'whitelist:\s*.*(?:[0-9A-Fa-f]{1,2}|[0-9A-Fa-f]{2}/\*{0,2}|[0-9A-Fa-f]{2}/\*\*/\*{0,2}|[0-9A-Fa-f]{2}/\*\*/\*\*)$'
            )
            $busidMatches = [string]::IsNullOrEmpty($BusId) -or
                $msg -match [regex]::Escape($BusId) -or
                ($isRejection -and
                 $msg -match ';\s*b(?:u(?:s(?:i(?:d(?:=.*)?)?)?)?)?$')
            $_.RecordId -gt $AfterRecordId -and
            (($vidPidMatches -and $busidMatches) -or
             $vidPidSuffixTruncated -or
             $whitelistTruncated)
        } | Select-Object -First 1
    if ($null -ne $events) {
        [pscustomobject]@{
            RecordId   = [long]$events.RecordId
            TimeCreated = $events.TimeCreated.ToUniversalTime().ToString('o')
            Message    = $events.Message
        } | ConvertTo-Json -Compress
    }
}

function Get-PresentHidInstanceIds {
    # Instance IDs of currently-present HID-class devices. The TOCTOU test takes a
    # baseline before attach and diffs after, so the VM's own keyboard/mouse are
    # excluded and only a smuggled HID interface shows up as "new".
    (Get-PnpDevice -PresentOnly -Class 'HIDClass' -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty InstanceId) -join "`n"
}

function Get-HidChildStatus {
    # Diagnose the HID stack for a device, including both the USB HID parent and
    # the Keyboard child. A parent that enumerated but whose kbdhid child never
    # started cannot deliver keystrokes, so the efficacy test needs to tell
    # "endpoint loaded but silent" from "keyboard child ready".
    param(
        [Parameter(Mandatory)] [string] $Vid,        # e.g. '16C0'
        [Parameter(Mandatory)] [string] $ProductId   # e.g. '03E8'
    )
    $match = "VID_${Vid}&PID_${ProductId}"
    @(
        Get-PnpDevice -PresentOnly -Class 'HIDClass' -ErrorAction SilentlyContinue
        Get-PnpDevice -PresentOnly -Class 'Keyboard' -ErrorAction SilentlyContinue
    ) |
        Where-Object { $_.InstanceId -match $match } |
        ForEach-Object {
            $problem = (Get-PnpDeviceProperty -InstanceId $_.InstanceId `
                -KeyName 'DEVPKEY_Device_ProblemCode' -ErrorAction SilentlyContinue).Data
            $service = (Get-PnpDeviceProperty -InstanceId $_.InstanceId `
                -KeyName 'DEVPKEY_Device_Service' -ErrorAction SilentlyContinue).Data
            [pscustomobject]@{
                InstanceId = $_.InstanceId
                Class      = "$($_.Class)"
                Status     = "$($_.Status)"
                Problem    = "$problem"
                Service    = "$service"
            } | ConvertTo-Json -Compress
        }
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

function Get-NetChildStatus {
    # Diagnose a network child stack for a VID/PID. A global adapter-name diff can
    # be satisfied by unrelated network churn, so the rogue-NIC efficacy test uses
    # this VID/PID-correlated PnP child oracle instead.
    param(
        [Parameter(Mandatory)] [string] $Vid,
        [Parameter(Mandatory)] [string] $ProductId
    )
    $match = "VID_${Vid}&PID_${ProductId}"
    Get-PnpDevice -PresentOnly -Class 'Net' -ErrorAction SilentlyContinue |
        Where-Object { $_.InstanceId -match $match } |
        ForEach-Object {
            $problem = (Get-PnpDeviceProperty -InstanceId $_.InstanceId `
                -KeyName 'DEVPKEY_Device_ProblemCode' -ErrorAction SilentlyContinue).Data
            $service = (Get-PnpDeviceProperty -InstanceId $_.InstanceId `
                -KeyName 'DEVPKEY_Device_Service' -ErrorAction SilentlyContinue).Data
            [pscustomobject]@{
                InstanceId   = $_.InstanceId
                Class        = "$($_.Class)"
                Status       = "$($_.Status)"
                Problem      = "$problem"
                Service      = "$service"
                FriendlyName = "$($_.FriendlyName)"
            } | ConvertTo-Json -Compress
        }
}

function Get-PresentNetAdapterNames {
    # Names of network adapters that are actually present (not 'Not Present').
    (Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object Status -ne 'Not Present' |
        Select-Object -ExpandProperty Name) -join "`n"
}

function Get-WindowsArtifactManifest {
    # Identify exactly what the Windows side is running. Hashes make a stale
    # helper/executable/driver deployment visible in test output and optionally
    # comparable with expected values from config.ini.
    param(
        [Parameter(Mandatory)] [string] $UsbipExe,
        [Parameter(Mandatory)] [string] $Helpers
    )

    function Artifact([string] $Name, [string] $Path) {
        if ([string]::IsNullOrEmpty($Path) -or !(Test-Path -LiteralPath $Path)) {
            return [pscustomobject]@{ Name=$Name; Path=$Path; Sha256=$null; Version=$null }
        }
        $item = Get-Item -LiteralPath $Path
        [pscustomobject]@{
            Name    = $Name
            Path    = $item.FullName
            Sha256  = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLower()
            Version = "$($item.VersionInfo.FileVersion)"
        }
    }

    function DriverPath([string] $Name) {
        $svc = Get-CimInstance Win32_SystemDriver -Filter "Name='$Name'" `
            -ErrorAction SilentlyContinue
        if ($null -eq $svc) { return $null }
        $path = "$($svc.PathName)".Trim('"')
        if ($path -match '^\\SystemRoot\\(.+)$') {
            return Join-Path $env:SystemRoot $Matches[1]
        }
        if ($path -match '^System32\\(.+)$') {
            return Join-Path $env:SystemRoot $path
        }
        $path
    }

    @(
        Artifact 'usbip.exe' $UsbipExe
        Artifact 'helpers.ps1' $Helpers
        Artifact 'usbip2_ude.sys' (DriverPath 'usbip2_ude')
        Artifact 'usbip2_filter.sys' (DriverPath 'usbip2_filter')
    ) | ConvertTo-Json -Compress
}

function Clear-UsbipState {
    # Detach everything, remove any lingering PnP nodes for the test VID, and
    # reset the filter so each test starts clean.
    #
    # The PnP removal matters: a usbip2_ude session that drops (e.g. the gadget
    # is torn down server-side, or the USB/IP connection resets) can leave an
    # orphaned device node that Windows still reports as present -- and even with
    # Status 'OK'. Test-PnpPresent would then match that phantom and report a
    # device that isn't really attached, a false positive on the security-
    # critical presence oracle. Reap them here (best effort) so every test starts
    # from a clean PnP slate. Only nodes matching the test VID are touched.
    param(
        [string] $UsbipExe = 'usbip.exe',
        [string] $TestVid  = '16C0',      # VID shared by all test gadgets (devices.py)
        [ValidateSet('closeonly', 'full', 'skip')]
        [string] $DetachMode = 'skip'
    )
    Write-Output "[cleanup] helpers.ps1 native-timeout revision: task-v4"
    # Detach is best-effort and intentionally opt-in for cleanup. In some wedged
    # UdeCx/plugin-out states even closeonly can block the WinRM cleanup path
    # before tests start. Stale VID nodes are still reaped below; set
    # DetachMode=closeonly/full only when you specifically need USB/IP detach.
    if ($DetachMode -eq 'skip') {
        Write-Output "[cleanup] skipping USB/IP detach by request"
    } else {
        $detachArg = if ($DetachMode -eq 'full') { '--all' } else { '--all=closeonly' }
        Write-Output "[cleanup] detaching all USB/IP ports ($DetachMode)"
        $detach = Invoke-NativeWithTimeout -FilePath $UsbipExe `
            -Arguments @('detach', $detachArg) -TimeoutSeconds 15
        if ($detach.TimedOut) {
            Write-Output "[cleanup] usbip.exe detach $detachArg timed out after 15s; continuing with PnP cleanup"
        } elseif ($detach.ExitCode -ne 0) {
            Write-Output "[cleanup] usbip.exe detach $detachArg exited $($detach.ExitCode): $($detach.Output)"
        }
        Start-Sleep -Milliseconds 1000
    }
    $null = Invoke-UsbipChecked -UsbipExe $UsbipExe -Arguments @('filter', '--disable')

    $match = "VID_$TestVid"
    $removePnpDevice = Get-Command Remove-PnpDevice -ErrorAction SilentlyContinue
    $pnputil = Get-Command pnputil.exe -ErrorAction SilentlyContinue
    $nodes = @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
        Where-Object { $_.InstanceId -match $match })

    foreach ($node in $nodes) {
        $id = $node.InstanceId
        Write-Output "[cleanup] stale PnP node found: $($node.Status) $($node.Class) $id"
        $removed = $false

        if ($null -ne $removePnpDevice) {
            try {
                Write-Output "[cleanup] removing via Remove-PnpDevice: $id"
                Remove-PnpDevice -InstanceId $id -Confirm:$false -ErrorAction Stop
                Write-Output "[cleanup] Remove-PnpDevice completed: $id"
                $removed = $true
            } catch {
                Write-Output "[cleanup] Remove-PnpDevice failed for $id`: $($_.Exception.Message)"
            }
        } else {
            Write-Output "[cleanup] Remove-PnpDevice not available; using pnputil.exe"
        }

        if (-not $removed) {
            if ($null -eq $pnputil) {
                Write-Output "[cleanup] pnputil.exe not available; cannot remove $id"
                continue
            }
            Write-Output "[cleanup] removing via pnputil.exe /remove-device: $id"
            $remove = Invoke-NativeWithTimeout -FilePath $pnputil.Source `
                -Arguments @('/remove-device', $id) -TimeoutSeconds 20
            $remove.Output.Trim() -split "`r?`n" |
                Where-Object { $_ } |
                ForEach-Object { Write-Output "[cleanup] pnputil: $_" }
            if ($remove.ExitCode -eq 0) {
                Write-Output "[cleanup] pnputil.exe completed: $id"
            } elseif ($remove.TimedOut) {
                Write-Output "[cleanup] pnputil.exe timed out for $id"
            } else {
                Write-Output "[cleanup] pnputil.exe failed for $id with exit $($remove.ExitCode)"
            }
        }
    }

    Start-Sleep -Milliseconds 300
    $remaining = @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
        Where-Object { $_.InstanceId -match $match } |
        Select-Object InstanceId, Status, Class)
    if ($remaining.Count -ne 0) {
        throw "Clear-UsbipState left test PnP nodes present: $($remaining | ConvertTo-Json -Compress)"
    }
    [pscustomobject]@{ Clean=$true; Remaining=0 } | ConvertTo-Json -Compress
}
