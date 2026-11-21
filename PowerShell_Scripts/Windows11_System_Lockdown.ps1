#Requires -Version 5.1
<#
.SYNOPSIS
    Hardened Windows 11 Debloat & Permanent Windows Update Lockdown Script
.DESCRIPTION
    1. Auto-elevates via UAC into a 64-bit PowerShell session.
    2. Applies Group Policy registry blocks for Windows Update & Drivers.
    3. Seizes TrustedInstaller ownership of wuauserv, UsoSvc, WaaSMedicSvc, BITS, and DoSvc.
    4. Deletes SCM TriggerInfo/FailureActions and neutralizes ServiceDll pointers so svchost cannot load update engines.
    5. Disables and locks all UpdateOrchestrator, WindowsUpdate, and WaaSMedic scheduled tasks.
    6. Registers a SYSTEM-level startup guard task to enforce Start=4 on every boot.
    7. Disables WSearch, uninstalls Edge & WebView2, and removes/blocks Microsoft Store.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# ==============================================================================
# 0. ELEVATION & PRIVILEGE INITIALIZATION
# ==============================================================================
function Assert-Elevated64BitSession {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)

    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        if (-not $PSCommandPath) {
            Write-Error "Save this script to a .ps1 file before running so it can auto-elevate."
            exit 1
        }

        $psExe = if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
            Join-Path $env:WINDIR "Sysnative\WindowsPowerShell\v1.0\powershell.exe"
        } else {
            Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
        }

        try {
            $argsList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
            $proc = Start-Process -FilePath $psExe -ArgumentList $argsList -Verb RunAs -Wait -PassThru
            exit $proc.ExitCode
        } catch {
            Write-Error "Elevation failed or was cancelled. $($_.Exception.Message)"
            exit 1
        }
    }
}

function Enable-Win32Privileges {
    $csCode = @"
using System;
using System.Runtime.InteropServices;

public class PrivilegeHelper {
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    internal static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct TokPriv1Luid {
        public int Count;
        public long Luid;
        public int Attr;
    }

    public static void Enable(string privilege) {
        IntPtr htok = IntPtr.Zero;
        if (OpenProcessToken(GetCurrentProcess(), 0x00000028, ref htok)) {
            TokPriv1Luid tp = new TokPriv1Luid { Count = 1, Luid = 0, Attr = 0x00000002 };
            if (LookupPrivilegeValue(null, privilege, ref tp.Luid)) {
                AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            }
        }
    }
}
"@
    if (-not ([System.Management.Automation.PSTypeName]'PrivilegeHelper').Type) {
        Add-Type -TypeDefinition $csCode -ErrorAction SilentlyContinue
    }
    [PrivilegeHelper]::Enable("SeTakeOwnershipPrivilege")
    [PrivilegeHelper]::Enable("SeRestorePrivilege")
    [PrivilegeHelper]::Enable("SeSecurityPrivilege")
    [PrivilegeHelper]::Enable("SeBackupPrivilege")
}

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================
function Set-RegistryDword {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [int]$Value
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force
}

function Seize-AndLockRegistryTree {
    param(
        [Parameter(Mandatory)] [string]$SubKeyPath,
        [switch]$ApplySystemDeny
    )
    $adminSid  = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    $systemSid = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-18")

    # Recursively seize ownership of the target key and all subkeys (e.g., Parameters, TriggerInfo)
    $allSubKeys = @($SubKeyPath)
    try {
        $base = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKeyPath)
        if ($base) {
            foreach ($child in $base.GetSubKeyNames()) {
                $allSubKeys += "$SubKeyPath\$child"
            }
            $base.Close()
        }
    } catch {}

    foreach ($currentKey in $allSubKeys) {
        try {
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                $currentKey,
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                [System.Security.AccessControl.RegistryRights]::TakeOwnership
            )
            if ($key) {
                $acl = $key.GetAccessControl()
                $acl.SetOwner($adminSid)
                $key.SetAccessControl($acl)
                $key.Close()
            }

            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                $currentKey,
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                [System.Security.AccessControl.RegistryRights]::ChangePermissions
            )
            if ($key) {
                $acl = $key.GetAccessControl()
                # Remove any existing Deny rules first so Administrators can write
                $acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |
                    Where-Object { $_.AccessControlType -eq "Deny" } |
                    ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

                $allowAdmin = [System.Security.AccessControl.RegistryAccessRule]::new(
                    $adminSid, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
                )
                $acl.AddAccessRule($allowAdmin)

                if ($ApplySystemDeny) {
                    $denySystem = [System.Security.AccessControl.RegistryAccessRule]::new(
                        $systemSid, "SetValue,CreateSubKey,Delete", "ContainerInherit,ObjectInherit", "None", "Deny"
                    )
                    $acl.AddAccessRule($denySystem)
                }

                $key.SetAccessControl($acl)
                $key.Close()
            }
        } catch {}
    }
}

function Disable-HardenedService {
    param(
        [Parameter(Mandatory)] [string]$ServiceName,
        [switch]$NeutralizePayload
    )
    if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
        return
    }

    $regSubKey = "SYSTEM\CurrentControlSet\Services\$ServiceName"
    $psRegPath = "HKLM:\$regSubKey"

    # 1. Seize full control of the service key & subkeys from TrustedInstaller
    Seize-AndLockRegistryTree -SubKeyPath $regSubKey

    # 2. Force-kill the running service host process if it refuses to stop gracefully
    $svcCim = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if ($svcCim -and $svcCim.ProcessId -gt 0 -and $svcCim.State -eq "Running") {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 300
        $svcCheck = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
        if ($svcCheck -and $svcCheck.State -eq "Running") {
            # Only kill PID if it's not shared with critical core OS services
            $sharedServices = @(Get-CimInstance Win32_Service -Filter "ProcessId=$($svcCheck.ProcessId)")
            if ($sharedServices.Count -eq 1) {
                Stop-Process -Id $svcCheck.ProcessId -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # 3. Disable via sc.exe and clear recovery failure actions
    & sc.exe config $ServiceName start= disabled | Out-Null
    & sc.exe failure $ServiceName reset= 0 actions= "" | Out-Null

    # 4. Set Start = 4 directly in Registry
    Set-ItemProperty -Path $psRegPath -Name "Start" -Value 4 -Type DWord -Force

    # 5. Deep neutralization: remove TriggerInfo & point ServiceDll to non-existent file
    if ($NeutralizePayload) {
        $triggerPath = Join-Path $psRegPath "TriggerInfo"
        if (Test-Path -LiteralPath $triggerPath) {
            Remove-Item -Path $triggerPath -Recurse -Force -ErrorAction SilentlyContinue
        }

        $paramPath = Join-Path $psRegPath "Parameters"
        if (Test-Path -LiteralPath $paramPath) {
            $currentDll = (Get-ItemProperty -Path $paramPath -Name "ServiceDll" -ErrorAction SilentlyContinue).ServiceDll
            if ($currentDll -and ($currentDll -notlike "*_DISABLED*")) {
                # Backup original path to ServiceDll_Backup in case you ever want to restore it
                Set-ItemProperty -Path $paramPath -Name "ServiceDll_Backup" -Value $currentDll -Type ExpandString -Force
                Set-ItemProperty -Path $paramPath -Name "ServiceDll" -Value "$currentDll.DISABLED" -Type ExpandString -Force
            }
        }

        # Lock key against SYSTEM / TrustedInstaller modifications
        Seize-AndLockRegistryTree -SubKeyPath $regSubKey -ApplySystemDeny
    }

$finalState = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
if ($finalState -and $finalState.StartMode -eq "Disabled") {
Write-Host "  [OK] Locked & Disabled service: $ServiceName" -ForegroundColor Green
} else {
Write-Warning "  [!] Service $ServiceName StartMode is '$($finalState.StartMode)'."
}
}
function Disable-ProtectedTask {
param(
[Parameter(Mandatory)] [string]$TaskPath,
[Parameter(Mandatory)] [string]$TaskName
)
$fullTask     = "$TaskPath$TaskName"
$relativePath = $fullTask.TrimStart('\')
$taskXmlFile  = Join-Path "$env:SystemRoot\System32\Tasks" $relativePath
$taskRegKey   = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\$relativePath"
if (Test-Path -LiteralPath $taskXmlFile) {
& takeown.exe /F $taskXmlFile /A | Out-Null
& icacls.exe $taskXmlFile /grant "*S-1-5-32-544:F" | Out-Null
}
Seize-AndLockRegistryTree -SubKeyPath $taskRegKey
& schtasks.exe /Change /TN $fullTask /DISABLE 2>&1 | Out-Null
Disable-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null
Seize-AndLockRegistryTree -SubKeyPath $taskRegKey -ApplySystemDeny
}

==============================================================================
# MAIN EXECUTION
==============================================================================

Assert-Elevated64BitSession
Enable-Win32Privileges

# 1. WINDOWS UPDATE & SERVICES

Write-Host "`n=== 1. Hardening & Neutralizing Windows Update Services ===" -ForegroundColor Cyan
$wuPolicy   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$wuAuPolicy = Join-Path $wuPolicy "AU"
Set-RegistryDword -Path $wuAuPolicy -Name "NoAutoUpdate" -Value 1
Set-RegistryDword -Path $wuAuPolicy -Name "AUOptions" -Value 1
Set-RegistryDword -Path $wuPolicy   -Name "ExcludeWUDriversInQualityUpdate" -Value 1
Set-RegistryDword -Path $wuPolicy   -Name "DisableWindowsUpdateAccess" -Value 1
Set-RegistryDword -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Value 0
$wuServices = @("wuauserv", "UsoSvc", "WaaSMedicSvc", "BITS", "DoSvc")
foreach ($svc in $wuServices) {
$deepLock = $svc -in @("wuauserv", "UsoSvc", "WaaSMedicSvc", "DoSvc")
Disable-HardenedService -ServiceName $svc -NeutralizePayload:$deepLock
}

# 1B. PROTECTED SCHEDULED TASKS & BINARIES

Write-Host "`n=== 1b. Disabling Protected Windows Update Scheduled Tasks ===" -ForegroundColor Cyan
$updateTaskPaths = @(
"\Microsoft\Windows\UpdateOrchestrator",
"\Microsoft\Windows\WindowsUpdate",
"\Microsoft\Windows\WaaSMedic"
)
foreach ($path in $updateTaskPaths) {
$tasks = Get-ScheduledTask -TaskPath $path -ErrorAction SilentlyContinue
foreach ($task in $tasks) {
Disable-ProtectedTask -TaskPath $task.TaskPath -TaskName $task.TaskName
$check = Get-ScheduledTask -TaskPath $task.TaskPath -TaskName $task.TaskName -ErrorAction SilentlyContinue
if ($check -and $check.State -eq "Disabled") {
Write-Host "  [OK] Disabled task: $($task.TaskPath)$($task.TaskName)" -ForegroundColor Green
} elseif ($check) {
Write-Warning "  [!] Task remains enabled: $($task.TaskPath)$($task.TaskName)"
}
}
}
$updateBinaries = @(
(Join-Path $env:SystemRoot "System32\UsoClient.exe"),
(Join-Path $env:SystemRoot "System32\WaaSMedicAgent.exe"),
(Join-Path $env:SystemRoot "System32\wuauclt.exe")
)
foreach ($bin in $updateBinaries) {
if (Test-Path -LiteralPath $bin) {
& takeown.exe /F $bin /A | Out-Null
if ($LASTEXITCODE -eq 0) {
& icacls.exe $bin /deny '*S-1-1-0:(RX)' | Out-Null
if ($LASTEXITCODE -eq 0) {
Write-Host "  [OK] Blocked binary execution: $bin" -ForegroundColor Yellow
}
}
}
}

# 1C. BOOT-TIME WATCHDOG TASK (RE-ENFORCES DISABLED STATE AT EVERY STARTUP)

Write-Host "`n=== 1c. Installing Boot-Time Update Lockdown Watchdog ===" -ForegroundColor Cyan
$guardCmd = 'reg add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v Start /t REG_DWORD /d 4 /f & reg add "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc" /v Start /t REG_DWORD /d 4 /f & reg add "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v Start /t REG_DWORD /d 4 /f & net stop wuauserv /y'
$action   = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c $guardCmd"
$trigger  = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
Register-ScheduledTask -TaskName "WU_Lockdown_Guard" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Write-Host "  [OK] Registered SYSTEM startup guard task: WU_Lockdown_Guard" -ForegroundColor Green

# 2. WINDOWS SEARCH INDEXING

Write-Host "`n=== 2. Disabling Windows Search Indexing (WSearch) ===" -ForegroundColor Cyan
Disable-HardenedService -ServiceName "WSearch"

# 3. MICROSOFT EDGE & WEBVIEW2

Write-Host "`n=== 3. Uninstalling & Blocking Microsoft Edge & WebView2 ===" -ForegroundColor Cyan
foreach ($svc in @("edgeupdate", "edgeupdatem", "MicrosoftEdgeElevationService")) {
Disable-HardenedService -ServiceName $svc
}
Get-ScheduledTask -TaskName "MicrosoftEdge" -ErrorAction SilentlyContinue |
Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
foreach ($proc in @("msedge", "msedgewebview2", "MicrosoftEdgeUpdate", "SearchHost", "Widgets")) {
Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue
}
$edgeInstallers = @(
Get-ChildItem -Path "${env:ProgramFiles(x86)}\Microsoft\Edge\Application*\Installer\setup.exe" -ErrorAction SilentlyContinue
)
foreach ($setup in $edgeInstallers) {
Start-Process -FilePath $setup.FullName -ArgumentList "--uninstall --system-level --verbose-logging --force-uninstall" -Wait
}
$webViewInstallers = @(
Get-ChildItem -Path "${env:ProgramFiles(x86)}\Microsoft\EdgeWebView\Application*\Installer\setup.exe" -ErrorAction SilentlyContinue
)
foreach ($setup in $webViewInstallers) {
Start-Process -FilePath $setup.FullName -ArgumentList "--uninstall --msedgewebview --system-level --verbose-logging --force-uninstall" -Wait
}
Get-AppxPackage -AllUsers "MicrosoftEdge" -ErrorAction SilentlyContinue |
Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
Get-WindowsCapability -Online -ErrorAction SilentlyContinue |
Where-Object { $_.Name -like "Edge" } |
Remove-WindowsCapability -Online -ErrorAction SilentlyContinue
$edgePolicy = "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate"
Set-RegistryDword -Path $edgePolicy -Name "DoNotUpdateToEdgeWithChromium" -Value 1
Set-RegistryDword -Path $edgePolicy -Name "InstallDefault" -Value 0
Set-RegistryDword -Path $edgePolicy -Name "Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" -Value 0
Set-RegistryDword -Path $edgePolicy -Name "Install{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" -Value 0
Write-Host "  [OK] Edge & WebView2 removal and policy blocks applied." -ForegroundColor Green

# 4. MICROSOFT STORE

Write-Host "`n=== 4. Removing & Blocking Microsoft Store ===" -ForegroundColor Cyan
Stop-Process -Name "WinStore.App", "StoreExperienceHost" -Force -ErrorAction SilentlyContinue
Get-AppxPackage -AllUsers "WindowsStore" -ErrorAction SilentlyContinue | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
Get-AppxPackage -AllUsers "StorePurchaseApp" -ErrorAction SilentlyContinue | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
Where-Object { $_.PackageName -like "WindowsStore" -or $_.PackageName -like "StorePurchaseApp" } |
Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
Disable-HardenedService -ServiceName "InstallService"
$storePolicy = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
Set-RegistryDword -Path $storePolicy -Name "RemoveWindowsStore" -Value 1
Set-RegistryDword -Path $storePolicy -Name "AutoDownload" -Value 2
Set-RegistryDword -Path $storePolicy -Name "DisableStoreApps" -Value 1
Get-ScheduledTask -TaskPath "\Microsoft\Windows\WindowsStore*" -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
Get-ScheduledTask -TaskPath "\Microsoft\Windows\InstallService*" -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
Write-Host "  [OK] Microsoft Store removal and policy blocks applied." -ForegroundColor Green

# 5. FINAL AUDIT

Write-Host "`n=== 5. Final Lockdown Audit ===" -ForegroundColor Cyan
foreach ($svc in @("wuauserv", "UsoSvc", "WaaSMedicSvc")) {
$info = Get-CimInstance Win32_Service -Filter "Name='$svc'" -ErrorAction SilentlyContinue
if ($info) {
Write-Host "  $svc -> State: $($info.State) | StartMode: $($info.StartMode)"
}
}
$remainingTasks = foreach ($path in $updateTaskPaths) {
Get-ScheduledTask -TaskPath $path -ErrorAction SilentlyContinue | Where-Object { $_.State -ne "Disabled" }
}
if ($remainingTasks) {
Write-Warning "  [!] $(@($remainingTasks).Count) protected task(s) remain active:"
$remainingTasks | ForEach-Object { Write-Warning "      $($_.TaskPath)$($_.TaskName)" }
} else {
Write-Host "  [OK] All UpdateOrchestrator, WindowsUpdate, and WaaSMedic tasks are Disabled." -ForegroundColor Green
}
Write-Host "`nCompleted. Restart your PC to verify that wuauserv stays permanently Stopped/Disabled.`n" -ForegroundColor Yellow