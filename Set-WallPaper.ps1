$ScriptVersion = "22.3.8.1"

function Enable-Privilege {
    param(
        ## The privilege to adjust.
        [ValidateSet(
            "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
            "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
            "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
            "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
            "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
            "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
            "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
            "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
            "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
            "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
            "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
        $Privilege,
        ## The process on which to adjust the privilege. Defaults to the current process.
        $ProcessId = $pid,
        ## Switch to disable the privilege, rather than enable it.
        [Switch] $Disable
    )

    ## Definition for P/Invoke to adjust privileges.
    $definition = @'
        using System;
        using System.Runtime.InteropServices;

        public class AdjPriv
        {
            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
                ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
            [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            internal struct TokPriv1Luid
            {
                public int Count;
                public long Luid;
                public int Attr;
            }

            internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
            internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
            internal const int TOKEN_QUERY = 0x00000008;
            internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

            public static bool EnablePrivilege(long processHandle, string privilege, bool disable)
            {
                bool retVal;
                TokPriv1Luid tp;
                IntPtr hproc = new IntPtr(processHandle);
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
                tp.Count = 1;
                tp.Luid = 0;
                tp.Attr = disable ? SE_PRIVILEGE_DISABLED : SE_PRIVILEGE_ENABLED;
                retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
                retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                return retVal;
            }
        }
'@

    $processHandle = (Get-Process -Id $ProcessId).Handle
    $type = Add-Type -TypeDefinition $definition -PassThru
    $type[0]::EnablePrivilege($processHandle, $Privilege, $Disable)
}

function Set-Owner {
    param (
        [Parameter(Mandatory = $true)][string] $identity,
        [Parameter(Mandatory = $true)][string] $filepath
    )

    $file = Get-Item -Path $filepath
    $acl = $file.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None)
    $me = [System.Security.Principal.NTAccount]$identity
    $acl.SetOwner($me)
    $file.SetAccessControl($acl)

    # After setting owner, modify the ACL.
    $acl = $file.GetAccessControl()
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, "FullControl", "Allow")
    $acl.SetAccessRule($rule)
    $file.SetAccessControl($acl)
}

function Set-Permission {
    param (
        [Parameter(Mandatory = $true)][string] $identity,
        [Parameter(Mandatory = $true)][string] $filepath,
        [Parameter(Mandatory = $true)][string] $FilesSystemRights,
        [Parameter(Mandatory = $true)][string] $type
    )

    $file = Get-Item -Path $filepath
    $acl = $file.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None)

    # Create new rule
    $FilesSystemAccessRuleArgumentList = $identity, $FilesSystemRights, $type
    $FilesSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $FilesSystemAccessRuleArgumentList
    
    # Apply new rule
    $acl.SetAccessRule($FilesSystemAccessRule)
    $file.SetAccessControl($acl)
}

# Get list of files
$files = Get-ChildItem -Path C:\Windows\Web\4K -Recurse | Where-Object { $_.Extension -eq ".jpg" }

try {
    $tsenv = New-Object -ComObject Microsoft.SMS.TSEnvironment
} catch {
    Write-Output "Not in TS"
}
if ($tsenv) {
    $InWinPE = $tsenv.value('_SMSTSInWinPE')
}

if ($InWinPE -ne "TRUE") {
    # Take ownership
    Enable-Privilege -Privilege SeTakeOwnershipPrivilege 

    # Set permissions on files
    $identity = "BUILTIN\Administrators"
    foreach ($filechild in $files) {
        Set-Owner -identity $identity -filepath $filechild.FullName
    }

    # Grant rights to Admin & System
    $identity = "BUILTIN\Administrators"
    $FilesSystemRights = "FullControl"
    $type = "Allow"
    foreach ($filechild in $files) {
        Set-Permission -identity $identity -type $type -FilesSystemRights $FilesSystemRights -filepath $filechild.FullName
    }

    # Set SYSTEM to Full Control
    $identity = "NT AUTHORITY\SYSTEM"
    $FilesSystemRights = "FullControl"
    $type = "Allow"
    foreach ($filechild in $files) {
        Set-Permission -identity $identity -type $type -FilesSystemRights $FilesSystemRights -filepath $filechild.FullName
    }

    # Delete "4K" images
    foreach ($filechild in $files) {
        Remove-Item -Path $filechild.FullName -Force -Verbose
        Write-Output "Deleting $($filechild.FullName)"
    }
}

# Download wallpaper from GitHub
$WallPaperURL = "https://github.com/admosdconfig/Public/blob/main/wallpaper.jpg"
Invoke-WebRequest -UseBasicParsing -Uri $WallPaperURL -OutFile "$env:TEMP\wallpaper.jpg"

# Copy the wallpaper into place
if (Test-Path -Path "$env:TEMP\wallpaper.jpg") {
    Write-Output "Running Command: Copy-Item .\wallpaper.jpg C:\Windows\Web\Wallpaper\Windows\img0.jpg -Force -Verbose"
    Copy-Item "$env:TEMP\wallpaper.jpg" "C:\Windows\Web\Wallpaper\Windows\img0.jpg" -Force -Verbose
} else {
    Write-Output "Did not find wallpaper.jpg in temp folder - Please confirm URL"
}

exit $exitcode
