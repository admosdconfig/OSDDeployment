#Setting 
$ScriptFile = $MyInvocation.MyCommand.Name 
$ScriptLocation  = Split-Path $MyInvocation.MyCommand.Path -Parent

$Path = "C:\Windows\Logs\"

$fileToCheck = "C:\Windows\Logs\DeploymentInfo.txt"
if (Test-Path $fileToCheck -PathType leaf)
{
    Remove-Item $fileToCheck
}

New-Item "C:\Windows\Logs\DeploymentInfo.txt" -ItemType file

$BuildDisplayVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion).DisplayVersion
$BuildNumber = (Get-WmiObject -Class Win32_OperatingSystem).BuildNumber
$BuildVersion = (Get-WmiObject -Class Win32_OperatingSystem).Version
$TaskSequenceName = "MDT Task Sequence: $TSEnv:TaskSequenceName"
$DeploymentType = "Deployment Type: $TSEnv:DeploymentType"
$JoinDomain = "Domain: $TSEnv:JoinDomain"
$JoinWorkgroup = "Workgroup: $TSEnv:JoinWorkgroup"
$OSDComputerName = Gwmi Win32_ComputerSystem | Select Caption
$OSDComputerName = $OSDComputerName.Caption
$OSDComputerName = "ComputerName: $OSDComputerName"
$MachineObjectOU = "Organizational Unit: $TSEnv:MachineObjectOU"
$Make = "Manufacturer: $TSEnv:Make"
$Model = "Model: $TSEnv:Model"
$AssetTag = "AssetTag: $TSEnv:AssetTag"
$SerialNumber = "SerialNumber: $TSEnv:SerialNumber"
$OSCertified  = "Certified Date: 11th of November 2022"

$Language = "Present Windows Languages: $TSEnv:ImageLanguage001, $TSEnv:ImageLanguage002, $TSEnv:ImageLanguage003, $TSEnv:ImageLanguage004"
$Version = Gwmi Win32_Operatingsystem | Select Caption
$Version = $Version.Caption
$Version = "Operating System: $Version $BuildDisplayVersion (OS Build: $BuildVersion)"
$Architecture = "Platform Architecture: $TSEnv:Architecture"

# BitLocker, if you wish to use in the future 
# $BDE = "Bitlocker Enabled: $TSEnv:IsBDE"
# $BDEKey = (Get-BitLockerVolume -MountPoint C).KeyProtector.RecoveryPassword
# $BDEKey = "Bitlocker Recovery Key: $BDEKey"
 
$Date = Get-Date
$Date = "Deployment Date: $Date"
 
$Text = @"
==================================================
  ---- AMAP - MDT - Deployment Information ----
  
$OSCertified
$TaskSequenceName
$DeploymentType
$OSDComputerName
$JoinDomain
$JoinWorkgroup
$MachineObjectOU
$Date
 
!!! Hardware Information !!!

$Make
$Model
$AssetTag
$SerialNumber
$Language
$Version
$Architecture
 
!!! Miscellaneous Information !!!
 
        ------ End of Information ------ 
==================================================
"@
 
If (-NOT (Test-Path $Path )) {
MD $Path ; Set-ItemProperty -Path $Path -Name Attributes -Value ([System.IO.FileAttributes]::Hidden) -Force
}
 
If ( (Test-Path "$Path\DeploymentInfo.txt" )) {
$Text | Add-Content "$Path\DeploymentInfo.txt"
}
 
If (-NOT (Test-Path "$Path\DeploymentInfo.txt" )) {
$Text | Out-File -Filepath "$Path\DeploymentInfo.txt"
}