[CmdletBinding()]
param (
    [parameter(Position = 0, Mandatory = $false)][string]$LMDomain = "corpid.net",
    [Parameter(Position = 1, Mandatory = $false)][string]$CompAcct = "localhost",
    [Parameter(Position = 2, Mandatory = $false)][decimal]$TimeDelay = 1,
    [Parameter(Position = 3, Mandatory = $false)]$ClearText
)
if ($ClearText) {
    $SecureText = ConvertTo-SecureString $ClearText -AsPlainText -Force
}
Clear-History; Clear-Host; $Error.Clear()
$CurrentFolder = Get-Location
Set-Variable -Name SystemPath -Value ($env:SystemRoot + "\System32")
Set-Location $SystemPath
Set-Variable -Name LocalAdmin -Value $null
Set-Variable -Name LocalAccounts -Value @()
Set-Variable -Name LocalServices -Value @()
Set-Variable -Name ListWebApps -Value @()
Set-Variable -Name AppPoolUser -Value $null
$PSVersion = $PSVersionTable.PSVersion
Write-Host ("Powershell version: " + $PSVersion)
switch (($PSVersion).Major) {
    {($_ -eq 5)} {
        $LocalAccounts += Get-LocalUser; Break
    }
    Default {
        $LocalAccounts += Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount = True"; Break
    }
}
foreach ($Account in $LocalAccounts) {
    if ($Account.SID -like "*-500") {
        $LocalAdmin = $Account.Name
    }
}
Set-Variable -Name Robocopy -Value ($SystemPath + "\Robocopy.exe")
Set-Variable -Name PShellPath -Value ($SystemPath + "\WindowsPowerShell\v1.0")
Set-Variable -Name LocalModules -Value ($PShellPath + "\Modules")
if (!(Test-Path ($LocalModules + "\ProcessCredentials"))) {
    New-Item -Path ($LocalModules + "\ProcessCredentials") -ItemType Directory | Out-Null
}
Set-Variable -Name SourceFolder -Value ($env:USERPROFILE + "\Downloads")
Set-Variable -Name FileName -Value "ProcessCredentials.psm1"
$SourceURL = ("https://github.com/bstobie/techops/releases/download/Secure-String/" + $FileName)
Set-Variable -Name Destination -Value ($SourceFolder + "\" + $FileName)
if (!(Test-Path -Path $Destination)) {
    try {
        Invoke-WebRequest -Uri $SourceURL -OutFile $Destination
    }
    catch {
        $Error.Clear()
    }
}
Set-Variable -Name ModuleSrc -Value ($SourceFolder)
Set-Variable -Name ModuleDes -Value ($LocalModules + "\ProcessCredentials")
Set-Variable -Name Options -Value ($FileName + " /R:1 /W:5")
$SrcFile = ($ModuleSrc + "\" + $FileName)
$DesFile = ($ModuleDes + "\" + $FileName)
if (!(Test-Path -Path $DesFile)) {
    Start-Process -FilePath $Robocopy -ArgumentList ($ModuleSrc + " " + $ModuleDes + " " + $Options) -WindowStyle Hidden -Wait
}
else {
    $Differences = Compare-Object -ReferenceObject (Get-Content -Path $SrcFile) -DifferenceObject (Get-Content -Path $DesFile)
    foreach ($Difference in $Differences) {
        if ($Difference.SideIndicator -eq "=>") {
            try {
                Start-Process -FilePath $Robocopy -ArgumentList ($ModuleSrc + " " + $ModuleDes + " " + $Options) -WindowStyle Hidden -Wait
                Break
            }
            catch {
                $Error.Clear()
            }
        }
    }
}
if (Test-Path -Path $SrcFile) {
    Remove-Item -Path $SrcFile -Force -ErrorAction SilentlyContinue | Out-Null
}
Import-Module ProcessCredentials
if ($SecureText) {
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureText)
    $ClearText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
}
$SvcAcctCreds = SetCredentials -SecureUser ("svc_lmdatacllctr@" + $LMDomain) -Domain $LMDomain -SecureString $ClearText
Remove-Variable -Name ClearText -Force -ErrorAction SilentlyContinue
if (!($SvcAcctCreds)) {$SvcAcctCreds = Get-Credential -Credential ("svc_lmdatacllctr@" + $LMDomain)}
$Session = New-PSSession -ComputerName $CompAcct -Credential $SvcAcctCreds
Set-Variable -Name SchTskTempFile -Value ("C:\Temp\SchTasks\SchTsk.csv")
if (!(Test-Path -Path (Split-Path -Path $SchTskTempFile))) {
    New-Item -Path (Split-Path -Path $SchTskTempFile) -ItemType Directory | Out-Null
}
$Script = {
    param ($SchTskTempFile)
    SchTasks.exe /query /V /FO CSV | Out-File $SchTskTempFile
}
try {
    Invoke-Command -Session $Session -ScriptBlock $Script -ArgumentList $SchTskTempFile
    $SchTaskList = Import-Csv -Path $SchTskTempFile
    foreach ($SchTask in $SchTaskList) {
        $SchTaskUser = ($SchTask.'Run As User')
        if ($SchTaskUser -eq $LocalAdmin) {
            $Message = ($SchTask.TaskName + " is using the 'Run As User': " + $SchTaskUser)
            try {
                Write-EventLog -LogName Application -Source "TechOps" -EventID 4673 -EntryType Error -Message $Message -Category 1 -RawData 10,20
            }
            catch {
                $Error.Clear()
            }
        }
    }
}
catch {
    $Error.Clear()
}
finally {
    Remove-Item -Path $SchTskTempFile -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
}
$WebApps = (Get-Module -ListAvailable webadmin*).Name
if ($WebApps) {
    Import-Module WebAdministration | Out-Null
}
if ([System.Diagnostics.EventLog]::SourceExists("TechOps") -eq $False) {
    try {
        New-EventLog -LogName Application -Source "TechOps"
    }
    catch {
        $Error.Clear()
    }
}
do {
    $AppPoolUser = ""
    if ($WebApps) {
        foreach ($WebApp in Get-ChildItem IIS:\AppPools) {
            $Name = ("IIS:\AppPools\" + $WebApp.Name)
            $Identity = $WebApp.processModel.IdentityType
            $AppPoolUser = $WebApp.processModel.userName
            if (!($AppPoolUser -eq "")) {
                $Message = ($Name + " is using the Identity Type: " + $Identity + " and username: " + $AppPoolUser)
                try {
                    Write-EventLog -LogName Application -Source "TechOps" -EventID 4673 -EntryType Error -Message $Message -Category 1 -RawData 10,20
                }
                catch {
                    $Error.Clear()
                }
            }
        }
    }
    $LocalServices = $null
    $LocalServices += Get-WmiObject Win32_Service -Filter ("Startname Like '%" + $LocalAdmin + "%'") | Select-Object Name, StartName
    if ($LocalServices) {
        $Message = ("Service name: " + $LocalServices.Name + " is using the Built-in account: " + $LocalAdmin)
        try {
            Write-EventLog -LogName Application -Source "TechOps" -EventID 4673 -EntryType Error -Message $Message -Category 1 -RawData 10,20
        }
        catch {
            $Error.Clear()
        }
    }
    else {
        Write-Host ("No errors found on " + ($env:COMPUTERNAME + "." + $env:USERDNSDOMAIN).ToLower())
        if ($AppPoolUser -eq "") {
            Break
        }
    }
    if ($TimeDelay -gt 0) {
        [float]$Delay = $TimeDelay * 60
        Start-Sleep -Seconds $Delay
    }
} while (($LocalServices) -and ($AppPoolUser -eq ""))
Set-Location $CurrentFolder
