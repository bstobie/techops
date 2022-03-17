[CmdletBinding()]
param (
    [parameter(Position = 0, Mandatory = $false)][string[]]$LogFileNames = @("BuiltInAdmin")
)
function Get-AdminAccount {
    param (
        [parameter(Position = 0, Mandatory = $true)][string]$DomainName
    )
    $GN = ((Get-ADUser -Identity $env:USERNAME).GivenName).ToLower()
    $SN = (Get-ADUser -Identity $env:USERNAME).Surname
    Set-Variable -Name ShortName -Value $null
    if ($GN -like "admin*") {
        $GN = ($GN.Replace("admin", ""))
    }
    $GN = ($GN.Trim()).Substring(0, 1).ToUpper() + (($GN.Replace("admin", "")).Trim()).Substring(1)
    [string]$FullName = ($GN + "." + $SN)
    [string]$UserName = (($GN[0]) + $SN)
    [string]$TrimName = ($UserName).Substring(0,5)
    if ($DomainName -like "*.*") {
        $DomainName = $DomainName.ToLower()
    }
    else {
        $DomainName = $DomainName.ToUpper()
    }
    switch ($DomainName.ToLower()) {
        {($_ -eq "1stglobal.com") -or ($_ -eq "1STGLOBAL")} {$ServerAdmin = ("a_" + $UserName).ToLower();       $DomainName = "1stglobal.com";  Break}
        {($_ -eq "bcor.ad") -or ($_ -eq "BCOR")}            {$ServerAdmin = ($UserName + "x").ToLower();        $DomainName = "bcor.ad";        Break}
        {($_ -eq "bcor.it") -or ($_ -eq "BCORIT")}          {$ServerAdmin = ("admin_" + $TrimName).ToLower();   $DomainName = "bcor.it";        Break}
        {($_ -eq "corpid.net") -or ($_ -eq "CORPID")}       {$ServerAdmin = ("DA-" + $FullName).ToLower();      $DomainName = "corpid.net";     Break}
        {($_ -eq "hdv.corp") -or ($_ -eq "HDVCORP")}        {$ServerAdmin = ($UserName + "x").ToLower();        $DomainName = "hdv.corp";       Break}
        {($_ -eq "taxact.com") -or ($_ -eq "TAXACT")}       {$ServerAdmin = ("admin_" + $TrimName).ToLower();   $DomainName = "taxact.com";     Break}
        default {
            $ServerAdmin = ("admin_" + $TrimName).ToLower()
            $DomainName = "irv.hdv.corp"
            Break
        }
    }
    return $ServerAdmin, $DomainName
}
function Get-BuiltinAdminAccount {
    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $true)][string]$ComputerName,
        [parameter(Position = 1, Mandatory = $true)][string]$ComputerDomain,
        [parameter(Position = 2, Mandatory = $true)][string]$ScriptFile
    )
    Import-Module ProcessCredentials
    $ServerAdmin, $AdminDomain = (Get-AdminAccount -DomainName $ComputerDomain)
    $AdminCreds = SetCredentials -SecureUser ($ServerAdmin + "@" + $AdminDomain) -Domain $AdminDomain
    if (!($AdminCreds)) {
        $AdminCreds = Get-Credential -Credential ($ServerAdmin + "@" + $AdminDomain) -ErrorAction $EAPreference
    }
    Set-Variable -Name HostFQDN -Value $null
    if (!($ComputerName -like ("*.*"))) {
        $HostFQDN = ($ComputerName + "." + $ComputerDomain)
    }
    else {
        $HostFQDN = $ComputerName
    }
    $BiosName = ($HostFQDN).Split(".")[0]
    $RemoteShare = ("\\" + $HostFQDN + "\C$")
    $FileName = Split-Path -Leaf $ScriptFile
    Set-Variable -Name ExitCode -Value $null
    try {
        $PSDrvName = (New-PSDrive -Name ($BiosName) -PSProvider "FileSystem" -Root $RemoteShare -Credential $AdminCreds)
        Copy-Item -Path $ScriptFile -Destination ($PSDrvName.Name + ":") -Force | Out-Null
        if (Test-Path -Path ($PSDrvName.Name + ":\" + $FileName)) {
            try {
                $RemoteSession = New-PSSession -ComputerName $HostFQDN -Credential $AdminCreds -ErrorAction $EAPreference
                $ExitCode = Invoke-Command -Session $RemoteSession -ScriptBlock {
                    param ($FileName)
                    Start-Process -FilePath "PowerShell.exe" -ArgumentList ("C:\" + $FileName)
                } -ArgumentList $FileName
            }
            catch {
                $Error.Clear()
                return 1
            }
        }
        else {
            return 573
        }
        Remove-PSDrive -Name $PSDrvName
        switch ($ExitCode) {
            0 {
                return 0
            }
            Default {
                return $_
            }
        }
    }
    catch {
        $Error.Clear()
        return 6021
    }
}
function Get-HostDomain {
    param (
        [parameter(Position = 0, Mandatory = $true)][string]$DomainName
    )
    switch ($DomainName) {
        {($_ -eq "1STGLOBAL")}  {$DomainName = "1stglobal.com";     Break}
        {($_ -eq "BCOR")}       {$DomainName = "bcor.ad";           Break}
        {($_ -eq "BCORIT")}     {$DomainName = "bcor.it";           Break}
        {($_ -eq "COLO")}       {$DomainName = "colo.ext.hdv.corp"; Break}
        {($_ -eq "CORPID")}     {$DomainName = "corpid.net";        Break}
        {($_ -eq "HDV")}        {$DomainName = "hdvest.com";        Break}
        {($_ -eq "HDVCORP")}    {$DomainName = "hdv.corp";          Break}
        {($_ -eq "HDVEXT")}     {$DomainName = "ext.hdv.corp";      Break}
        {($_ -eq "IRV")}        {$DomainName = "irv.hdv.corp";      Break}
        {($_ -eq "TAXACT")}     {$DomainName = "taxact.com";        Break}
    }
    return $DomainName
}
$Error.Clear(); Clear-History; Clear-Host
[datetime]$StartTime = Get-Date -Format o
$EAPreference = "SilentlyContinue"
try {
    Set-Variable -Name SystemRoot -Value ($env:SystemRoot + "\System32")
    Set-Variable -Name PriorLocation -Value (Get-Location)
    Set-Location -Path $SystemRoot
    $ScriptName = $MyInvocation.MyCommand.Name
    $ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
    [string]$LogLocation = ($ScriptPath + "\Logs\" + $ScriptName.Replace(".ps1", ""))
    [string]$LogDate = Get-Date -Format "yyyy-MMdd"
    [string[]]$Global:LogFiles = @()
    foreach ($LogFile in $LogFileNames) {
        if (Get-Variable -Name $LogFile -ErrorAction $EAPreference){
            Remove-Variable -Name LogFile
        }
        New-Variable -Name "$($LogFile)" -Value ([string]($LogLocation + "\" + $LogFile + "_" + $LogDate + ".log"))
        $LogFiles += (Get-Variable -Name "$($LogFile)").Value
    }
    [int]$LogCount = 0
    foreach ($LogFile in $LogFiles) {
        if (!(Test-Path -Path $LogLocation)) {
            New-Item -Path $LogLocation -ItemType Directory | Out-Null
        }
        $FileName = (Split-Path -Path $LogFile -Leaf).Replace(".log", "")
        $Files = Get-Item -Path ($LogLocation + "\*.*")
        [int]$FileCount = 0
        foreach($File in $Files) {
            if (!($File.Mode -eq "d----") -and ($File.Name -like ($FileName + "*"))) {
                $FileCount ++
            }
        }
        if (($FileCount -gt 0) -and $LogCount -eq 0) {
            $NewLogFile = ($FileName + "(" + $FileCount + ").log")
            ("Changing the name of this log [" + $FileName + "] to [" + $NewLogFile + "].") | Out-File -FilePath $LogFiles[0] -Append
            Rename-Item -Path $LogFile -NewName $NewLogFile
        }
        ("Starting a new log [" + $FileName + "] at [" + $StartTime + "].`r") | Out-File -FilePath $LogFiles[$LogCount]
        $LogCount ++
    }
    $Message = ("Starting to process device collections for systems running services with the Built-In Admin account.`r")
    $Message | Out-File -FilePath $LogFiles[0] -Append
    Set-Variable -Name CollectionPath -Value ($ScriptPath + "\Thycotic")
    if (Test-Path -Path $CollectionPath) {
        foreach ($DeviceCollection in Get-ChildItem -Path $CollectionPath) {
            if ($DeviceCollection.Extension -eq ".csv") {
                $Message = ("Beginning to process device collections " + $DeviceCollection.FullName + ".`r")
                $Message | Out-File -FilePath $LogFiles[0] -Append
                $Devices = Import-Csv -Path $DeviceCollection.FullName
                foreach ($Device in $Devices) {
                    $HostDomain = Get-HostDomain -DomainName $Device.'Domain Name'
                    $HostFQDN = ($Device.'Computer Name' + "." + $HostDomain)
                    $Message = ("Processing hostname: [" + $HostFQDN + "]")
                    $Message | Out-File -FilePath $LogFiles[0] -Append
                    $Results = Test-NetConnection -ComputerName $HostFQDN
                    if ($Results.PingSucceeded) {
                        $Message = ("Successfully pinged hostname: [" + $HostFQDN + "]")
                        $Message | Out-File -FilePath $LogFiles[0] -Append
                        $FileName = "IdPriviledgedUsage.ps1"
                        $ScriptFile = ($ScriptPath + "\" + $FileName)
                        $Message = ("Attempting to remotely connect to hostname: [" + $HostFQDN + "]")
                        $Message | Out-File -FilePath $LogFiles[0] -Append
                        $Results = Get-BuiltinAdminAccount -ComputerName $HostFQDN -ComputerDomain $HostDomain -ScriptFile $ScriptFile
                        switch ($Results) {
                            0 {
                                $Message = ("Successfully started: '" + $FileName + "' on hostname: [" + $HostFQDN + "]`r`n")
                                $Message | Out-File -FilePath $LogFiles[0] -Append
                                Break
                            }
                            573 {
                                $Message = ("WARNING:`tFailed to copy '" + $FileName + "' to hostname: [" + $HostFQDN + "]`r`n")
                                $Message | Out-File -FilePath $LogFiles[0] -Append
                                Break
                            }
                            6021 {
                                $Message = ("WARNING:`tThe SMB client is not accessible on hostname: [" + $HostFQDN + "]`r`n")
                                $Message | Out-File -FilePath $LogFiles[0] -Append
                                Break
                            }
                            default {
                                $Message = ("ERROR:`tFailed to run script: '" + $FileName + "' on hostname: [" + $HostFQDN + "].  ErrorCode: " + $Results + "`r`n")
                                $Message | Out-File -FilePath $LogFiles[0] -Append
                                Break
                            }
                        }
                    }
                    else {
                        $Message = ("WARNING:`tNot able to ping hostname: [" + $HostFQDN + "]`r")
                        $Message | Out-File -FilePath $LogFiles[0] -Append
                    }
                }
            }
        }
        return 0
    }
    else {
        return 2
    }
}
catch {
    $Error.Clear()
    return 1
}
finally {
    Set-Location -Path ($PriorLocation)
}