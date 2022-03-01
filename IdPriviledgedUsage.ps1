[CmdletBinding()]
param (
    [parameter(Position = 0, Mandatory = $false)][string]$DNSDomain = ($env:USERDNSDOMAIN).ToLower(),
    [Parameter(Position = 1, Mandatory = $false)][string]$CompAcct = "localhost",
    [parameter(Position = 2, Mandatory = $false)][string[]]$LogFileNames = @("Thycotic"),
    [Parameter(Position = 3, Mandatory = $false)][decimal]$TimeDelay = 1,
    [Parameter(Position = 4, Mandatory = $false)]$ClearText
)
function Test-ADAuthentication {
    param (
        $UserName,
        $SecureString
    )
    $BSTR=[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    $UnEncrypted=[System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    $null -ne (New-Object System.DirectoryServices.DirectoryEntry "", $UserName, $UnEncrypted).psbase.name
    Remove-Variable -Name UnEncrypted -Force -ErrorAction SilentlyContinue
}
if ($ClearText) {
    $SecureString = ConvertTo-SecureString $ClearText -AsPlainText -Force
    Remove-Variable -Name ClearText -Force -ErrorAction SilentlyContinue | Out-Null
}
$ListPSVars = Get-Variable -Exclude ("DNSDomain", "CompAcct", "LogFileNames", "TimeDelay", "ClearText", "SecureString") | Select-Object -ExpandProperty Name
[datetime]$StartTime = Get-Date -Format o
Clear-History; Clear-Host; $Error.Clear()
$EAPreference = "SilentlyContinue"
try {
    $ScriptName = $MyInvocation.MyCommand.Name
    $ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
    [string]$LogLocation = ($ScriptPath + "\Logs\" + $ScriptName.Replace(".ps1", ""))
    [string]$LogDate = Get-Date -Format "yyyy-MMdd"
    [string[]]$Global:LogFiles = @()
    foreach ($LogFile in $LogFileNames) {
        if (Get-Variable -Name $LogFile -ErrorAction $EAPreference){
            Remove-Variable -Name LogFile
        }
        New-Variable -Name "$($LogFile)" -Value ([string]($LogLocation + "\" + $LogFile + "_" +  $LogDate + ".log"))
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
        ("Starting a new log [" + $FileName + "] at [" + $StartTime + "].") | Out-File -FilePath $LogFiles[$LogCount]
        $LogCount ++
    }
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
            $Message = ("'" + $LocalAdmin + "' is the 'Built-In Administrator' account for " + $CompAcct + ".")
            $Message | Out-File -FilePath $LogFiles[0] -Append
            Break
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
            $Message = ("Downloaded the latest release of: '" + $FileName + "' to: [" + $Destination + "].")
            $Message | Out-File -FilePath $LogFiles[0] -Append
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
            if ($Difference.SideIndicator -eq " = >") {
                try {
                    Start-Process -FilePath $Robocopy -ArgumentList ($ModuleSrc + " " + $ModuleDes + " " + $Options) -WindowStyle Hidden -Wait
                    $Message = ("Copied '" + $FileName + "' from: [" + $Destination + "] to [" + $ModuleDes + "].")
                    $Message | Out-File -FilePath $LogFiles[0] -Append
                    Break
                }
                catch {
                    $Error.Clear()
                }
            }
        }
    }
    Import-Module ProcessCredentials
    $SvcAcctCreds = SetCredentials -SecureUser ("svc_medtc@" + $DNSDomain) -Domain $DNSDomain -SecureString $SecureString
    if (!($SvcAcctCreds)) {$SvcAcctCreds = Get-Credential -Credential ("svc_medtc@" + $DNSDomain)}
    $Message = ("Testing the ability of service account: '" + $SvcAcctCreds.UserName + "' to connect to [" + $DNSDomain + "].")
    $Message | Out-File -FilePath $LogFiles[0] -Append
    if (Test-ADAuthentication -UserName $SvcAcctCreds.UserName -SecureString $SvcAcctCreds.Password) {
        $Message = ("Successfully connected to [" + $DNSDomain + "] using '" + $SvcAcctCreds.UserName + "'.")
        $Message | Out-File -FilePath $LogFiles[0] -Append
        $Message = ("Attempting to connect using 'New-PSSession' to '" + $CompAcct + "'.")
        $Message | Out-File -FilePath $LogFiles[0] -Append
        try {
            $Message = ("Successfully connected to [" + $CompAcct + "] using 'New-PSSession'.")
            $Message | Out-File -FilePath $LogFiles[0] -Append
            $Session = New-PSSession -ComputerName $CompAcct -Credential $SvcAcctCreds
            Set-Variable -Name SchTskTempFile -Value ("C:\Temp\SchTsk.csv")
            if (!(Test-Path -Path (Split-Path -Path $SchTskTempFile))) {
                New-Item -Path (Split-Path -Path $SchTskTempFile) -ItemType Directory | Out-Null
            }
            $Script = {
                param ($SchTskTempFile)
                SchTasks.exe /query /V /FO CSV | Out-File $SchTskTempFile
            }
        }
        catch {
            $Message = ("Failed to connect using 'New-PSSession' on '" + $CompAcct + "' with " + $Error.message + " error message.")
            $Message | Out-File -FilePath $LogFiles[0] -Append
            $Error.Clear()                
        }
        try {
            $Message = ("Attempting to retrieve 'Task Scheduler' configuration data and export it to [" + $SchTskTempFile + "].")
            $Message | Out-File -FilePath $LogFiles[0] -Append
            Invoke-Command -Session $Session -ScriptBlock $Script -ArgumentList $SchTskTempFile
            $SchTaskList = Import-Csv -Path $SchTskTempFile
            foreach ($SchTask in $SchTaskList) {
                $SchTaskUser = ($SchTask.'Run As User')
                if ($SchTaskUser -eq $LocalAdmin) {
                    $Message = ($SchTask.TaskName + " is using the 'Run As User': " + $SchTaskUser)
                    $Message | Out-File -FilePath $LogFiles[0] -Append
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
            $Message = ("Failed to connect to 'Task Scheduler' on '" + $CompAcct + "' with " + $Error.message + " error message.")
            $Message | Out-File -FilePath $LogFiles[0] -Append
            $Error.Clear()
        }
        finally {
            Remove-Item -Path $SchTskTempFile -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
            $Message = ("Removed the temporary 'Task Scheduler' log file from [" + $SchTskTempFile + "].")
            $Message | Out-File -FilePath $LogFiles[0] -Append
        }
        $WebApps = (Get-Module -ListAvailable webadmin*).Name
        if ($WebApps) {
            Import-Module WebAdministration | Out-Null
            $Message = ("Imported the Web Administration module for PowerShell.")
            $Message | Out-File -FilePath $LogFiles[0] -Append
        }
        if ([System.Diagnostics.EventLog]::SourceExists("TechOps") -eq $False) {
            try {
                New-EventLog -LogName Application -Source "TechOps"
                $Message = ("Created new Application event log source object 'TechOps'.")
                $Message | Out-File -FilePath $LogFiles[0] -Append
                }
            catch {
                $Message = ("Failed to created new Application event log source object 'TechOps' with " + $Error.message + " error message.")
                $Message | Out-File -FilePath $LogFiles[0] -Append
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
                        $Message | Out-File -FilePath $LogFiles[0] -Append
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
                $Message | Out-File -FilePath $LogFiles[0] -Append
                try {
                    Write-EventLog -LogName Application -Source "TechOps" -EventID 4673 -EntryType Error -Message $Message -Category 1 -RawData 10,20
                }
                catch {
                    $Error.Clear()
                }
            }
            else {
                $Message = ("No errors found on " + ($env:COMPUTERNAME + "." + $env:USERDNSDOMAIN).ToLower())
                $Message | Out-File -FilePath $LogFiles[0] -Append
                Write-Host $Message
                if ($AppPoolUser -eq "") {
                    Break
                }
            }
            if ($TimeDelay -gt 0) {
                [float]$Delay = $TimeDelay * 60
                Start-Sleep -Seconds $Delay
            }
        } while (($LocalServices) -and ($AppPoolUser -eq ""))
    }
}
catch {
    $Error.Clear(); Clear-History; Clear-Host
}
finally {
    Set-Location $CurrentFolder
    $AddListPSVars = @(
        "MaximumHistoryCount", "NestedPromptLevel", "OutputEncoding", "profile", "ProgressPreference", "PSCulture",
        "PSDefaultParameterValues", "psEditor", "PSEmailServer", "PSSessionApplicationName", "PSSessionConfigurationName",
        "PSSessionOptions", "PSUICulture", "PWD", "StackTrace", "VerbosePreference", "WarningPreference", "WhatIfPreference"
    )
    foreach ($AddVar in $AddListPSVars) {
        $ListPSVars += $AddVar
    }
    Get-Variable * | Remove-Variable -Exclude $ListPSVars -Force -ErrorAction SilentlyContinue
}
