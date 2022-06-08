[CmdletBinding()]
param (
    [parameter(Position = 0, Mandatory = $false)][string[]]$DomainList = @(
        "1stglobal.com",
        "bcor.ad",
        "bcor.it",
        "colo.ext.hdv.corp",
        "corpid.net",
        "ext.hdv.corp",
        "hdv.corp",
        "hdvest.com",
        "irv.hdv.corp"
    ),
    [parameter(Position = 1, Mandatory = $false)][string[]]$LogFileNames = @("ActiveServers")
)
Import-Module -Name AdminTools
Import-Module -Name ActiveDirectory
Import-Module -Name ProcessCredentials
$EAPreference = "SilentlyContinue"
[string]$ScriptPath = Split-Path -Path ($MyInvocation.MyCommand.Definition)
[string]$ScriptName = $MyInvocation.MyCommand.Name
[string]$LogDate = Get-Date -Format "yyyy-MMdd"
[datetime]$StartTime = Get-Date -Format o
[string]$LogLocation = ($ScriptPath.Replace($ScriptName, "") + "\Logs\" + $ScriptName.Replace(".ps1", ""))
$ADFilter = 'OperatingSystem -like "*server*" -and Enabled -eq "true" -and PasswordExpired -eq "false"'
$Properties = ("SID", "Name", "IPv4Address", "DistinguishedName", "Operatingsystem", "PasswordLastSet", "whenChanged")
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
        ("Changing the name of this log [" + $FileName + "] to [" + $NewLogFile + "].") | Out-File -FilePath $LogFile -Append
        Rename-Item -Path $LogFile -NewName $NewLogFile
    }
    ("Starting a new log [" + $FileName + "] at [" + $StartTime + "].") | Out-File -FilePath $LogFile
    $LogCount ++
}
$Error.Clear(); Clear-History; Clear-Host
foreach ($Domain in $DomainList) {
    [int]$iMemberCount = 0
    [int]$i2000 = 0
    [int]$i2003 = 0
    [int]$i2008 = 0
    [int]$i2012 = 0
    [int]$i2016 = 0
    [int]$i2019 = 0
    [int]$i2022 = 0
    $SvcAcctCreds, $DomainName = Get-SvcAcctName -DomainName $Domain -ErrorAction $EAPreference
    $DCList = Get-ADDomainController -Filter * -Server $DomainName -Credential $SvcAcctCreds | Select-Object -Property "Name"
    $PDC = ((Get-ADDomainController -Discover -Domain $DomainName -Service "PrimaryDC").Name + "." + $DomainName)
    $Message = ("Retrieving data from the [" + $PDC + "] domain controller ...`r`n")
    $Message | Out-File -FilePath $LogFile -Append
    $MemberList = Get-ADComputer -Filter $ADFilter -Server $PDC -Credential $SvcAcctCreds -Properties $Properties |
        Sort-Object -Property "OperatingSystem", "Name" |
        Select-Object -Property $Properties
    $Message = ("SID `tHostname `tDomain `tOperatingSystem `tIPv4Address `tDays `twhenChanged")
    $Message | Out-File -FilePath $LogFile -Append
    try {
        foreach ($Member in $MemberList) {
            [int]$iDCCount = 0
            [int]$LastChanged = 0
            [string]$ChangeDate = $null
            [string]$IPv4Address = ""
            [datetime]$CompareDate = Get-Date -Format o
            Set-Variable -Name WhenChanged -Value @()
            Set-Variable -Name MemberName -Value @()
            foreach ($DC in $DCList) {
                $FqdnDC = ($DC.Name + "." + $Domain)
                $CurrentHost = Get-ADComputer -Identity $Member.SID -Server $FqdnDC -Credential $SvcAcctCreds -Properties $Properties |
                    Sort-Object -Property "OperatingSystem", "Name" |
                    Select-Object -Property $Properties
                $WhenChanged += $CurrentHost.whenChanged
            }
            foreach ($Date in $WhenChanged) {
                $DateDiff = (New-TimeSpan -Start $Date -End $CompareDate).Days
                if ($LastChanged -eq 0) {
                    $ChangeDate = $WhenChanged[$iDCCount]
                    $LastChanged = $DateDiff
                }
                elseif ($DateDiff -lt $LastChanged) {
                    $ChangeDate = $WhenChanged[$iDCCount]
                    $LastChanged = $DateDiff
                }
                $iDCCount ++
            }
            if ($Member.IPv4Address) {
                $IPv4Address = $Member.IPv4Address
            }
            else {
                $IPv4Address = "[N/A]"
            }
            switch ($Member.OperatingSystem) {
                {$_ -like "*2000*"} {
                    $i2000 ++
                    Break
                }
                {$_ -like "*2003*"} {
                    $i2003 ++
                    Break
                }
                {$_ -like "*2008*"} {
                    $i2008 ++
                    Break
                }
                {$_ -like "*2012*"} {
                    $i2012 ++
                    Break
                }
                {$_ -like "*2016*"} {
                    $i2016 ++
                    Break
                }
                {$_ -like "*2019*"} {
                    $i2019 ++
                    Break
                }
                {$_ -like "*2022*"} {
                    $i2022 ++
                    Break
                }
            }
            $Message = (($Member.SID).Value + "`t" + $Member.Name + "`t" + $Domain + "`t" + $Member.OperatingSystem + "`t" + $IPv4Address + "`t" + $LastChanged + "`t" + $ChangeDate)
            $Message | Out-File -FilePath $LogFile -Append
            Start-Sleep -Milliseconds 50
            $iMemberCount ++
        }
    }
    catch {
        $Error.Clear()
    }
    finally {
        $Message = ("`tTotal server count: " + $iMemberCount)
        $Message | Out-File -FilePath $LogFile -Append
        $Message = ("2000 [" + $i2000 + "] `t2003 [" + $i2003 + "] `t2008 [" + $i2008 + "] `t2012 [" + $i2012 + "] `t2016 [" + $i2016 + "] `t2019 [" + $i2019 + "] `t2022 [" + $i2022 + "]")
        $Message | Out-File -FilePath $LogFile -Append
    }
}