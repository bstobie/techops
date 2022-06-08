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
    [parameter(Position = 1, Mandatory = $false)][string[]]$Ports = @(
        "445",
        "5985"
    ),
    [parameter(Position = 2, Mandatory = $false)][string[]]$LogFileNames = @(
        "MemberServers"
    )<#,
    [parameter(Position = 3, Mandatory = $false)][string[]]$DCPortList = @(
        "TCP, 53, Domain Name System",
        "TCP, 88, Kerberos",
        "TCP, 135, Microsoft End Point Mapper (RPC)",
        "TCP, 389, Lightweight Directory Access Protocol (LDAP)",
        "TCP, 445, Microsoft-DS (Directory Services) SMB",
        "TCP, 464, Kerberos Change/Set password",
        "TCP, 636, Lightweight Directory Access Protocol over TLS/SSL (LDAPS)",
        "TCP, 3268, Microsoft Global Catalog",
        "TCP, 3269, Microsoft Global Catalog over SSL",
        "TCP, 9389, Microsoft AD DS Web Services",
        "UDP, 53, Domain Name System",
        "UDP, 88, Kerberos",
        "UDP, 137, NetBIOS Name Service",
        "UDP, 138, NetBIOS Datagram Service",
        "UDP, 445, Microsoft-DS (Directory Services) Active Directory",
        "UDP, 464, Kerberos Change/Set password",
        "UDP, 500, Internet Security Association and Key Management Protocol (ISAKMP) / Internet Key Exchange (IKE)"
    )#>
)
$ListPSVars = Get-Variable -Exclude ("DomainList") | Select-Object -ExpandProperty Name
Import-Module -Name AdminTools
Import-Module -Name ActiveDirectory
Import-Module -Name ProcessCredentials
$EAPreference = "SilentlyContinue"
[string]$ScriptPath = Split-Path -Path ($MyInvocation.MyCommand.Definition)
[string]$ScriptName = $MyInvocation.MyCommand.Name
[string]$LogDate = Get-Date -Format "yyyy-MMdd"
[datetime]$StartTime = Get-Date -Format o
[string]$LogLocation = ($ScriptPath.Replace($ScriptName, "") + "\Logs\" + $ScriptName.Replace(".ps1", ""))
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
$ADFilter = ("OperatingSystem -like '*server*' -and Enabled -eq 'true' -and PasswordExpired -eq 'false'")
$Properties = ("Name", "IPv4Address", "DistinguishedName", "Operatingsystem", "PasswordLastSet", "whenChanged")
try {
    Clear-History; Clear-Host; $Error.Clear()
    Set-Variable -Name bIPv4Address -Value $false
    Set-Variable -Name bOnline -Value $false
    Set-Variable -Name iDefault -Value 0
    Set-Variable -Name iCount -Value 0
    $CurrentLocation = (Get-Location).Path
    Set-Location -Path $ScriptPath
    Set-Variable -Name ScrubList -Value ($ScriptPath + "\" + $ScriptName.Replace(".ps1", ""))
    foreach ($Domain in $DomainList) {
        $SvcAcctCreds, $DomainName = Get-SvcAcctName -DomainName $Domain -ErrorAction $EAPreference
        $DCList = Get-ADDomainController -Filter * -Server $DomainName -Credential $SvcAcctCreds | Select-Object -Property "Name"
        $PDC = ((Get-ADDomainController -Discover -Domain $DomainName -Service "PrimaryDC").Name + "." + $DomainName)
        $Message = ("Retrieving data from the [" + $PDC + "] domain controller . . .`r`n")
        $Message | Out-File -FilePath $LogFile -Append
        $MemberList = Get-ADComputer -Filter $ADFilter -Server $PDC -Credential $SvcAcctCreds -Properties $Properties |
            Sort-Object -Property "OperatingSystem", "Name" |
            Select-Object -Property $Properties
        foreach ($Member in $MemberList) {
            $Status = $null
            $byPass = $true
            $bOnline = $false
            $bIPv4Address = $false
            if (Test-Path -Path $ScrubList) {
                foreach ($ComputerList in Get-ChildItem -Path $ScrubList) {
                    if ($ComputerList.Extension -eq ".csv") {
                        $DeviceList = Import-Csv -Path $ComputerList.FullName
                        foreach ($Device in $DeviceList) {
                            if (($Member.Name).ToUpper() -eq ($Device.Hostname).ToUpper()) {
                                $byPass = $false
                                Break
                            }
                        }
                    }
                }
            }
            if (!($ByPass)) {
                $WhenChanged = @()
                $LastLoggedonDC = $null
                $DummyObject = New-Object -TypeName PSObject 
                if (($Member.IPv4Address)) {
                    [int]$iDCCount = 0
                    [string]$ReportingDate = $null
                    [datetime]$CompareDate = Get-Date -Format o
                    foreach ($DC in $DCList) {
                        if ($Member.Name -eq $DC.Name) {
                            $byPass = $true
                            Break
                        }
                    }
                    if ($byPass -eq $false) {
                        foreach ($DC in $DCList) {
                            $FqdnDC = ($DC.Name + "." + $Domain)
                            try {
                                $MemberName = Get-ADComputer -Identity $Member.Name -Server $FqdnDC -Credential $SvcAcctCreds -Properties $Properties |
                                    Sort-Object -Property "OperatingSystem", "Name" |
                                    Select-Object -Property $Properties
                                $WhenChanged += ($DummyObject | Select-Object @{
                                    L = "Date";         E = {$MemberName.whenChanged}}, @{
                                    L = "Controller";   E = {$FqdnDC}}
                                )
                            }
                            catch {
                                $Error.Clear()
                            }
                        }
                        Set-Variable -Name LastChanged -Value 0
                        foreach ($Date in $WhenChanged.Date) {
                            $DateDiff = (New-TimeSpan -Start $Date -End $CompareDate).Days
                            if ($LastChanged -eq 0) {
                                $ReportingDate = $Date
                                $LastChanged = $DateDiff
                                $LastLoggedonDC = $WhenChanged.Controller[$iDCCount]
                            }
                            elseif ($DateDiff -lt $LastChanged) {
                                $ReportingDate = $Date
                                $LastChanged = $DateDiff
                                $LastLoggedonDC = $WhenChanged.Controller[$iDCCount]
                            }
                            $iDCCount ++
                        }
                        $CurrentHost = Get-ADComputer -Identity $Member.Name -Server $LastLoggedonDC -Credential $SvcAcctCreds -Properties $Properties |
                            Sort-Object -Property "OperatingSystem", "Name" |
                            Select-Object -Property $Properties
                        switch ($CurrentHost.DistinguishedName) {
                            {$_ -like "*OU=Workspaces*"} {
                                $byPass = $true
                                Break
                            }
                            {$_ -like "*OU=ToBeDeleted*"} {
                                $byPass = $true
                                Break
                            }
                            {($_ -like "*CN=Computers*") -or ($_ -like "*OU=Landing Zone*")} {
                                $MemberName, $Status = Get-ServicePrincipalNames -ComputerName $CurrentHost.Name -ComputerDomain $DomainName
                                if ($MemberName -like ($CurrentHost.Name + "*")) {
                                    $Message = ("SPN: " + $MemberName + "`tWhen changed: " + $ReportingDate)
                                }
                                else {
                                    $Message = ("SPN: " + $MemberName + "`tWhen changed: " + $ReportingDate + " - CNAME: " + $CurrentHost.Name)
                                }
                                $Message | Out-File -FilePath $LogFile -Append
                                $Message = ("ERROR:`tIn the wrong OU: " + $CurrentHost.DistinguishedName)
                                $Message | Out-File -FilePath $LogFile -Append
                                $bIPv4Address = $true
                                $byPass = $true
                                $iDefault ++
                                Break
                            }
                            Default {
                                Break
                            }
                        }
                    }
                    if ($byPass -eq $false) {
                        $MemberName, $Status = Get-ServicePrincipalNames -ComputerName $CurrentHost.Name -ComputerDomain $DomainName
                        if ($Status -eq "Resolved") {
                            if ($MemberName -like ($CurrentHost.Name + "*")) {
                                $Message = ("SPN: " + $MemberName + "`tWhen changed: " + $ReportingDate)
                            }
                            else {
                                $Message = ("SPN: " + $MemberName + "`tWhen changed: " + $ReportingDate + " - CNAME: " + $CurrentHost.Name)
                            }
                            $Message | Out-File -FilePath $LogFile -Append
                            $bIPv4Address = $true
                        }
                        if ($bIPv4Address) {
                            $bOnline = Test-Connection -ComputerName $MemberName -ErrorAction $EAPreference
                            if ($bOnline) {
                                Set-Variable -Name MSG -Value "WARNING"
                                $HostDomain = ($MemberName.SubString($MemberName.indexof(".") + 1)).ToLower()
                                $SvcAcctCreds, $DomainName = Get-SvcAcctName -DomainName $HostDomain
                                $OSName = $Member.OperatingSystem
                                foreach ($Port in $Ports) {
                                    $Status = "unknown"
                                    $Results = Get-PortCheck -HostFQDN $MemberName -PortNumber $Port -OSName $OSName
                                    switch ($Results) {
                                        0 {
                                            $MSG = "INFO"
                                            $Status = "passed"
                                            Break
                                        }
                                        Default {
                                            $MSG = "ERROR"
                                            $Status = "failed"
                                            Break
                                        }
                                    }
                                    $Message = ("`t" + $MSG + ":`tThe port check on [" + $MemberName + "] " + $Status + " for port: " + $Port + ".")
                                    $Message | Out-File -FilePath $LogFile -Append
                                }
                                $iCount ++
                            }
                            else {
                                $Message = ("`tWARNING:`tServer: [" + $MemberName + "] is not currently accessible over the network.")
                                $Message | Out-File -FilePath $LogFile -Append
                            }
                            $Message = ("`n")
                            $Message | Out-File -FilePath $LogFile -Append
                        }
                    }
                }
            }
            $Error.clear()
        }
    }
}
catch {
    $Error.clear()
}
finally {
    $Message = ("`r`n Server count: `t " + $iCount + " `r`n")
    $Message | Out-File -FilePath $LogFile -Append
    $Message = ("`n In the Computers container: `t " + $iDefault + " `r`n")
    $Message | Out-File -FilePath $LogFile -Append
    Set-Location -Path $CurrentLocation
    $AddListPSVars = @(
        "EAPreference"
    )
    foreach ($AddVar in $AddListPSVars) {
        $ListPSVars += $AddVar
    }
    Get-Variable * | Remove-Variable -Exclude $ListPSVars -Force -ErrorAction $EAPreference
}