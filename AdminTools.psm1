Import-Module -Name ProcessCredentials
function Get-AdminUserName {
    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $true)][string]$DomainName,
        [parameter(Position = 1, Mandatory = $false)][bool]$bShortName = $false
    )
    $GN = ((Get-ADUser -Identity $env:USERNAME).GivenName).ToLower()
    $SN = (Get-ADUser -Identity $env:USERNAME).Surname
    if ($GN -like "admin*") {
        $GN = ($GN.Replace("admin", ""))
    }
    $GN = ($GN.Trim()).Substring(0, 1).ToUpper() + (($GN.Replace("admin", "")).Trim()).Substring(1)
    [string]$FullName = ($GN + "." + $SN)
    [string]$UserName = (($GN[0]) + $SN)
    [string]$TrimName = ($UserName).Substring(0,5)
    switch ($DomainName) {
        {($_ -eq "1STGLOBAL") -or ($_ -eq "1stglobal.com")} {
            $ServerAdmin = ("a_" + $UserName).ToLower()
            $DomainSN = "1STGLOBAL"
            $DomainName = "1stglobal.com"
            Break
        }
        {($_ -eq "BCOR") -or ($_ -eq "bcor.ad")} {
            $ServerAdmin = ($UserName + "x").ToLower()
            $DomainSN = "BCOR"
            $DomainName = "bcor.ad"
            Break
        }
        {($_ -eq "BCORIT") -or ($_ -eq "bcor.it")} {
            $ServerAdmin = ("admin_" + $TrimName).ToLower()
            $DomainSN = "BCORIT"
            $DomainName = "bcor.it"
            Break
        }
        {($_ -eq "CORPID") -or ($_ -eq "corpid.net")} {
            $ServerAdmin = ("SA-" + $FullName).ToLower()
            $DomainSN = "CORPID"
            $DomainName = "corpid.net"
            Break
        }
        {($_ -eq "HDV") -or ($_ -eq "hdvest.com")} {
            $ServerAdmin = ("admin_" + $TrimName).ToLower()
            $DomainSN = "HDV"
            $DomainName = "hdvest.com"
            Break
        }
        {($_ -eq "HDVCORP") -or ($_ -eq "hdv.corp")} {
            $ServerAdmin = ($UserName + "x").ToLower()
            $DomainSN = "HDVCORP"
            $DomainName = "hdv.corp"
            Break
        }
        {($_ -eq "TAXACT") -or ($_ -eq "taxact.com")} {
            $ServerAdmin = ("admin_" + $TrimName).ToLower()
            $DomainSN = "TAXACT"
            $DomainName = "taxact.com"
            Break
        }
        default {
            $ServerAdmin = ("admin_" + $TrimName).ToLower()
            $DomainName = "irv.hdv.corp"
            $DomainSN = "IRV"
            Break
        }
    }
    $iCount = 0
    $bReset = $false
    do {
        if ($iCount -eq 1) {
            $bReset = $true
        }
        $AdminSecret = Set-Credentials -SecureUser ($ServerAdmin + "@" + $DomainName) -Domain $DomainName -ResetPassword $bReset
        if (!($AdminSecret)) {
            $AdminSecret = Get-Credential -Credential ($ServerAdmin + "@" + $DomainName) -ErrorAction $EAPreference
        }
        $iCount ++
    } until (Test-ADAuthentication -UserName $AdminSecret.UserName -SecureString $AdminSecret.Password)
    if ($bShortName) {
        return $AdminSecret, $DomainSN
    }
    else {
        return $AdminSecret, $DomainName
    }
}
function Get-ClearString {
    [CmdletBinding()]
    param (
        $UserName,
        $SecureString
    )
    $BSTR=[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    $UnEncrypted=[System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    return $UserName, $UnEncrypted
}
function Get-ComputerInfo {
    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $true)]$MemberData,
        [parameter(Position = 1, Mandatory = $false)][string[]]$Properties = @(
            "Name",
            "IPv4Address",
            "DistinguishedName",
            "Operatingsystem",
            "Enabled",
            "PasswordExpired",
            "PasswordLastSet",
            "whenChanged"
        ),
        [parameter(Position = 2, Mandatory = $true)]$SvcAcctInfo,
        [parameter(Position = 3, Mandatory = $true)]$DomainName,
        [parameter(Position = 4, Mandatory = $true)]$DCList,
        [parameter(Position = 5, Mandatory = $true)]$LogFile
    )
    $Status = $null
    $byPass = $false
    $bOnline = $false
    $bIPv4Address = $false
    Set-Variable -Name EAPreference -Value "SilentlyContinue"
    if (($MemberData.IPv4Address)) {
        [int]$iDCCount = 0
        [string]$ReportingDate = $null
        [datetime]$CompareDate = Get-Date -Format o
        Set-Variable -Name WhenChanged -Value @()
        foreach ($DC in $DCList) {
            if ($MemberData.Name -eq $DC.Name) {
                $byPass = $true
                Break
            }
        }
        if ($byPass -eq $false) {
            foreach ($DC in $DCList) {
                $FqdnDC = ($DC.Name + "." + $DomainName)
                try {
                    $CurrentHost = Get-ADComputer -Identity $MemberData.Name -Server $FqdnDC -Credential $SvcAcctInfo -Properties $Properties |
                        Sort-Object -Property "OperatingSystem", "Name" |
                        Select-Object -Property $Properties
                    $WhenChanged += $CurrentHost.whenChanged
                }
                catch {
                    $Error.Clear()
                }
            }
            Set-Variable -Name LastChanged -Value 0
            foreach ($Date in $WhenChanged) {
                $DateDiff = (New-TimeSpan -Start $Date -End $CompareDate).Days
                if ($LastChanged -eq 0) {
                    $ReportingDate = $WhenChanged[$iDCCount]
                    $LastChanged = $DateDiff
                }
                elseif ($DateDiff -lt $LastChanged) {
                    $ReportingDate = $WhenChanged[$iDCCount]
                    $LastChanged = $DateDiff
                }
                $iDCCount ++
            }
        }
        switch ($MemberData.DistinguishedName) {
            {$_ -like "*OU=Workspaces*"} {
                $byPass = $true
                Break
            }
            {$_ -like "*OU=ToBeDeleted*"} {
                $byPass = $true
                Break
            }
            {($_ -like "*CN=Computers*") -or ($_ -like "*OU=Landing Zone*")} {
                $MemberName, $Status = Get-ServicePrincipalNames -ComputerName $MemberData.Name -ComputerDomain $DomainName
                $Message = ($MemberName + "`tWhen changed: " + $ReportingDate)
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
        if ($byPass -eq $false) {
            $MemberName, $Status = Get-ServicePrincipalNames -ComputerName $MemberData.Name -ComputerDomain $DomainName
            if ($Status -eq "Resolved") {
                $Message = ($MemberName + "`tWhen changed: " + $ReportingDate)
                $Message | Out-File -FilePath $LogFile -Append
                $bIPv4Address = $true
            }
        }
        if ($bIPv4Address) {
            $bOnline = Test-Connection -ComputerName $MemberName -ErrorAction $EAPreference
            if ($bOnline) {
                Set-Variable -Name MSG -Value "WARNING"
                $HostDomain = ($MemberName.SubString($MemberName.indexof(".") + 1)).ToLower()
                $SvcAcctCreds, $DomainName = Get-SvcAcctName -DomainName $HostDomain
                $OSName = $MemberData.OperatingSystem
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
function Get-HostDomain {
    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $true)][string]$DomainName
    )
    switch ($DomainName) {
        {($_ -eq "1STGLOBAL") -or ($_ -eq "1stglobal.com")} {$DomainName = "1stglobal.com";     Break}
        {($_ -eq "BCOR") -or ($_ -eq "bcor.ad")}            {$DomainName = "bcor.ad";           Break}
        {($_ -eq "BCORIT") -or ($_ -eq "bcor.it")}          {$DomainName = "bcor.it";           Break}
        {($_ -eq "COLO") -or ($_ -eq "colo.ext.hdv.corp")}  {$DomainName = "colo.ext.hdv.corp"; Break}
        {($_ -eq "CORPID") -or ($_ -eq "corpid.net")}       {$DomainName = "corpid.net";        Break}
        {($_ -eq "HDV") -or ($_ -eq "hdvest.com")}          {$DomainName = "hdvest.com";        Break}
        {($_ -eq "HDVCORP") -or ($_ -eq "hdv.corp")}        {$DomainName = "hdv.corp";          Break}
        {($_ -eq "HDVEXT") -or ($_ -eq "ext.hdv.corp")}     {$DomainName = "ext.hdv.corp";      Break}
        {($_ -eq "IRV") -or ($_ -eq "irv.hdv.corp")}        {$DomainName = "irv.hdv.corp";      Break}
        {($_ -eq "TAXACT") -or ($_ -eq "taxact.com")}       {$DomainName = "taxact.com";        Break}
    }
    return $DomainName
}
function Get-OperatingSystem {
    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $true)]$HostFQDN,
        [parameter(Position = 1, Mandatory = $true)]$AdminSecret
    )
    $TempFile = ($env:TEMP + "\RemoteOS.txt")
    $AdminUser, $UnEncrypted = (Get-ClearString -UserName $AdminSecret.UserName -SecureString $AdminSecret.Password)
    try {
        Start-Process -Wait cmd.exe -ArgumentList ("/c SystemInfo /s $($HostFQDN) /u:$($AdminUser) /p:$($UnEncrypted)") -WindowStyle Hidden -RedirectStandardOutput $TempFile
        foreach ($Line in Get-Content $TempFile) {
            switch ($Line) {
                {$_ -like "OS Name*"}       {$OSName = (($_).Split(":")[1]).Trim();      Break}
                {$_ -like "OS Version*"}    {$OSVersion = (($_).Split(":")[1]).Trim();   Break}
                Default {Break}
            }
        }
    }
    catch {
        $Error.Clear()
    }
    finally {
        if (Test-Path -Path $TempFile) {
            Remove-Item -Path $TempFile -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }
    return $OSName, $OSVersion
}
function Get-PortCheck {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true)][string]$HostFQDN,
        [Parameter(Position = 1, Mandatory = $true)][int]$PortNumber,
        [Parameter(Position = 2, Mandatory = $false)][string]$OSName = "2008+"
    )
    begin {
        $TempFile = ($env:TEMP + "\PortCheck.txt")
    }
    process {
        try {
            if ($OSName -like "*2003*") {
                $TelNet = ("telnet " + $HostFQDN + " " + $PortNumber)
                $RemoteUser, $UnEncrypted = (Get-ClearString -UserName $SvcAcctCreds.UserName -SecureString $SvcAcctCreds.Password)
                Start-Process -Wait cmd.exe -ArgumentList ("/c $($TelNet) /s $($HostFQDN) /u:$($RemoteUser) /p:$($UnEncrypted)") -WindowStyle Hidden | Out-File $TempFile
                foreach ($Line in Get-Content $TempFile) {
                    switch ($Line) {
                        {$_ -like "*Welcome to Microsoft Telnet Client*"} {
                            return 0
                            Break
                        }
                        Default {
                            Break
                        }
                    }
                }
            }
            else {
                $Results = Test-NetConnection -ComputerName $HostFQDN -Port $PortNumber
                if ($Results.TcpTestSucceeded) {
                    return 0
                }
                else {
                    return 1
                }
            }
        }
        catch {
            $Error.Clear()
            return 2
        }
    }
    end {
        if (Test-Path -Path $TempFile) {
            Remove-Item -Path $TempFile
        }
    }
}
function Get-RegistryValue {
    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $true)][string]$ComputerName,
        [parameter(Position = 1, Mandatory = $true)][string]$ComputerDomain
    )
    $ServerAdmin, $AdminDomain = (Get-SvcAcctName -DomainName $ComputerDomain)
    if ($ComputerName -like ("*.*")) {
        $ComputerName = $ComputerName.Split(".")[0]
    }
    $HostFQDN = ($ComputerName + "." + $ComputerDomain)
    try {
        $Results = Invoke-Command -ComputerName $HostFQDN -Credential $ServerAdmin -ScriptBlock {
            Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
        } -ErrorAction SilentlyContinue
        return $Results
    }
    catch {
        $Error.Clear()
        return 1
    }
}
function Get-RemoteFileShare {
    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $true)][string]$ComputerName,
        [parameter(Position = 1, Mandatory = $true)][string]$ComputerDomain,
        [parameter(Position = 2, Mandatory = $true)][string]$FileShare,
        [parameter(Position = 3, Mandatory = $true)][string[]]$Folders,
        [parameter(Position = 4, Mandatory = $true)][string[]]$FileNames,
        [parameter(Position = 5, Mandatory = $false)][string]$TempFolder = ($env:TEMP + "\" + $FileShare)
    )
    $SvcAcctSecret, $AdminDomain = (Get-SvcAcctName -DomainName $ComputerDomain)
    if ($ComputerName -like ("*.*")) {
        $ComputerName = $ComputerName.Split(".")[0]
    }
    $HostFQDN = ($ComputerName + "." + $ComputerDomain)
    $RemoteShare = ("\\" + $HostFQDN + "\" + $FileShare)
    if (!(Test-Path -Path $TempFolder)) {
        New-Item -Path $TempFolder -ItemType Directory -Force | Out-Null
    }
    try {
        $PSDrvName = (New-PSDrive -Name ($ComputerName) -PSProvider "FileSystem" -Root $RemoteShare -Credential $SvcAcctSecret)
        try {
            foreach ($Folder in $Folders) {
                $CurrentLocation = Get-Location
                Set-Location ($PSDrvName.Name + ":\" + $Folder)
                try {
                    foreach ($FileName in $FileNames) {
                        $Results = Get-ChildItem -Filter $FileName
                        Copy-Item -Path $Results.FullName -Destination $TempFolder
                    }
                }
                catch {
                    $Error.Clear()
                }
                finally {
                    Set-Location -Path $CurrentLocation
                }
            }
        }
        catch {
            $Error.Clear()
        }
    }
    catch {
        $Error.Clear()
    }
    finally {
        Remove-PSDrive -Name $PSDrvName
    }
    return $TempFolder
}
function Get-RemoteLogs {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true)][string]$HostFQDN,
        [Parameter(Position = 1, Mandatory = $true)][string]$ComputerDomain,
        [Parameter(Position = 2, Mandatory = $true)][string]$LogFile
    )
    if ($env:COMPUTERNAME -eq ($HostFQDN.Split(".")[0])) {
        return $LogFile
    }
    else {
        $AdminSecret = (Get-AdminUserName -DomainName $ComputerDomain)
        $RemoteShare = ("\\" + $HostFQDN + "\C$\Temp")
        $Results = Test-NetConnection -ComputerName $HostFQDN -Port 445
        if ($Results.TcpTestSucceeded) {
            $PSDrvName = (New-PSDrive -Name ($HostFQDN.Split(".")[0]) -PSProvider "FileSystem" -Root $RemoteShare -Credential $AdminSecret)
            Copy-Item -Path ($PSDrvName.Name + ":\*.log") -Destination (Split-Path -Parent $LogFile) -Force | Out-Null
            Remove-PSDrive -Name $PSDrvName
            return $LogFile
        }
        else {
            return 1
        }
    }
}
function Get-RemotePSVersion {
    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $true)]$HostFQDN,
        [parameter(Position = 1, Mandatory = $true)]$AdminSecret
    )
    try {
        $OSName, $OSVersion = Get-OperatingSystem -HostFQDN $HostFQDN -AdminSecret $AdminSecret
        switch ($OSName) {
            {$_ -like "*2003*"} {
                $TempFile = ($env:TEMP + "\RemotePSVersion.txt")
                $AdminUser, $UnEncrypted = (Get-ClearString -UserName $AdminSecret.UserName -SecureString $AdminSecret.Password)
                $RemoveProcess = ("powershell.exe `$PSVersionTable.psversion")
                try {
                    Start-Process -Wait cmd.exe -ArgumentList ("/c $($RemoveProcess) /s $($HostFQDN) /u:$($AdminUser) /p:$($UnEncrypted)") -RedirectStandardOutput $TempFile
                    foreach ($Line in Get-Content $TempFile) {
                        switch ($Line) {
                            {$_ -like "OS Name*"}       {$OSName = (($_).Split(":")[1]).Trim();      Break}
                            {$_ -like "OS Version*"}    {$OSVersion = (($_).Split(":")[1]).Trim();   Break}
                            Default {Break}
                        }
                    }
                }
                catch {
                    $Error.Clear()
                }
                finally {
                    if (Test-Path -Path $TempFile) {
                        Remove-Item -Path $TempFile -Force -ErrorAction SilentlyContinue | Out-Null
                    }
                }
                Break
            }
            Default {
                $RemoteSession = New-PSSession -ComputerName $HostFQDN -Credential $AdminSecret
                if ($RemoteSession) {
                    $Message = ("Successfully opened a remote session: [" + $RemoteSession.Id + "] to: " + $HostFQDN + ".")
                    Write-Host $Message
                    $PSVersion = Invoke-Command -Session $RemoteSession -ScriptBlock {
                        return $PSVersionTable.psversion
                    }
                }
                Remove-PSSession -Id $RemoteSession.Id
                Break
            }
        }
    }
    catch {
        $Error.Clear()
        $PSVersion = 0
    }
    return $PSVersion
}
function Get-RightString {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $True)][String]$DateString,
        [Parameter(Position = 1, Mandatory = $True)][Int]$Length
    )
    $StartChar = [math]::min($DateString.length - $Length, $DateString.length)
    $StartChar = [math]::max(0, $StartChar)
    $Right = $DateString.SubString($StartChar, [math]::min($DateString.length, $Length))
    Return $Right    
}
function Get-ServicePrincipalNames {
    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $true)]$ComputerName,
        [parameter(Position = 1, Mandatory = $true)]$ComputerDomain
    )
    $HostFQDN = (($ComputerName).ToUpper() + "." + ($ComputerDomain).ToLower())
    try {
        $HostName = ([System.Net.Dns]::GetHostEntry($HostFQDN)).HostName
        $HostDomain = ($HostName.SubString($HostName.indexof(".") + 1)).ToLower()
        $BiosName = ($HostName.Split(".")[0]).ToUpper()
        $HostName = ($BiosName + "." + $HostDomain)
        return $HostName, "Resolved"
    }
    catch {
        [PSCustomObject]@{
            Name = $HostFQDN
            Status = $Error[0].Exception.Message
        }
    }
}
function Get-ServiceStatus {
    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $true)][string[]]$SvcList,
        [parameter(Position = 1, Mandatory = $true)][string]$ShortName,
        [parameter(Position = 2, Mandatory = $true)][string]$Domain
    )
    Set-Variable -Name intCount -Value 0
    Set-Variable -Name Services -Value @()
    Set-Variable -Name ServiceList -Value @()
    Set-Variable -Name bRetestState -Value $true
    $SvcObject = New-Object -TypeName PSObject
    $HostFQDN = ($ShortName + "." + $Domain)
    $AdminSecret, $Domain = (Get-SvcAcctName -DomainName $Domain)
    $PSVersion = Get-RemotePSVersion -HostFQDN $HostFQDN -AdminSecret $AdminSecret
    try {
        switch ($PSVersion) {
            {$_.Major -ge 3} {
                foreach ($SvcName in $SvcList) {
                    New-Variable -Name "SvcName$($intCount)" -Value $SvcName
                    $SvcState = $null
                    $SvcState = (Test-RemoteService -HostName $ShortName -DomainName $Domain -ServiceName $SvcName).ToString()
                    if ($SvcState -ne 1) {
                        if ($SvcState -eq "Running") {
                            $bServicesRunning = $true
                        }
                        else {
                            $bServicesRunning = $false
                            try {
                                Switch (Set-RemoteServices -HostName $ShortName -DomainName $Domain -ServiceName $SvcName -State Start) {
                                    {($_ -eq $null)}    {Break}
                                    Default {
                                        $Message = ("ERROR:`tThe state of service: " + $SvcName + " failed to start.")
                                        Write-Host $Message -ForegroundColor Red -BackgroundColor Yellow
                                        $Error.Clear()
                                        return 3
                                    }
                                }
                                do {
                                    $SvcState = (Test-RemoteService -HostName $ShortName -DomainName $Domain -ServiceName $SvcName).ToString()
                                    if ($SvcState -ne 1) {
                                        if ($SvcState -eq "Running") {
                                            $bServicesRunning = $true
                                            $bRetestState = $false
                                            Break
                                        }
                                        else {
                                            Start-Sleep -Seconds $Delay
                                        }
                                    }
                                } until ($bRetestState)
                            }
                            catch {
                                $Message = ("ERROR:`tNot able to check the state of service: " + $SvcName + ".")
                                Write-Host $Message -ForegroundColor Red -BackgroundColor Yellow
                                $Error.Clear()
                                return 2
                            }
                        }
                        $Services += ($SvcObject | Select-Object @{
                            L = "Name";     E = {(Get-Variable -Name "SvcName$($intCount)").Value}}, @{
                            L = "State";    E = {$SvcState}}
                        )
                        Remove-Variable -Name "SvcName$($intCount)"
                        $Message = ("Service: " + $SvcName + " is currently '" + $SvcState + "'.")
                        Write-Host $Message
                    }
                    else {
                        $Message = ("ERROR:`tThe state of service: " + $SvcName + " is currently: '" + $SvcState + "'.")
                        Write-Host $Message -ForegroundColor Red -BackgroundColor Yellow
                        $Error.Clear()
                        return 1
                    }
                    $intCount ++
                }
                foreach ($Service in $Services) {
                    if (($Service.State).ToString() -ne "Running") {
                        $ServiceList += $Service.Name
                        $bServicesRunning = $false
                    }
                }
                Break
            }
            Default {
                return $true, $ServiceList
            }
        }
    }
    catch {
        $Error.Clear()
        return $true, $ServiceList
    }
    return $bServicesRunning, $ServiceList
}
function Get-SvcAcctName {
    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $false)][string]$SvcAcctName = "svc_mecm_sysaccess",
        [parameter(Position = 1, Mandatory = $true)][string]$DomainName,
        [parameter(Position = 2, Mandatory = $false)][bool]$bShortName = $false
    )
    switch ($DomainName) {
        {($_ -eq "1STGLOBAL") -or ($_ -eq "1stglobal.com")} {
            $DomainSN = "1STGLOBAL"
            $DomainName = "1stglobal.com"
            Break
        }
        {($_ -eq "BCOR") -or ($_ -eq "bcor.ad")} {
            $DomainSN = "BCOR"
            $DomainName = "bcor.ad"
            Break
        }
        {($_ -eq "BCORIT") -or ($_ -eq "bcor.it")} {
            $DomainSN = "BCORIT"
            $DomainName = "bcor.it"
            Break
        }
        {($_ -eq "COLO") -or ($_ -eq "colo.ext.hdv.corp")} {
            $DomainSN = "COLO"
            $DomainName = "colo.ext.hdv.corp"
            Break
        }
        {($_ -eq "CORPID") -or ($_ -eq "corpid.net")} {
            $DomainSN = "CORPID"
            $DomainName = "corpid.net"
            Break
        }
        {($_ -eq "HDV") -or ($_ -eq "hdvest.com")} {
            $DomainSN = "HDV"
            $DomainName = "hdvest.com"
            Break
        }
        {($_ -eq "HDVCORP") -or ($_ -eq "hdv.corp")} {
            $DomainSN = "HDVCORP"
            $DomainName = "hdv.corp"
            Break
        }
        {($_ -eq "HDVEXT") -or ($_ -eq "ext.hdv.corp")} {
            $DomainSN = "HDVEXT"
            $DomainName = "ext.hdv.corp"
            Break
        }
        {($_ -eq "IRV") -or ($_ -eq "irv.hdv.corp")} {
            $DomainSN = "IRV"
            $DomainName = "irv.hdv.corp"
            Break
        }
        {($_ -eq "TAXACT") -or ($_ -eq "taxact.com")} {
            $DomainSN = "TAXACT"
            $DomainName = "taxact.com"
            Break
        }
    }
    $iCount = 0
    $bReset = $false
    do {
        if ($iCount -eq 1) {
            $bReset = $true
        }
        $AccountSecret = Set-Credentials -SecureUser ($SvcAcctName + "@" + $DomainName) -Domain $DomainName -ResetPassword $bReset
        if (!($AccountSecret)) {
            $AccountSecret = Get-Credential -Credential ($SvcAcctName + "@" + $DomainName) -ErrorAction SilentlyContinue
        }
        $iCount ++
    } until (Test-ADAuthentication -UserName $AccountSecret.UserName -SecureString $AccountSecret.Password)
    if ($bShortName) {
        return $AccountSecret, $DomainSN
    }
    else {
        return $AccountSecret, $DomainName
    }
}
function Set-BatchService {
    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $true)]$NetBIOS,
        [parameter(Position = 1, Mandatory = $true)]$ComputerDomain,
        [parameter(Position = 2, Mandatory = $true)]$ServiceName,
        [parameter(Position = 3, Mandatory = $true)][ValidateSet("Start", "Stop", "Status")]$State
    )
    $HostFQDN = ($NetBIOS + "." + $ComputerDomain)
    $AdminSecret, $ComputerDomain = (Get-SvcAcctName -DomainName $ComputerDomain)
    $RemoteShare = ("\\" + $HostFQDN + "\C$\Temp")
    try {
        [string]$Statement = ""
        $PSDrvName = (New-PSDrive -Name ($HostFQDN.Split(".")[0]) -PSProvider "FileSystem" -Root $RemoteShare -Credential $AdminSecret)
        $NewBatchFile = ($PSDrvName.Name + ":\" + $ServiceName + ".cmd")
        New-Item -Path $NewBatchFile -ItemType File -ErrorAction SilentlyContinue | Out-Null
        if (Test-Path -Path $NewBatchFile) {
            Remove-Item -Path $NewBatchFile -Force -ErrorAction SilentlyContinue | Out-Null
        }
        if ($ServiceName -contains " ") {
            $ServiceName = ("""" + $ServiceName + """")
        }
        switch ($State) {
            {($_ -eq "Start") -or ($_ -eq "Stop")} {
                $Statement = ("net $State " + $ServiceName)
                Break
            }
            Default {
                $Statement = ("sc query " + $ServiceName)
                Break
            }
        }
        $Statement | Out-File $NewBatchFile -Encoding ascii -Force -ErrorAction Stop
        Remove-PSDrive -Name $PSDrvName
    }
    catch {
        $Error.Clear()
        return 1
    }
}
function Set-LocalAdminAccount {
    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $true)][string]$ComputerName,
        [parameter(Position = 1, Mandatory = $true)][string]$ComputerDomain,
        [parameter(Position = 2, Mandatory = $true)][string]$NewAccount,
        [parameter(Position = 3, Mandatory = $true)][string]$Secret,
        [parameter(Position = 4, Mandatory = $true)][string]$AppName,
        [parameter(Position = 5, Mandatory = $true)]$LogFile
    )
    $SecureString = ConvertTo-SecureString -String $Secret -AsPlainText -Force
    Remove-Variable -Name Secret
    $AdminSecret = (Get-AdminUserName -DomainName $ComputerDomain)
    if (!($ComputerName -like ("*.*"))) {
        $HostFQDN = ($ComputerName + "." + $ComputerDomain)
    }
    else {
        $HostFQDN = $ComputerName
    }
    try {
        $Results = Invoke-Command -ComputerName $HostFQDN -Credential $AdminSecret -ScriptBlock {
            param ($AppName, $HostFQDN, $LogFile, $NewAccount, $SecureString)
            Set-Variable -Name PSVersion -Value $PSVersionTable.PSVersion
            Set-Variable -Name LocalAccounts -Value @()
            $Message = ("Processing hostname: [" + $HostFQDN + "]")
            $Message | Out-File -FilePath $LogFile
            switch (($PSVersion).Major) {
                {($_ -eq 5)} {
                    $LocalAccounts += Get-LocalUser
                    Break
                }
                Default {
                    $LocalAccounts += Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount = True"
                    Break
                }
            }
            foreach ($Account in $LocalAccounts) {
                if ($Account.SID -like "*-500") {
                    $LocalAdmin = $Account.Name
                    $Message = ("'" + $LocalAdmin + "' is the 'Built-In Administrator' account for " + $HostFQDN + ".")
                    $Message | Out-File -FilePath $LogFile -Append
                }
                elseif ($Account.Name -eq $NewAccount) {
                    $bFound = $false
                    switch (($PSVersion).Major) {
                        {($_ -eq 5)} {
                            foreach ($User in (Get-LocalGroupMember -Group "Administrators").Name) {
                                if ($User -like ("*" + $NewAccount + "*")) {
                                    $bFound = $true
                                    Break
                                }
                            }
                            if (!($bFound)) {
                                Add-LocalGroupMember -Group "Administrators" -Member $NewAccount
                            }
                            Break
                        }
                        Default {
                            $UserList = @("net localgroup Administrators")
                            $TempUserList = ($env:TEMP + "\AdminUsers.txt")
                            Start-Process cmd.exe $UserList -NoNewWindow -RedirectStandardInput $TempUserList
                            foreach ($User in Get-Content $TempUserList) {
                                if ($User -like ("*" + $NewAccount + "*")) {
                                    $bFound = $true
                                    Break
                                }
                            }
                            $AddGroup = @("net localgroup Administrators " + $NewAccount + " /add")
                            if (!($bFound)) {
                                Start-Process cmd.exe $AddGroup -NoNewWindow
                            }
                            Remove-Item -Path $TempUserList | Out-Null
                            Break
                        }
                    }
                    if (!($bFound)) {
                        $Message = ("Added: [" + $NewAccount + "] to the 'Administrator' group on: [" + $HostFQDN + "].")
                    }
                    else {
                        $Message = ("INFO: [" + $NewAccount + "] was already a member of the 'Administrator' group on: [" + $HostFQDN + "].")
                    }
                    $Message | Out-File -FilePath $LogFile -Append
                    return 0
                }
            }
            return 1
        } -ArgumentList $AppName, $HostFQDN, $LogFile, $NewAccount, $SecureString
        if ($Results -eq 1) {
            $Results = Invoke-Command -ComputerName $HostFQDN -Credential $AdminSecret -ScriptBlock {
                param ($AppName, $HostFQDN, $LogFile, $NewAccount, $SecureString)
                Set-Variable -Name PSVersion -Value $PSVersionTable.PSVersion
                try {
                    switch (($PSVersion).Major) {
                        {($_ -eq 5)} {
                            New-LocalUser -Name $NewAccount -Description ("Local Admin Account for " + $AppName + ".") -Password $SecureString
                            Add-LocalGroupMember -Group "Administrators" -Member $NewAccount
                            Break
                        }
                        Default {
                            $AddUser = @("net user /add " + $NewAccount + " " + $SecureString)
                            Start-Process cmd.exe $AddUser -NoNewWindow
                            $Message = ("Added: [" + $NewAccount + "] as a new user on: [" + $HostFQDN + "].")
                            $Message | Out-File -FilePath $LogFile -Append
                            $AddGroup = @("net localgroup Administrators " + $NewAccount + " /add")
                            Start-Process cmd.exe $AddGroup -NoNewWindow
                            Break
                        }
                    }
                    $Message = ("Added: [" + $NewAccount + "] to the 'Administrator' group on: [" + $HostFQDN + "].")
                    $Message | Out-File -FilePath $LogFile -Append
                    return 0
                }
                catch {
                    return $Error[0].Exception.Message
                    $Error.Clear()
                    return 2
                }
            } -ArgumentList $AppName, $HostFQDN, $LogFile, $NewAccount, $SecureString
        }
    }
    catch {
        $Error.Clear()
        return 1
    }
    if ($Results -ne 0) {
        return $Results
    }
}
function Set-RemoteFileShare {
    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $true)][string]$ComputerName,
        [parameter(Position = 1, Mandatory = $true)][string]$ComputerDomain,
        [parameter(Position = 2, Mandatory = $true)][string]$FileShare,
        [parameter(Position = 3, Mandatory = $true)][string[]]$Folders,
        [parameter(Position = 4, Mandatory = $true)][string]$FileName
    )
    $SvcAcctSecret, $AdminDomain = (Get-SvcAcctName -DomainName $ComputerDomain)
    if ($ComputerName -like ("*.*")) {
        $ComputerName = $ComputerName.Split(".")[0]
    }
    $HostFQDN = ($ComputerName + "." + $ComputerDomain)
    $RemoteShare = ("\\" + $HostFQDN + "\" + $FileShare)
    try {
        $PSDrvName = (New-PSDrive -Name ($ComputerName) -PSProvider "FileSystem" -Root $RemoteShare -Credential $SvcAcctSecret)
        try {
            $CurrentFile = Split-Path -Leaf $FileName
            foreach ($Folder in $Folders) {
                $DesFileName = ($PSDrvName.Name + ":\" + $Folder + "\" + $CurrentFile)
                if (Test-Path -Path ($DesFileName)) {
                    Remove-Item -Path $DesFileName -Force -ErrorAction SilentlyContinue | Out-Null
                }
                try {
                    Copy-Item -Path $FileName -Destination ($PSDrvName.Name + ":\" + $Folder)
                }
                catch {
                    $Error.Clear()
                }
            }
        }
        catch {
            $Error.Clear()
        }
    }
    catch {
        $Error.Clear()
    }
    finally {
        Remove-PSDrive -Name $PSDrvName
    }
}
function Set-RemoteServices {
    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $true)]$HostName,
        [parameter(Position = 1, Mandatory = $true)]$DomainName,
        [parameter(Position = 2, Mandatory = $true)]$ServiceName,
        [parameter(Position = 3, Mandatory = $true)][ValidateSet("Start", "Stop")]$State
    )
    $HostFQDN = ($HostName + "." + $DomainName)
    $AdminSecret, $DomainName = (Get-SvcAcctName -DomainName $DomainName)
    $PSVersion = Get-RemotePSVersion -HostFQDN $HostFQDN -AdminSecret $AdminSecret
    try {
        switch ($PSVersion) {
            {$_.Major -ge 3} {
                $Status = Invoke-Command -ComputerName $HostFQDN -Credential $AdminSecret -ScriptBlock {
                    param ($ServiceName, $State)
                    switch ($State) {
                        {$_ -eq "Start"}    {return (Start-Service -InputObject $(Get-Service -Name $ServiceName)).Status;  Break}
                        {$_ -eq "Stop"}     {return (Stop-Service -InputObject $(Get-Service -Name $ServiceName)).Status;   Break}
                    }
                    return (Start-Service -InputObject $(Get-Service -Name $ServiceName)).Status
                } -ArgumentList $ServiceName, $State
                Break
            }
            Default {
                $CurrentLocation = Get-Location
                Set-BatchService -NetBIOS $HostName -ComputerDomain $DomainName -ServiceName $ServiceName -State $State
                try {
                    Set-Location "E:\Sysinternals"
                    $RemoteCMD = ("C:\Temp\" + $ServiceName + ".cmd")
                    $ResultsFile = ($env:TEMP + "\" + $ServiceName + ".log")
                    Start-Process PSExec64.exe -ArgumentList ("-s \\" + $HostFQDN + " """ + $RemoteCMD + """") -RedirectStandardOutput $ResultsFile -WindowStyle Hidden -Wait
                    foreach ($Line in Get-Content $ResultsFile) {
                        $Status = ($ServiceName + " is running on: " + $HostName)
                    }
                    Remove-Item -Path $ResultsFile
                }
                catch {
                    $Error.Clear()
                    return 2
                }
                finally {
                    Set-Location $CurrentLocation
                }
                Break
            }
        }
        return $Status
    }
    catch {
        $Error.Clear()
        return 1
    }
}
function Start-TCPServer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]$Port = 10000
    )
    do {
        # Create a TCP listender on Port $Port
        $TcpObject = New-Object System.Net.Sockets.TcpListener($port)
        # Start TCP listener
        $ReceiveBytes = $TcpObject.Start()
        # Accept TCP client connection
        $ReceiveBytes = $TcpObject.AcceptTcpClient()
        # Stop TCP Client listener
        $TcpObject.Stop()
        # Output information about remote client
        $ReceiveBytes.Client.RemoteEndPoint
    }  while (1)
}
function Start-UDPServer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]$Port = 10000
    )
    # Create a endpoint that represents the remote host from which the data was sent.
    $RemoteComputer = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
    Write-Host "Server is waiting for connections - $($UdpObject.Client.LocalEndPoint)"
    Write-Host "Stop with CRTL + C"
    # Loop de Loop
    do {
        # Create a UDP listender on Port $Port
        $UdpObject = New-Object System.Net.Sockets.UdpClient($Port)
        # Return the UDP datagram that was sent by the remote host
        $ReceiveBytes = $UdpObject.Receive([ref]$RemoteComputer)
        # Close UDP connection
        $UdpObject.Close()
        # Convert received UDP datagram from Bytes to String
        $ASCIIEncoding = New-Object System.Text.ASCIIEncoding
        [string]$ReturnString = $ASCIIEncoding.GetString($ReceiveBytes)
        # Output information
        [PSCustomObject]@{
            LocalDateTime = $(Get-Date -UFormat "%Y-%m-%d %T")
            SourceIP      = $RemoteComputer.address.ToString()
            SourcePort    = $RemoteComputer.Port.ToString()
            Payload       = $ReturnString
        }
    } while (1)
}
function Test-ADAuthentication {
    [CmdletBinding()]
    param (
        $UserName,
        $SecureString
    )
    $BSTR=[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    $UnEncrypted=[System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    $null -ne (New-Object System.DirectoryServices.DirectoryEntry "", $UserName, $UnEncrypted).psbase.name
    Remove-Variable -Name UnEncrypted -Force -ErrorAction SilentlyContinue
}
function Test-Date {
    [CmdletBinding()]
    param (
        [ValidateScript({
            try {
                [datetime]::ParseExact($PSItem, 'd', [System.Globalization.CultureInfo](Get-Culture))
            }
            catch {
                throw Write-Error -Message "Enter the name of the folder using a short date format: '1/25/2022'" -ErrorAction Stop
            }
        })][string]$Date
    )
    Return $Date.Replace("/","-")
}
function Test-NetConnectionUDP {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true)][string]$ComputerName,
        [Parameter(Position = 1, Mandatory = $true)][int32]$Port,
        [Parameter(Position = 2, Mandatory = $false)][int32]$SourcePort = 50000
    )
    begin {
        # Create a UDP client object
        $UdpObject = New-Object system.Net.Sockets.Udpclient($SourcePort)
        # Define connect parameters
        $UdpObject.Connect($ComputerName, $Port)
    }
    process {
        try {
            # Convert current time string to byte array
            $ASCIIEncoding = New-Object System.Text.ASCIIEncoding
            $Bytes = $ASCIIEncoding.GetBytes("$(Get-Date -UFormat "%Y-%m-%d %T")")
            # Send data to server
            [void]$UdpObject.Send($Bytes, $Bytes.length)
            return 0            
        }
        catch {
            $Error.Clear()
            return 1
        }
    }
    end {
        # Cleanup
        $UdpObject.Close()
    }
}
function Test-RemoteService {
    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $true)]$HostName,
        [parameter(Position = 1, Mandatory = $true)]$DomainName,
        [parameter(Position = 2, Mandatory = $true)]$ServiceName
    )
    $AdminSecret, $DomainName = (Get-SvcAcctName -DomainName $DomainName)
#    $AdminSecret = (Get-AdminUserName -DomainName $DomainName)
    $HostFQDN = ($HostName + "." + $DomainName)
    try {
        $State = Invoke-Command -ComputerName $HostFQDN -Credential $AdminSecret -ScriptBlock {
            param ($ServiceName)
            return (Get-Service -Name $ServiceName).Status
        } -ArgumentList $ServiceName
        return $State
    }
    catch {
        $Error.Clear()
        return 1
    }
}
Export-ModuleMember -Function Get-AdminUserName
Export-ModuleMember -Function Get-ComputerInfo
Export-ModuleMember -Function Get-HostDomain
Export-ModuleMember -Function Get-OperatingSystem
Export-ModuleMember -Function Get-PortCheck
Export-ModuleMember -Function Get-RegistryValue
Export-ModuleMember -Function Get-RemoteFileShare
Export-ModuleMember -Function Get-RemoteLogs
Export-ModuleMember -Function Get-RightString
Export-ModuleMember -Function Get-ServicePrincipalNames
Export-ModuleMember -Function Get-ServiceStatus
Export-ModuleMember -Function Get-SvcAcctName
Export-ModuleMember -Function Set-LocalAdminAccount
Export-ModuleMember -Function Set-RemoteFileShare
Export-ModuleMember -Function Set-RemoteServices
Export-ModuleMember -Function Start-TCPServer
Export-ModuleMember -Function Start-UDPServer
Export-ModuleMember -Function Test-ADAuthentication
Export-ModuleMember -Function Test-Date
Export-ModuleMember -Function Test-NetConnectionUDP
Export-ModuleMember -Function Test-RemoteService
