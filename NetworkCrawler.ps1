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
#        "taxact.com",
#        "taxactonline.com"
    ),
    [parameter(Position = 1, Mandatory = $false)][string[]]$LogFileNames = @(
        "NetworkScan"
    ),
    [parameter(Position = 2, Mandatory = $false)][string[]]$ImportList = "ResourceList"
)
$ListPSVars = Get-Variable -Exclude ("DomainList") | Select-Object -ExpandProperty Name
[string]$ScriptPath = Split-Path -Path ($MyInvocation.MyCommand.Definition)
[string]$ScriptName = $MyInvocation.MyCommand.Name
[string]$LogDate = Get-Date -Format "yyyy-MMdd"
[datetime]$StartTime = Get-Date -Format o
$EAPreference = "SilentlyContinue"
Import-Module -Name AdminTools
Import-Module -Name ActiveDirectory
Import-Module -Name ProcessCredentials
$Global:ProgressPreference = "SilentlyContinue"
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
    $LogFileName = (Split-Path -Path $LogFile -Leaf).Replace(".log", "")
    $Files = Get-Item -Path ($LogLocation + "\*.*")
    [int]$FileCount = 0
    foreach($File in $Files) {
        if (!($File.Mode -eq "d----") -and ($File.Name -like ($LogFileName + "*"))) {
            $FileCount ++
        }
    }
    if (($FileCount -gt 0) -and $LogCount -eq 0) {
        $NewLogFile = ($LogFileName + "(" + $FileCount + ").log")
        ("Changing the name of this log [" + $LogFileName + "] to [" + $NewLogFile + "].") | Out-File -FilePath $LogFile -Append
        Rename-Item -Path $LogFile -NewName $NewLogFile
    }
    ("Starting a new log [" + $LogFileName + "] at [" + $StartTime + "].") | Out-File -FilePath $LogFile
    $LogCount ++
}
$ADFilter = ("OperatingSystem -like '*server*' -and Enabled -eq 'true' -and PasswordExpired -eq 'false'")
$Properties = ("SID", "Name", "IPv4Address", "DNSHostName", "DistinguishedName", "Operatingsystem", "PasswordLastSet", "whenChanged")
Clear-History; Clear-Host; $Error.Clear()
try {
    $CurrentLocation = (Get-Location).Path
    Set-Location -Path $ScriptPath
    Set-Variable -Name ScrubList -Value ($ScriptPath + "\" + $ImportList)
    $mdaActiveDeviceList = @()
    $mdaActiveNetworkList = @()
    $mdaInActiveDevices = @()
    $DummyObject = New-Object -TypeName PSObject 
    if (!(Test-Path -Path $ScrubList)) {
        New-Item -Path $ScrubList -ItemType Directory | Out-Null
    }
    try {
        if (Test-Path -Path $ScrubList) {
            Remove-Item -Path ($ScrubList + "\*") -Force -ErrorAction $EAPreference | Out-Null
        }
        $PythonApp = ("python")
        $PythonScript = '"e:\Support\Scripts\ComputerList\GetDevices.py"'
        $ScriptBlock = ($PythonApp + " " + $PythonScript)
        $Message = ("Beginning to export Logic Monitor device list using " + $PythonApp + " script: [" + $PythonScript + "]")
        Write-Host $Message; $Message | Out-File -FilePath $LogFile -Append
        Start-Process cmd.exe -ArgumentList ("/c " + $ScriptBlock) -WindowStyle Hidden -Wait
        if (Test-Path -Path $ScrubList) {
            $Pattern = "[^a-zA-Z0-9/*=,.:]( )"
            foreach ($ComputerList in Get-ChildItem -Path $ScrubList) {
                $ComputerFileName = $ComputerList.PSChildName
                if ($ComputerList.Extension -eq ".json") {
                    $FullFileName = ($ScrubList + "\" + $ComputerFileName).Replace(".json",".txt")
                    (Get-Content -Path ($ScrubList + "\" + $ComputerFileName)) -replace $Pattern,"" | Out-File $FullFileName -Encoding ascii
                    Set-Variable -Name bAccessible -Value $false
                    Set-Variable -Name bCategoryValue -Value $false
                    Set-Variable -Name bCustomProperties -Value $false
                    Set-Variable -Name bDeviceName -Value $false
                    Set-Variable -Name bReset -Value $true
                    Set-Variable -Name DeviceIP -Value $null
                    Set-Variable -Name DeviceName -Value $null
                    Set-Variable -Name DisplayName -Value $null
                    Set-Variable -Name DeviceValue -Value $null
                    Set-Variable -Name NetworkSource -Value $null
                    $Message = ("Processing the exported data from Logic Monitor: [" + $FullFileName + "]")
                    Write-Host $Message; $Message | Out-File -FilePath $LogFile -Append
                    try {
                        foreach ($CLV in Get-Content -Path $FullFileName) {
                            $Results = $null
                            if ($bReset) {
                                $bAccessible = $false
                                $bCategoryValue = $false
                                $bCustomProperties = $false
                                $bDeviceName = $false
                                $DeviceName = $null
                                $DisplayName = $null
                                $DeviceValue = $null
                                $bReset = $false
                            }
                            switch ($CLV) {
                                {$_ -like '"id": *'} {
                                    $bDeviceName = $true
                                    Break
                                }
                                {($_ -like '"name": *' -and $bDeviceName)} {
                                    $iCount = 0
                                    $DeviceIP = $null
                                    $NetworkSource = "Internal"
                                    $DnsValue = (($CLV).Replace('"',"").Split(" "))[1].Replace(",","")
                                    if ($DnsValue) {
                                        $Results = Test-NetConnection -ComputerName $DnsValue -DiagnoseRouting -ErrorAction $EAPreference
                                        try {
                                            if ($Results.ResolvedAddresses) {
                                                if ($Results.ResolvedAddresses[0]) {
                                                    do {
                                                        if (!($Results.ResolvedAddresses[$iCount] -like "*:*")) {
                                                            $DeviceIP = ($Results.ResolvedAddresses[$iCount])
                                                        }
                                                        $iCount ++
                                                    } until ($DeviceIP)
                                                    if ($Results.RouteDiagnosticsSucceeded) {
                                                        $bAccessible = $true
                                                    }
                                                }
                                                else {
                                                    $bAccessible = $false
                                                }
                                            }
                                        }
                                        catch {
                                            $Error.Clear()
                                        }
                                        $bDeviceName = $false
                                        $DeviceName = $DnsValue
                                    }
                                    Break
                                }
                                {$_ -like '"displayName": *'} {
                                    $DisplayName = (($CLV).Replace('"',"").Split(" "))[1].Replace(",","")
                                    Break
                                }
                                {$_ -like '"customProperties": *'} {
                                    $bCustomProperties = $true
                                    Break
                                }
                                {($_ -like '*"system.categories"*' -and $bCustomProperties)} {
                                    $bCategoryValue = $true
                                    Break
                                }
                                {($_ -like '"value": *' -and $bCategoryValue -and $bCustomProperties)} {
                                    $DeviceValue = (($CLV).Replace('"',"").Split(" "))[1]
                                    $bReset = $true
                                    Break
                                }
                                Default {
                                    Break
                                }
                            }
                            if ($bReset) {
                                $Message = ""
                                if (!($bAccessible)) {
                                    $mdaInActiveDevices += ($DummyObject | Select-Object @{
                                        L = "Name";         E = {$DeviceName}}
                                    )
                                    $Message = ("WARNING:`t[" + $DeviceName + "] is not accessible on the network.")
                                }
                                else {
                                    $bNetwork = $true
                                    $DeviceType = $null
                                    switch ($DeviceValue) {
                                        {$_ -like "*Collector*"}    {$bNetwork = $false;    Break}
                                        {$_ -like "*snmpTCPUDP*"}   {$bNetwork = $true;     Break}
                                        {$_ -like "*TopoSwitch*"}   {$bNetwork = $true;     Break}
                                        {$_ -like "*PaloAlto*"}     {$bNetwork = $true;     Break}
                                        {$_ -like "*Storage*"}      {$bNetwork = $true;     Break}
                                        {$_ -like "*ESXi*"}         {$bNetwork = $true;     Break}
                                        {$_ -like "*F5*"}           {$bNetwork = $true;     Break}
                                        Default {Break}
                                    }
                                    switch ($DisplayName) {
                                        {$_ -like "*epan*"}                 {$bNetwork = $true; Break}
                                        {$_ -like "*ipan*"}                 {$bNetwork = $true; Break}
                                        Default {Break}
                                    }
                                    if (!($DeviceName -eq $DeviceIP) -and $DeviceName -like "*.*") {
                                        switch ($DeviceIP.IPAddressToString) {
                                            {$_ -like "10.*"} {$NetworkSource = "Internal"; Break}
                                            {$_ -like "172.*"} {
                                                [int]$SecondOctate = ($_).Split(".")[1]
                                                if (($SecondOctate -ge 16) -and ($SecondOctate -le 31)) {
                                                    $NetworkSource = "Internal"; Break
                                                }
                                            }
                                            {$_ -like "192.168.*"} {$NetworkSource = "Internal"; Break}
                                            Default {$NetworkSource = "External"; Break}
                                        }
                                        if ($NetworkSource -eq "Internal") {
                                            switch ($DeviceName) {
                                                {$_ -like "*1stglobal.com*"}        {$bNetwork = $false; Break}
                                                {$_ -like "*bcor.ad*"}              {$bNetwork = $false; Break}
                                                {$_ -like "*bcor.it*"}              {$bNetwork = $false; Break}
                                                {$_ -like "*colo.ext.hdv.corp*"}    {$bNetwork = $false; Break}
                                                {$_ -like "*corpid.net*"}           {$bNetwork = $false; Break}
                                                {$_ -like "*ext.hdv.corp*"}         {$bNetwork = $false; Break}
                                                {$_ -like "*hdv.corp*"}             {$bNetwork = $false; Break}
                                                {$_ -like "*hdvest.com*"}           {$bNetwork = $false; Break}
                                                {$_ -like "*irv.hdv.corp*"}         {$bNetwork = $false; Break}
                                                {$_ -like "*taxact.com*"}           {$bNetwork = $false; Break}
                                                {$_ -like "*taxactonline.com*"}     {$bNetwork = $false; Break}
                                                Default {Break}
                                            }
                                        }
                                    }
                                    if (!($NetworkSource -eq "External")) {
                                        if ($bNetwork) {
                                            $DeviceType = "Networking"
                                            $mdaActiveNetworkList += ($DummyObject | Select-Object @{
                                                L = "IPv4";         E = {$DeviceIP}}, @{
                                                L = "Name";         E = {$DeviceName}}, @{
                                                L = "DisplayName";  E = {$DisplayName}}, @{
                                                L = "Value";        E = {$DeviceValue}}
                                            )
                                        }
                                        else {
                                            $DeviceType = "Computer"
                                            $mdaActiveDeviceList += ($DummyObject | Select-Object @{
                                                L = "IPv4";         E = {$DeviceIP}}, @{
                                                L = "Name";         E = {$DeviceName}}, @{
                                                L = "DisplayName";  E = {$DisplayName}}, @{
                                                L = "Value";        E = {$DeviceValue}}
                                            )
                                        }
                                        $Message = ("" + $DeviceType + "`t[" + $DeviceName + "] is online, listed in LogicMonitor as: [" + $DisplayName + "]")
                                        $Message += (", and has the following category value(s):" + $DeviceValue)
                                    }
                                    else {
                                        $Message = ("INFO:`t[" + $DeviceName + "] is not an internal network.")
                                    }
                                }
                                Write-Host $Message; $Message | Out-File -FilePath $LogFile -Append
                            }
                        }
                    }
                    catch {
                        $Error.Clear()
                    }
                    finally {
                        if (Test-Path -Path $FullFileName) {
                            Remove-Item -Path $FullFileName -Force | Out-Null
                        }
                    }
                }
            }
        }
    }
    catch {
        $Error.Clear()
    }
    Clear-History; Clear-Host; $Error.Clear()
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
        $Message = ("Retrieving data from the [" + $PDC + "] domain controller . . .`r`n")
        Write-Host $Message; $Message | Out-File -FilePath $LogFile -Append
        $MemberList = Get-ADComputer -Filter $ADFilter -Server $PDC -Credential $SvcAcctCreds -Properties $Properties |
            Sort-Object -Property "Name", "IPv4Address" | Select-Object -Property $Properties
        $Message = (("=" * 82) * 2)
        Write-Host $Message; $Message | Out-File -FilePath $LogFile -Append
        $Message = ("SID `tHostname `tDomain `tOperatingSystem `tIPv4Address `tDays `twhenChanged `tLogic Monitor status")
        Write-Host $Message; $Message | Out-File -FilePath $LogFile -Append
        foreach ($Member in $MemberList) {
            $ByPass = $false
            [int]$iDCCount = 0
            [int]$LastChanged = 0
            [string]$ChangeDate = $null
            [string]$IPv4Address = ""
            [datetime]$CompareDate = Get-Date -Format o
            Set-Variable -Name WhenChanged -Value @()
            Set-Variable -Name MemberName -Value @()
            try {
                foreach ($DC in $DCList) {
                    $FqdnDC = ($DC.Name + "." + $Domain)
                    $CurrentHost = Get-ADComputer -Identity $Member.SID -Server $FqdnDC -Credential $SvcAcctCreds -Properties $Properties |
                        Sort-Object -Property "OperatingSystem", "Name" | Select-Object -Property $Properties
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
            }
            catch {
                $Error.Clear()
            }
            try {
                if ($Member.IPAddressToString) {
                    $IPv4Address = $Member.IPAddressToString
                    if ($LastChanged -gt 60) {
                        $ByPass = $true
                    }
                }
                else {
                    $IPv4Address = "[N/A]"
                    $ByPass = $true
                }
            }
            catch {
                $Error.Clear()
            }
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
                        $Message = ("SPN: " + $MemberName)
                    }
                    else {
                        $Message = ("SPN: " + $MemberName + " - CNAME: " + $CurrentHost.Name)
                    }
                    $Message = ("ERROR:`tIn the wrong OU: " + $CurrentHost.DistinguishedName + " | " + $Message)
                    Write-Host $Message; $Message | Out-File -FilePath $LogFile -Append
                    $byPass = $false
                    Break
                }
                Default {
                    Break
                }
            }
            switch ($Member.OperatingSystem) {
                {$_ -like "*2000*"} {$i2000 ++; Break}
                {$_ -like "*2003*"} {$i2003 ++; Break}
                {$_ -like "*2008*"} {$i2008 ++; Break}
                {$_ -like "*2012*"} {$i2012 ++; Break}
                {$_ -like "*2016*"} {$i2016 ++; Break}
                {$_ -like "*2019*"} {$i2019 ++; Break}
                {$_ -like "*2022*"} {$i2022 ++; Break}
            }
            if (!($ByPass)) {
                foreach ($LmDevice in $mdaActiveDeviceList) {
                    if ($LmDevice.Name -eq $Member.DNSHostName) {
                        $ByPass = $true
                        Break
                    }
                }
            }
            if ($ByPass) {
                $Message = ("INFO`tBypassing server: [" + $Member.DNSHostName + "]")
            }
            else {
                [int]$CollectionID = 0
                [string]$CollectionName = ""
                [string]$CustomProperties = ""
                [string]$DeviceName = $Member.DNSHostName
                [string]$DisplayName = $Member.Name
                $dpLeft = ($DisplayName.SubString(0, 3)).ToUpper()
                $dpRight = ($DisplayName.SubString($DisplayName.Length - 5, 5)).ToUpper()
                switch ($dpLeft) {
                    "AE1" {
                        $CustomProperties = "AWS_US_East_1"
                        $CollectionName = "AE1VWLMCL01P"
                        $CollectionID = 10
                        Break
                    }
                    "AW2" {
                        $CustomProperties = "AWS_US_West_2"
                        $CollectionName = "AW2VWLMCL01P"
                        $CollectionID = 11
                        Break
                    }
                    "ORD" {
                        $CustomProperties = "Chicago"
                        $CollectionName = "ORDVWLMCL10P"
                        $CollectionID = 28
                        Break
                    }
                    "CHI" {
                        $CustomProperties = "Chicago"
                        $CollectionName = "ORDVWLMCL10P"
                        $CollectionID = 28
                        Break
                    }
                    Default {
                        $CustomProperties = "SunGard"
                        $CollectionName = "SGRVWLMCL10P"
                        $CollectionID = 29
                        Break
                    }
                }
                switch ($Domain) {
                    {$_ -eq "1stglobal.com"} {
                        $CollectionName = "SGRVWLMCL05P"
                        $CollectionID = 25
                        Break
                    }
                    {$_ -eq "bcor.ad"} {
                        $CollectionName = "SGRVWLMCL06P"
                        $CollectionID = 18
                        Break
                    }
                    {$_ -eq "bcor.it"} {
                        $CollectionName = "SGRVWLMCL02P"
                        $CollectionID = 14
                        Break
                    }
                    {$_ -eq "colo.ext.hdv.corp"} {
                        $CollectionName = "SGRVWLMCL04P"
                        $CollectionID = 16
                        Break
                    }
                    {$_ -eq "ext.hdv.corp"} {
                        $CollectionName = "SGRVWLMCL07P"
                        $CollectionID = 19
                        Break
                    }
                    {$_ -eq "hdv.corp"} {
                        $CollectionName = "SGRVWLMCL09P"
                        $CollectionID = 24
                        Break
                    }
                    {$_ -eq "hdvest.com"} {
                        $CollectionName = "SGRVWLMCL08P"
                        $CollectionID = 21
                        Break
                    }
                    {$_ -eq "irv.hdv.corp"} {
                        $CollectionName = "SGRVWLMCL03P"
                        $CollectionID = 15
                        Break
                    }
                    {$_ -eq "taxact.com"} {
                        $CollectionName = "ORDVWLMCL02P"
                        $CollectionID = 23
                        Break
                    }
                    {$_ -eq "taxactonline.com"} {
                        $CollectionName = "AE1VWMID3800P"
                        $CollectionID = 30
                        Break
                    }
                }
                if (($dpRight -like "*VP*") -or ($dpRight -like "*P")) {
                    $CustomProperties = ("," + $CustomProperties)
                    switch ($Domain) {
                        {$_ -eq "1stglobal.com"}        {$CustomProperties = "1g-prod" + $CustomProperties;     Break}
                        {$_ -eq "bcor.ad"}              {$CustomProperties = "bcor-prod" + $CustomProperties;   Break}
                        {$_ -eq "bcor.it"}              {$CustomProperties = "bcorit-prod" + $CustomProperties; Break}
                        {$_ -eq "colo.ext.hdv.corp"}    {$CustomProperties = "colo-prod" + $CustomProperties;   Break}
                        {$_ -eq "corpid.net"}           {$CustomProperties = "corpid-prod" + $CustomProperties; Break}
                        {$_ -eq "ext.hdv.corp"}         {$CustomProperties = "ext-prod" + $CustomProperties;    Break}
                        {$_ -eq "hdv.corp"}             {$CustomProperties = "hdv-prod" + $CustomProperties;    Break}
                        {$_ -eq "hdvest.com"}           {$CustomProperties = "hdvest-prod" + $CustomProperties; Break}
                        {$_ -eq "irv.hdv.corp"}         {$CustomProperties = "irv-prod" + $CustomProperties;    Break}
                        {$_ -eq "taxact.com"}           {$CustomProperties = "taxact-prod" + $CustomProperties; Break}
                        {$_ -eq "taxactonline.com"}     {$CustomProperties = "tao-prod" + $CustomProperties;    Break}
                    }
                }
                $Message = ("Attempting to add device: [" + $DeviceName + "] to Logic Monitor for collector: [" + $CollectionName + "].")
                $mdaAdditionDevices += ($DummyObject | Select-Object @{
                    L = "Name";                 E = {$DeviceName}}, @{
                    L = "DisplayName";          E = {$DisplayName}}, @{
                    L = "preferredCollectorId"; E = {$CollectionID}}, @{
                    L = "hostGroupIds";         E = {0}}, @{
                    L = "customProperties";     E = {('"name":"system.categories","value":"' + $CustomProperties + '"')}}
                )
            }
            $Message = (($Member.SID).Value + "`t" + $Member.Name + "`t" + $Domain + "`t" + $Member.OperatingSystem + "`t" + $IPv4Address + "`t" + $LastChanged + "`t" + $ChangeDate + " | " + $Message)
            Write-Host $Message; $Message | Out-File -FilePath $LogFile -Append
            Start-Sleep -Milliseconds 50
            $iMemberCount ++
            $Error.clear()
        }
    }
}
catch {
    $Error.clear()
}
finally {
    Set-Location -Path $CurrentLocation
    $AddListPSVars = @(
        "EAPreference"
    )
    foreach ($AddVar in $AddListPSVars) {
        $ListPSVars += $AddVar
    }
    Get-Variable * | Remove-Variable -Exclude $ListPSVars -Force -ErrorAction $EAPreference
}