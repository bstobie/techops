[CmdletBinding()]
param(
    [parameter(ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)][string[]]$LogFileNames = @("Collectors"),
    [parameter(ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)][string]$PrimaySiteServer = "SGRVWMECMP10P.corpid.net",
    [parameter(ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)][string]$SiteCode,
    [parameter(ValueFromPipeline = $true)][int]$StartYear = (Get-Date).Year,
	[int]$StartMonth = "{0:00}" -f (Get-Date).Month,
	[int]$StartDay = "{0:00}" -f (Get-Date).Day <#,
	[int]$StartHour = "{0:00}" -f (Get-Date).Hour,
    [int]$StartMinute = "{0:00}" -f (Get-Date).Minute #>
)
$CurrentLocation = Get-Location
$EAPreference = "SilentlyContinue"
[datetime]$StartTime = Get-Date -Format o
Clear-History; Clear-Host; $Error.Clear()
$ScriptPath = $MyInvocation.MyCommand.Definition
$ScriptName = $MyInvocation.MyCommand.Name
[boolean]$bElevated = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Groups -contains "S-1-5-32-544"
function Convert-NormalDateToConfigMgrDate {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true, ValueFromPipeline = $true)][string]$starttime
    )
    return [System.Management.ManagementDateTimeconverter]::ToDMTFDateTime($starttime)
}
function Get-ScheduleToken {
    $SMS_ST_RecurInterval = "SMS_ST_RecurInterval"
    $class_SMS_ST_RecurInterval = [wmiclass]""
    $class_SMS_ST_RecurInterval.psbase.Path = ("\\" + $SMSProvider + "\ROOT\SMS\Site_" + $SiteCode + ":" + $SMS_ST_RecurInterval)
    $script:scheduleToken = $class_SMS_ST_RecurInterval.CreateInstance()
    if ($scheduleToken) {
        $scheduleToken.DayDuration = 0
        $scheduleToken.DaySpan = 1
        $scheduleToken.HourDuration = 0
        $scheduleToken.HourSpan = 0
        $scheduleToken.IsGMT = $false
        $scheduleToken.MinuteDuration = 0
        $scheduleToken.MinuteSpan = 0
        $scheduleToken.StartTime = (Convert-NormalDateToConfigMgrDate $startTime)
    }
}
function Get-SiteCode {
    $wqlQuery = "SELECT * FROM SMS_ProviderLocation"
    $a = Get-WmiObject -Query $wqlQuery -Namespace "root\sms" -ComputerName $SMSProvider
    $a | ForEach-Object {
        if ($_.ProviderForLocalSite) {
            $script:SiteCode = $_.SiteCode
        }
    }
    return $SiteCode
}
if ($bElevated) {
    Set-Variable -Name Repositories -Value @("PSGallery")
    Set-Variable -Name PackageProviders -Value @("Nuget")
    Set-Variable -Name ModuleList -Value @("ConfigurationManager")
    Set-Variable -Name ConfigMgrPath -Value $env:SMS_ADMIN_UI_PATH
    # PowerShell Version (.NetFramework Error Checking) >>>--->
    [int]$PSVersion = ([string]$PSVersionTable.PSVersion.Major + "." + [string]$PSVersionTable.PSVersion.Minor)
    if ($PSVersion -lt 6) {
        Write-Host ("Please be patient while prerequisite modules are installed and loaded.")
        $NugetPackage = Find-PackageProvider -Name $PackageProviders
        if ($NugetPackage.Status -eq "Available") {
            foreach ($Provider in $PackageProviders) {
                $FindPackage = Find-PackageProvider -Name $Provider
                $GetPackage = Get-PackageProvider -Name $Provider
                if ($FindPackage.Version -ne $GetPackage.Version) {
                    Install-PackageProvider -Name $FindPackage.Name -Force -Scope CurrentUser
                }
            }
            foreach ($Repository in $Repositories) {
                Set-PSRepository -Name $Repository -InstallationPolicy Trusted
            }
            foreach ($ModuleName in $ModuleList) {
                $ConfigMgr = Get-WindowsCapability -Name ($ModuleName) -Online | Select-Object -Property Name, State
                if ($ConfigMgr.State -eq "NotPresent") {
                    $ConfigMgrBin = $ConfigMgrPath | Split-Path
                    if (Test-Path -Path $ConfigMgrBin) {
                        Set-Location -Path $ConfigMgrBin
                        Import-Module (".\" + $ModuleName)
                    }
                }
            }
        }
        Write-Host ("The prerequisite modules are now installed and ready to process this script.")
    }
    # Import Windows Update for Powershell module
    Install-Module -Name PSWindowsUpdate -Force | Out-Null
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force -ErrorAction SilentlyContinue
    Import-Module PSWindowsUpdate
    # Process Existing Log Files
    [string]$LogLocation = ($ScriptPath.Replace($ScriptName, "") + "Logs\" + $ScriptName.Replace(".ps1", ""))
    [string]$LogDate = Get-Date -Format "yyyy-MMdd"
    [string[]]$LogFiles = @()
    [int]$intCount = 0
    foreach ($LogFile in $LogFileNames) {
        $intCount ++
        if (Get-Variable -Name ("LogFN$($intCount)") -ErrorAction $EAPreference){
            Remove-Variable -Name "LogFN$($intCount)"
        }
        New-Variable -Name "LogFN$($intCount)" -Value ([string]($LogLocation + "\" + $LogFile + "_"+ $LogDate + ".log"))
        $LogFiles += (Get-Variable -Name "LogFN$($intCount)").Value
    }
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
        if ($FileCount -gt 0) {
            $NewLogFile = ($FileName + "(" + $FileCount + ").log")
            ("Changing the name of this log [" + $FileName + "] to [" + $NewLogFile + "].") | Out-File -FilePath $LogFile -Append
            Rename-Item -Path $LogFile -NewName $NewLogFile
        }
        ("Starting a new log [" + $FileName + "] at [" + $StartTime + "].") | Out-File -FilePath $LogFile
    }
    Clear-History; Clear-Host; $Error.Clear()
    # Script Body >>>--->> Unique code for Windows PowerShell scripting
    $RefreshTypefrom = "2"
    $RefreshTypeto = "2"
    $ScriptRoot = Split-Path -Path $ScriptPath
    $ExclusionList = ($ScriptRoot + "\ExclusionIDs.txt")
    $CollectionsFound = ($ScriptRoot + "\Collections_Inc_Full_" + $LogDate + ".csv")
    ("Attempting to connect to the Primary Site: [" + $PrimaySiteServer + "]") | Out-File -FilePath $LogFile -Append
    $SMSProvider = ($PrimaySiteServer.Split("."))[0]
    if ($SiteCode -eq "") {
        $SiteCode = Get-SiteCode
    }
    $xCollections = @()
    if (Test-Path -Path $ExclusionList) {
        foreach ($xCollection in Get-Content $ExclusionList) {
            $xCollections += $xCollection
        }
    }
    $Connected = Get-PSDrive -Name $SiteCode -ErrorAction $EAPreference
    try {
        if (!($Connected.IsConnected)) {
            New-PSDrive -Name $SiteCode -PSProvider "CMSite" -Root $PrimaySiteServer -Description "Primary site"
        }
        Set-Location ($SiteCode + ":")
        [datetime]$MWstartTime = Get-Date -Day $StartDay -Month $StartMonth -Year $StartYear -Hour 18 -Minute 0 -Second 0 -Millisecond 0
        if ($RefreshTypefrom -ne $RefreshTypeto) {
            Get-CMDeviceCollection | Where-Object {$_.RefreshType -eq $RefreshTypefrom -and $_.CollectionID -notin $xCollections} | Select-Object CollectionID, Name | Export-CSV -NoTypeInformation $CollectionsFound
            $DeviceCollections = Import-Csv -Path $CollectionsFound | Select-Object -ExpandProperty CollectionID
            foreach ($DeviceCollection in $DeviceCollections) {
                #Get the collection details that we want to change the membership (removal of incremental collection)
                $Collection = Get-CMCollection -CollectionId $DeviceCollection
                $Collection.RefreshType = $RefreshTypeto
                $Collection.RefreshSchedule = Get-ScheduleToken $MWstartTime
                $Collection.Put()
                $Message = ("The scheduled refresh on Collection: '" + $Collection.Name + "' was changed from: " + $RefreshTypefrom + " to: " + $RefreshTypeto)
                $Message | Out-File -FilePath $LogFile -Append
            }
        }
        else {
            Get-Command -Module PSWindowsUpdate | Out-Null
            Get-CMDeviceCollection | Where-Object {$_.Name -like "*patching*" -and $_.CollectionID -notin $xCollections} | Select-Object CollectionID, Name | Export-CSV -NoTypeInformation $CollectionsFound
            $DeviceCollections = Import-Csv -Path $CollectionsFound | Select-Object -ExpandProperty CollectionID
            foreach ($DeviceCollection in $DeviceCollections) {
                #Get the collection details that we want to change the membership (removal of incremental collection)
                $Collection = (Get-CMCollectionMember -CollectionId $DeviceCollection).Name
                $Message = ("Checking each device in collection: '" + (Get-CMCollection -CollectionId $DeviceCollection).Name + "'")
                $Message | Out-File -FilePath $LogFile -Append
                foreach ($Member in $Collection) {
                    $Message = ("Checking '" + $Member + "' for Windows Updates.")
                    $Message | Out-File -FilePath $LogFile -Append
                    $WUStatus = Get-WindowsUpdate -ComputerName $Member -IsInstalled -IsAssigned -ErrorAction SilentlyContinue
                    if ($WUStatus) {
                        ("`t" + $WUStatus) | Out-File -FilePath $LogFile -Append
                    }
#                    Install-WindowsUpdate -AcceptAll -AutoReboot
                    $WUReboot = Get-WURebootStatus -ComputerName $Member -ErrorAction SilentlyContinue
                    if ($WUReboot) {
                        ("`t" + $WUReboot) | Out-File -FilePath $LogFile -Append
                    }
                    $WUHistory = Get-WUHistory -ComputerName $Member -Last 7 -ErrorAction SilentlyContinue
                    if ($WUHistory) {
                        ("`t" + $WUHistory) | Out-File -FilePath $LogFile -Append
                    }
                }
            }
        }
    }
    catch {
        $Error.Clear()
        throw Write-Error -Message ("Unable to connect to Primary Site Server using PSDrive.") -ErrorAction Stop
    }
    finally {
        if (Test-Path -Path $CollectionsFound) {
            Remove-Item -Path $CollectionsFound -Force | Out-Null
        }
        Set-Location $CurrentLocation
        Remove-PSDrive -Name $SiteCode
    }
    # Script Body <<---<<< Unique code for Windows PowerShell scripting
}
else {
    Set-Location $CurrentLocation
}
Remove-Variable -Name * -ErrorAction $EAPreference
