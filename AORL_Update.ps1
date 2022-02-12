[CmdletBinding()]
param (
    [Parameter(Position = 0, Mandatory = $false)][string]$RevisionDate = "1-25-2022",
    [Parameter(Position = 1, Mandatory = $false)][string]$Environment = "UAT",
    [parameter(Position = 2, Mandatory = $false)][string]$FileServer = "IRVFILVP01",
    [parameter(Position = 3, Mandatory = $false)][string]$FSShare = "AORL$",
    [parameter(Position = 4, Mandatory = $false)][string]$FSDomain = "irv.hdv.corp",
    [Parameter(Position = 5, Mandatory = $false)][string]$FSSrcShare = ("\\" + $FileServer + "." + $FSDomain + "\" + $FSShare),
    [parameter(Position = 6, Mandatory = $false)][string]$WebSrvDomain = "colo.ext.hdv.corp"
)
function RightString {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory=$True)][String]$DateString,
        [Parameter(Position = 1, Mandatory=$True)][Int]$Length
    )
    $startchar = [math]::min($DateString.length - $Length, $DateString.length)
    $startchar = [math]::max(0, $startchar)
    $right = $DateString.SubString($startchar, [math]::min($DateString.length, $Length))
    Return $right    
}
Set-Location -Path ($env:SystemRoot + "\System32")
Set-Variable -Name Robocopy -Value (".\Robocopy.exe")
Set-Variable -Name PShellPath -Value (".\WindowsPowerShell\v1.0")
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
Set-Variable -Name Options -Value ($FileName + " /R:2 /W:5")
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
Clear-Host; Clear-History; $Error.Clear()
$EAPreference = "SilentlyContinue"
Import-Module ProcessCredentials
$GI = (((Get-ADUser -Identity $env:USERNAME).GivenName).SubString(0,1)).ToLower()
$SI = (((Get-ADUser -Identity $env:USERNAME).Surname).SubString(0,4)).ToLower()
$FilterName = ("Name -like 'admin*" + $GI + "*" + $SI + "*'")
$SvcAcctCreds = SetCredentials -SecureUser ("svc_lmdatacllctr@" + $FSDomain) -Domain $FSDomain
if (!($SvcAcctCreds)) {$SvcAcctCreds = Get-Credential -Credential ("svc_lmdatacllctr@" + $FSDomain)}
Set-Variable -Name AdminUser -Value (Get-ADUser -Credential $SvcAcctCreds -Server $FSDomain -Filter $FilterName).SamAccountName
$FSCredentials = Get-Credential -Credential ($AdminUser + "@" + $FSDomain)
if ($FSCredentials) {
    Set-Variable -Name LocalTempPath -Value ("E:\Temp\" + $FSShare)
    if (!(Test-Path -Path $LocalTempPath)) {
        New-Item -Path $LocalTempPath -ItemType Directory | Out-Null
    }
    $FolderYear = RightString $RevisionDate 4
    $FSFullPath = ("Policy and Procedures\" + $FolderYear + "\" + $RevisionDate)
    try {
        $PSDrvName = (New-PSDrive -Name "RemoteFS" -PSProvider "FileSystem" -Root $FSSrcShare -Credential $FSCredentials)
        $FilePath = ($PSDrvName.Name + ":\" + $FSFullPath + "\*.zip")
        Copy-Item -Path $FilePath -Destination $LocalTempPath
    }
    catch {
        $Error.Clear()
    }
    finally {
        Remove-PSDrive -Name "RemoteFS"
    }
    switch ($Environment) {
        "UAT" {
            $eCode = "U"; Break
        }
        Default {
            $eCode = "P"; Break
        }
    }
    Set-Variable -Name DestSrvList -Value @()
    for ($i = 3; $i -le 6; $i++) {
        New-Variable -Name "DestServer$($i)" -Value ([string]("DFWWEBV" + $eCode + "0" + $i))
        $DestSrvList+=(Get-Variable -Name "DestServer$($i)").Value
        Remove-Variable -Name "DestServer$($i)"
    }
    foreach ($WebServer in $DestSrvList) {
        $i = RightString $WebServer 1
        Set-Variable -Name ContentList -Value @("1gwebhelp","webhelp")
        $WebSvrShare = ("\\" + $WebServer + "." + $WebSrvDomain + "\" + $FSShare)
        try {
            $PSDrvName = (New-PSDrive -Name ("WebDest" + $i) -PSProvider "FileSystem" -Root $WebSvrShare -Credential $FSCredentials)
            foreach ($ZipFileName in $ContentList) {
                $WSFullPath = ($PSDrvName.Name + ":\" + $ZipFileName)
                if (Test-Path -Path $WSFullPath) {
                    Remove-Item -Path $WSFullPath -Recurse -Force -Verbose
                }
                Expand-Archive -Path ($LocalTempPath + "\" + $ZipFileName + ".zip") -DestinationPath $WSFullPath -ErrorAction $EAPreference
            }
            Remove-PSDrive -Name ("WebDest" + $i)
        }
        catch {
            $Error.Clear()
        }
    }
    Remove-Item -Path $LocalTempPath -Recurse -Force | Out-Null
}
Remove-Item -Path $SrcFile -Recurse -Force | Out-Null
