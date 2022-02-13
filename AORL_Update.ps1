[CmdletBinding()]
param (
    [Parameter(Position = 0, Mandatory = $true)][string]$RevisionDate,
    [Parameter(Position = 1, Mandatory = $false)][ValidateSet("DEV","PRD","UAT")][string]$Environment = "UAT",
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
function Test-Date {
param (
    [ValidateScript({
        try {
            [datetime]::ParseExact($PSItem, 'd', [System.Globalization.CultureInfo](Get-Culture))
        }
        catch {
            throw Write-Error -Message "Enter the name of the folder using a short date format: '1/25/2022'" -ErrorAction Stop
        }
    })][string]$date
)
Return $date.Replace("/","-")
}
<#
        This potion of the script will retrieve the latest version of the ProcessCredentials Module. 
    The ProcessCredentials Module will verify the existence of a previously processed key and password 
    file combination.  If either file is missing, the script will generate a new pair. When creating a 
    new key/password file pair, the administrator running this script will be prompted for a valid 
    password for the account being processed.  If a invalid password is entered or the administrator 
    needs to change the existing password, the script can be run again using the "-ResetPassword" 
    parameter.
#>
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
Clear-Host; Clear-History; $Error.Clear()
$EAPreference = "SilentlyContinue"
Import-Module ProcessCredentials
<#
        This potion of the script will generate a search string based on the domain naming convention for 
    administrator accounts. The script is generating this search based on the administrator running this 
    code. The service account that has account management access to the domain being processed will be 
    used to retrieve the SamAccountName for the administrator in the domain where the file server exists.
#>
$GI = (((Get-ADUser -Identity $env:USERNAME).GivenName).SubString(0,1)).ToLower()
$SI = (((Get-ADUser -Identity $env:USERNAME).Surname).SubString(0,4)).ToLower()
$FilterName = ("Name -like 'admin*" + $GI + "*" + $SI + "*'")
$SvcAcctCreds = SetCredentials -SecureUser ("svc_lmdatacllctr@" + $FSDomain) -Domain $FSDomain
if (!($SvcAcctCreds)) {$SvcAcctCreds = Get-Credential -Credential ("svc_lmdatacllctr@" + $FSDomain)}
Set-Variable -Name AdminUser -Value (Get-ADUser -Credential $SvcAcctCreds -Server $FSDomain -Filter $FilterName).SamAccountName
<#
        The administrator will be required to enter their passowrd for accessing the file/web server each time 
    the script is processed. The service account is the only password that will be stored using key/password 
    combination encrytion files. These files will be stored in a secure location in the users local profile.
#>
$FSCredentials = Get-Credential -Credential ($AdminUser + "@" + $FSDomain)
if ($FSCredentials) {
    Set-Variable -Name LocalTempPath -Value ("E:\Temp\" + $FSShare)
    if (!(Test-Path -Path $LocalTempPath)) {
        New-Item -Path $LocalTempPath -ItemType Directory | Out-Null
    }
    else {
        Remove-Item -Path ($LocalTempPath + "\*") -Recurse -Force | Out-Null
    }
    $FolderName = Test-Date $RevisionDate.Replace("-","/")
    if ($FolderName) {
        $FolderYear = RightString $FolderName 4
        $FSFullPath = ("Policy and Procedures\" + $FolderYear + "\" + $FolderName)
        try {
            $PSDrvName = (New-PSDrive -Name "RemoteFS" -PSProvider "FileSystem" -Root $FSSrcShare -Credential $FSCredentials)
            $FilePath = ($PSDrvName.Name + ":\" + $FSFullPath + "\*.zip")
            if (Test-Path -Path $FilePath) {
                Copy-Item -Path $FilePath -Destination $LocalTempPath
            }
            else {
                $eMessage = "Not able to locate files '" + $FSFullPath + "\*.zip' on file server share: [" + $FSSrcShare + "]."
                throw Write-Error -Message $eMessage -ErrorAction Stop
            }
        }
        catch {
            $Error.Clear()
        }
        finally {
            Remove-PSDrive -Name "RemoteFS"
        }
        Set-Variable -Name ContentList -Value @("1gwebhelp","webhelp")
        foreach ($ZipFileName in $ContentList) {
            $LocalZipFile = ($LocalTempPath + "\" + $ZipFileName)
            Expand-Archive -Path ($LocalZipFile + ".zip") -DestinationPath $LocalZipFile -ErrorAction $EAPreference
            Remove-Item -Path ($LocalZipFile + ".zip") -Force -Verbose
        }
        switch ($Environment) {
            "UAT" {
                $eCode = "U"; Break
            }
            "PRD" {
                $eCode = "P"; Break
            }
            Default {
                $eCode = "D"; Break
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
                foreach ($FolderName in $ContentList) {
                    $SrcPath = ($LocalTempPath + "\" + $FolderName)
                    $DestPath = ($PSDrvName.Name + ":\" + $FolderName)
                    Write-Host ("Deleting files from: [" + $DestPath + "].")
                    Remove-Item -Path $DestPath -Recurse -Force | Out-Null
                    Write-Host ("Copying files from: [" + $SrcPath+ "] to [" + $DestPath + "].")
                    Copy-Item -Path $SrcPath -Destination $DestPath -Recurse -Force | Out-Null
                }
                Remove-PSDrive -Name ("WebDest" + $i)
            }
            catch {
                $Error.Clear()
            }
        }
        Remove-Item -Path $LocalTempPath -Recurse -Force | Out-Null
    }
}
Remove-Item -Path $SrcFile -Recurse -Force | Out-Null
