[CmdletBinding()]
param (
    [Parameter(Position = 0, Mandatory = $true)][string]$RevisionDate,
    [Parameter(Position = 1, Mandatory = $false)][ValidateSet("DEV", "PRD", "UAT")][string]$Environment = "UAT",
    [parameter(Position = 2, Mandatory = $false)][string]$FileServer = "IRVFILVP01",
    [parameter(Position = 3, Mandatory = $false)][string]$FSShare = "AORL$",
    [parameter(Position = 4, Mandatory = $false)][string]$FSDomain = "irv.hdv.corp",
    [Parameter(Position = 5, Mandatory = $false)][string]$FSSrcShare = ("\\" + $FileServer + "." + $FSDomain + "\" + $FSShare),
    [parameter(Position = 6, Mandatory = $false)][string]$WebSrvDomain = "colo.ext.hdv.corp"
)
<#
        This potion of the script will retrieve the latest version of the ProcessCredentials Module. 
    The ProcessCredentials Module will verify the existence of a previously processed key and password 
    file combination.  If either file is missing, the script will generate a new pair. When creating a 
    new key/password file pair, the administrator running this script will be prompted for a valid 
    password for the account being processed.  If a invalid password is entered or the administrator 
    needs to change the existing password, the script can be run again using the "-ResetPassword" 
    parameter.
#>
Import-Module -Name AdminTools
Import-Module -Name ProcessCredentials
Set-Variable -Name SystemPath -Value ($env:SystemRoot + "\System32")
Set-Variable -Name Robocopy -Value ($SystemPath + "\Robocopy.exe")
Set-Variable -Name PShellPath -Value ($SystemPath + "\WindowsPowerShell\v1.0")
Set-Variable -Name LocalModules -Value ($env:USERPROFILE+"\Documents\WindowsPowerShell\Modules")
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
<#
        This potion of the script will generate a search string based on the domain naming convention for 
    administrator accounts. The script is generating this search based on the administrator running this 
    code. The service account that has account management access to the domain being processed will be 
    used to retrieve the SamAccountName for the administrator in the domain where the file server exists.
#>
$GN = ((Get-ADUser -Identity $env:USERNAME).GivenName)
$GI = (($GN.Replace("admin", "")).Trim()).Substring(0, 1)
$SI = (((Get-ADUser -Identity $env:USERNAME).Surname).SubString(0,4))
$FilterName = ("Name -like 'admin*" + $GI + "*" + $SI + "*'").ToLower()
$SvcAcctCreds = Set-Credentials -SecureUser ("svc_lmdatacllctr@" + $FSDomain) -Domain $FSDomain
if (!($SvcAcctCreds)) {$SvcAcctCreds = Get-Credential -Credential ("svc_lmdatacllctr@" + $FSDomain)}
Set-Variable -Name AdminUser -Value (Get-ADUser -Credential $SvcAcctCreds -Server $FSDomain -Filter $FilterName).SamAccountName
<#
        The administrator will be required to enter their passowrd for accessing the file/web server each time 
    the script is processed. The service account is the only password that will be stored using key/password 
    combination encrytion files. These files will be stored in a secure location in the users local profile.
#>
try {
    $FSCredentials = Get-Credential -Credential ($AdminUser + "@" + $FSDomain)
    if (Test-ADAuthentication -UserName $FSCredentials.UserName -SecureString $FSCredentials.Password) {
        <#
            This potion of the script will create a temporary folder for placing the data that is being 
        transferred from the file server to the web servers.
        #>
        Set-Variable -Name LocalTempPath -Value ("E:\Temp\" + $FSShare)
        if (!(Test-Path -Path $LocalTempPath)) {
            Write-Host ("Creating temporary folder: [" + $LocalTempPath + "].`r`n")
            New-Item -Path $LocalTempPath -ItemType Directory | Out-Null
        }
        else {
            Write-Host ("Emptied temporary folder: [" + $LocalTempPath + "].`r`n")
            Remove-Item -Path ($LocalTempPath + "\*") -Recurse -Force | Out-Null
        }
        $FolderName = Test-Date $RevisionDate.Replace("-","/")
        if ($FolderName) {
            $FolderYear = Get-RightString $FolderName 4
            $FSFullPath = ("Policy and Procedures\" + $FolderYear + "\" + $FolderName)
            try {
                Write-Host ("`nConnecting to file server: [" + $FSSrcShare + "] using credentials: [" + $FSCredentials.UserName + "].`r")
                $PSDrvName = (New-PSDrive -Name "RemoteFS" -PSProvider "FileSystem" -Root $FSSrcShare -Credential $FSCredentials)
                $FilePath = ($PSDrvName.Name + ":\" + $FSFullPath + "\*.zip")
                if (Test-Path -Path $FilePath) {
                    Write-Host ("`tCopying zip files [" + $FilePath + "] to temporary folder: [" + $LocalTempPath + "].`r")
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
                Write-Host ("`tDisconnected from file server: [" + $FSSrcShare + "].`r")
                Remove-PSDrive -Name "RemoteFS"
            }
            Set-Variable -Name ContentList -Value @("1gwebhelp","webhelp")
            foreach ($ZipFileName in $ContentList) {
                $LocalZipFile = ($LocalTempPath + "\" + $ZipFileName)
                Write-Host ("`nExpanding: [" + $LocalZipFile + "] to temporary folder.`r")
                Expand-Archive -Path ($LocalZipFile + ".zip") -DestinationPath $LocalZipFile -ErrorAction $EAPreference
                Remove-Item -Path ($LocalZipFile + ".zip") -Force -Verbose
            }
            <#
                This potion of the script will construct a list of web servers for the environment being processed.
            #>
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
            <#
                This potion of the script will process the destination server list.
            #>
            try {
                foreach ($WebServer in $DestSrvList) {
                    $i = Get-RightString $WebServer 1
                    Set-Variable -Name ContentList -Value @("1gwebhelp","webhelp")
                    $WebSvrShare = ("\\" + $WebServer + "." + $WebSrvDomain + "\" + $FSShare)
                    try {
                        Write-Host ("`nConnected to web server: [" + $WebSvrShare + "] using credentials: [" + $FSCredentials.UserName + "].`r")
                        $PSDrvName = (New-PSDrive -Name ("WebDest" + $i) -PSProvider "FileSystem" -Root $WebSvrShare -Credential $FSCredentials)
                        foreach ($FolderName in $ContentList) {
                            $SrcPath = ($LocalTempPath + "\" + $FolderName)
                            $DestPath = ($PSDrvName.Name + ":\" + $FolderName)
                            Write-Host ("`tDeleting files from: [" + $DestPath + "].`r")
                            Remove-Item -Path $DestPath -Recurse -Force | Out-Null
                            Write-Host ("`tCopying files from: [" + $SrcPath+ "] to [" + $DestPath + "].`r")
                            Copy-Item -Path $SrcPath -Destination $DestPath -Recurse -Force | Out-Null
                        }
                        Write-Host ("`tDisconnected from file server: [" + $WebSvrShare + "].`r")
                    }
                    catch {
                        $Error.Clear()
                    }
                    finally {
                        Remove-PSDrive -Name ("WebDest" + $i)
                    }
                }
            }
            finally {
                if (Test-Path -Path $LocalTempPath) {
                    Remove-Item -Path $LocalTempPath -Recurse -Force | Out-Null
                }
            }
        }
    }
}
finally {
    if (Test-Path -Path $SrcFile) {
        Remove-Item -Path $SrcFile -Recurse -Force | Out-Null
    }
}
