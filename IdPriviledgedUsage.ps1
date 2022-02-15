[CmdletBinding()]
param (
    [Parameter(Position=0,Mandatory=$false)][string]$ThycoticUser = "blusys",
    [Parameter(Position=1,Mandatory=$false)][decimal]$TimeDelay = 1,
    [Parameter(Position=2,Mandatory=$false)][string]$CompAcct = "localhost"
)
Clear-History; Clear-Host
$CurrentFolder = Get-Location
Set-Location ($env:SystemRoot + "\System32")
Set-Variable -Name LocalAdmin -Value $null
Set-Variable -Name LocalAccounts -Value @()
Set-Variable -Name LocalServices -Value @()
Set-Variable -Name ListWebApps -Value @()
Set-Variable -Name AppPoolUser -Value $null
Set-Variable -Name UserDescription -Value "Local user account for Thycotic - Secret Server"
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
[bool]$bFound = $false
foreach ($Account in $LocalAccounts) {
    if ($Account.SID -like "*-500") {
        $LocalAdmin = $Account.Name
    }
    if ($Account.Name -eq $ThycoticUser) {
        $bFound = $true
    }
}
if (!($bFound)) {
    $minLength = 16
    $maxLength = 28
    $nonAlphaChars = 5
    $length = Get-Random -Minimum $minLength -Maximum $maxLength
    try {
        add-type -AssemblyName System.Web
        $AccountPass = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
        $SecurePass = ConvertTo-SecureString -String $AccountPass -AsPlainText -Force
        switch (($PSVersion).Major) {
            {($_ -eq 5)} {
                New-LocalUser -Name $ThycoticUser -Password $SecurePass -FullName "Secret Server" -Description $UserDescription | Out-Null
                Add-LocalGroupMember -Group "Administrators" -Member $ThycoticUser
                Break
            }
            Default {
                $group = "Administrators"
                $currentName = hostname
                $objOu = [ADSI]"WinNT://$currentName"
                $objUser = $objOU.Create("User", $ThycoticUser)
                $objUser.setpassword($AccountPass)
                Clear-Variable -Name "AccountPass"
                $objUser.SetInfo()
                $objUser.description = $UserDescription
                $objUser.SetInfo()
                $objOU = [ADSI]"WinNT://$currentName/$group"
                $objOU.add("WinNT://$currentName/$($ThycoticUser)")
                Break
            }
        }
    }
    catch {
       $Error.Clear()
    }
    finally {
        Clear-Variable -Name "AccountPass"
        $bFound = $true
    }
}
$WebApps = (Get-Module -ListAvailable webadmin*).Name
if ($WebApps) {
    Import-Module WebAdministration | Out-Null
}
if ([System.Diagnostics.EventLog]::SourceExists("TechOps") -eq $False) {
    try {
        New-EventLog -LogName Application -Source "TechOps"
    }
    catch {
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
        try {
            Write-EventLog -LogName Application -Source "TechOps" -EventID 4673 -EntryType Error -Message $Message -Category 1 -RawData 10,20
        }
        catch {
            $Error.Clear()
        }
    }
    else {
        Write-Host ("No errors found on " + ($env:COMPUTERNAME + "." + $env:USERDNSDOMAIN).ToLower())
        if ($AppPoolUser -eq "") {
            Break
        }
    }
    if ($TimeDelay -gt 0) {
        [float]$Delay = $TimeDelay * 60
        Start-Sleep -Seconds $Delay
    }
} while (($LocalServices) -and ($AppPoolUser -eq ""))
Set-Location $CurrentFolder
