[CmdletBinding()]
param (
    [Parameter(Position = 0,Mandatory = $false)][string]$CompAcct = "localhost"
)
function Get-LoggedInUser {
    <#
        .SYNOPSIS
            This will check the specified machine to see all users who are logged on.
            For updated help and examples refer to -Online version.
        .NOTES
            Name: Get-LoggedInUser
            Author: Paul Contreras
            Version: 3.0
            DateUpdated: 2021-Sep-21
        .LINK
            https://thesysadminchannel.com/get-logged-in-users-using-powershell/ -
            For updated help and examples refer to -Online version.
        .PARAMETER ComputerName
            Specify a computername to see which users are logged into it.  If no computers are specified, it will default to the local computer.
        .PARAMETER UserName
            If the specified username is found logged into a machine, it will display it in the output.
        .EXAMPLE
            Get-LoggedInUser -ComputerName Server01
            Display all the users that are logged in server01
        .EXAMPLE
            Get-LoggedInUser -ComputerName Server01, Server02 -UserName jsmith
            Display if the user, jsmith, is logged into server01 and/or server02
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][string[]]$ComputerName = $env:COMPUTERNAME,
        [Parameter(Position = 1, Mandatory = $false)][Alias("SamAccountName")][string]$UserName
    )
    begin {}
    process {
        foreach ($Computer in $ComputerName) {
            try {
                $Computer = $Computer.ToLower()
                if (!($Computer -eq "localhost")) {
                    $SessionList = quser /Server:$Computer 2 > $null
                }
                else {
                    $SessionList = quser
                }
                if ($SessionList) {
                    $UserInfo = foreach ($Session in ($SessionList | Select-Object -Skip 1)) {
                        $Session = $Session.ToString().trim() -replace "\s+", " " -replace ">", ""
                        if ($Session.Split(" ")[3] -eq "Active") {
                            [PSCustomObject]@{
                                ComputerName = $Computer
                                UserName     = $session.Split(" ")[0]
                                SessionName  = $session.Split(" ")[1]
                                SessionID    = $Session.Split(" ")[2]
                                SessionState = $Session.Split(" ")[3]
                                IdleTime     = $Session.Split(" ")[4]
                                LogonTime    = $session.Split(" ")[5, 6, 7] -as [string] -as [datetime]
                            }
                        }
                        else {
                            [PSCustomObject]@{
                                ComputerName = $Computer
                                UserName     = $session.Split(" ")[0]
                                SessionName  = $null
                                SessionID    = $Session.Split(" ")[1]
                                SessionState = "Disconnected"
                                IdleTime     = $Session.Split(" ")[3]
                                LogonTime    = $session.Split(" ")[4, 5, 6] -as [string] -as [datetime]
                            }
                        }
                    }
                    if ($PSBoundParameters.ContainsKey("Username")) {
                        $UserInfo | Where-Object {$_.UserName -eq $UserName}
                    }
                    else {
                        $UserInfo | Sort-Object LogonTime
                    }
                }
            }
            catch {
                Write-Error $_.Exception.Message
            }
        }
    }
    end {}
}
Clear-History; Clear-Host
$CurrentFolder = Get-Location
Set-Location ($env:SystemRoot + "\System32")
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
if ([System.Diagnostics.EventLog]::SourceExists("TechOps") -eq $False) {
    New-EventLog -LogName Application -Source "TechOps"
}
Set-Variable -Name LoggedInAdmin -Value $null
do {
    $LoggedInAdmin = $null
    foreach ($Account in $LocalAccounts) {
        if ($Account.SID -like "*-500") {
            $LoggedInAdmin = Get-LoggedInUser -ComputerName $CompAcct -UserName $Account.Name
            if (!($LoggedInAdmin)) {
                try {
                    switch (($PSVersion).Major) {
                        {($_ -eq 5)} {
                            $Account.Name | Disable-LocalUser
                        }
                        Default {
                            $User = Get-WmiObject "Win32_UserAccount" -Filter ("LocalAccount = True AND Name = '" + $Account.Name + "'")
                            $User.Disabled = $True
                            $User.Put()
                        }
                    }
                }
                catch {
                    $Error.Clear()
                }
            }
            else {
                $Message = ("The built-in admin: " + $Account.Name + " is using actively logged in.")
                Write-EventLog -LogName Application -Source "TechOps" -EventID 4673 -EntryType Error -Message $Message -Category 1 -RawData 10,20
            }
        }
    }
} while ($LoggedInAdmin)
Set-Location $CurrentFolder
