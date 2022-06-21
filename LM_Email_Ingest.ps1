<# http://www.garrettpatterson.com/2014/04/18/checkread-messages-exchangeoffice365-inbox-with-powershell/ #>
# Check/Read Messages Exchange/Office365 Inbox with Powershell
[CmdletBinding()]
param(
    [parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][bool[]]$AdminPwdReset=$false
)
Set-Location -Path ($env:SystemRoot+"\System32")
$SystemPath = Get-Location
Clear-History; Clear-Host
Install-module -name MSOnline
Install-Module -Name AzureAD
$ScriptName = ($MyInvocation.MyCommand.Name).Replace(".ps1","")
$ScriptPath = ($MyInvocation.MyCommand.Definition).Replace("\"+$ScriptName+".ps1","")
Set-Variable -Name PShellPath -Value ($SystemPath.Path+"\WindowsPowerShell\v1.0")
Set-Variable -Name LocalModules -Value ($PShellPath+"\Modules")
$LocalCredsPath = ($env:USERPROFILE+"\AppData\Local\Credentials")
Set-Variable -Name DllName -Value "Microsoft.Exchange.WebServices.dll"
Set-Variable -Name DllPath -Value ($env:ProgramFiles+"\Microsoft\Exchange\Web Services\2.2")
if ($AdminPwdReset) {
    if (Test-Path -Path $LocalCredsPath) {
        Remove-Item $LocalCredsPath -Recurse -Force | Out-Null
        if (Test-Path ($LocalModules+"\ProcessCredentials")) {
            Remove-Item ($LocalModules+"\ProcessCredentials") -Recurse -Force | Out-Null
        }
    } else {
        $AdminPwdReset=$false
    }
}
if (!(Test-Path ($LocalModules+"\ProcessCredentials"))) {
    New-Item -Path ($LocalModules+"\ProcessCredentials") -ItemType Directory | Out-Null
}
if (!(Test-Path -Path ($DllPath+"\"+$DllName))) {
    if (!(Test-Path -Path $DllPath)) {
        New-Item -Path $DllPath -ItemType Directory -Force | Out-Null
    }
    Copy-Item -Path ($ScriptPath+"\"+$DllName) -Destination $DllPath -Force | Out-Null
}
if (!($ScriptPath -eq "C:\Scripts\EmailProcessing")) {
    if (Test-Path -Path ($ScriptPath+"\Modules\ProcessCredentials")) {
        Copy-Item -Path ($ScriptPath+"\Modules\ProcessCredentials\*.*") -Destination ($LocalModules+"\ProcessCredentials") -Force | Out-Null
        Remove-Item ($ScriptPath+"\Modules") -Recurse -Force | Out-Null
    }
    if (Test-Path -Path ($ScriptPath+"\"+$DllName)) {
        Remove-Item -Path ($ScriptPath+"\"+$DllName) -Force | Out-Null
    }
}
Import-Module ProcessCredentials
Set-Variable -Name EmailUser -Value "svc_lmdatacllctr"
Set-Variable -Name EmailDomain -Value "bcor.onmicrosoft.com"
$EmailCredentials = SetCredentials -SecureUser $EmailUser -Domain $EmailDomain
$EmailUserDomain = ($EmailUser+"@"+$EmailDomain)
If(!($EmailCredentials)){$EmailCredentials=get-credential}
$BSTR=[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($EmailCredentials.Password)
$SrvAcctPwd=[System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
$SecureString = ConvertTo-SecureString $SrvAcctPwd -AsPlainText -Force
$EmailUserCreds = New-Object System.Management.Automation.PSCredential $EmailUserDomain, $SecureString
$SrvAcctPwd = $null; $BSTR = $null
Connect-MsolService -Credential $EmailUserCreds
Connect-AzureAD -Credential $EmailUserCreds | Out-Null
# Search filter for Un-read messages in the Inbox
Set-Variable -Name ErrorFolder -Value "Errors"
Set-Variable -Name ProcessFolder -Value "Processed"
Set-Variable -Name inboxfilter -Value $null
Set-Variable -Name FromAddress -Value @(
    "automate-prod-a@hdvest.com",
    "autopager@hdvest.com",
    "dataservices@hdvest.com",
    "diplomatadmin@hdvprod.net",
    "noreply@hdvest.com",
    "noreply-protegent@fisglobal.com"
)
Set-Variable -Name OriginalSender -Value $false
Set-Variable -Name SubjectFilter -Value @(
    "error",
    "trigger error",
    "failure",
    "job execution failures",
    "failed status"
)
Set-Variable -Name BodySearch -Value @(
    "status:*failed"
)
Set-Variable -Name SubjectExclusion -Value @(
    "failures report"
)
Set-Variable -Name SubjectMatch -Value $false
# Connect to the Inbox
Set-Variable -Name FullPathEWS -Value ($DllPath+"\"+$DllName)
[void][Reflection.Assembly]::LoadFile($FullPathEWS)
$s = new-object Microsoft.Exchange.WebServices.Data.ExchangeService
$s.Credentials = New-Object Microsoft.Exchange.WebServices.Data.WebCredentials($EmailUserCreds)
$s.Url = new-object Uri("https://outlook.office365.com/EWS/Exchange.asmx");
$inbox = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($s,[Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Inbox)
# Find Folder for Errors Messages
$fv = new-object Microsoft.Exchange.WebServices.Data.FolderView(20)
$fv.Traversal = "Deep"
$effname = new-object Microsoft.Exchange.WebServices.Data.SearchFilter+ContainsSubstring([Microsoft.Exchange.WebServices.Data.FolderSchema]::DisplayName,$ErrorFolder)
$efolders = $s.findFolders([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::MsgFolderRoot,$effname, $fv)
$ErrorsFolder = $efolders.Folders[0]
# Find Folder for Processed Messages
$pffname = new-object Microsoft.Exchange.WebServices.Data.SearchFilter+ContainsSubstring([Microsoft.Exchange.WebServices.Data.FolderSchema]::DisplayName,$ProcessFolder)
$pfolders = $s.findFolders([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::MsgFolderRoot,$pffname, $fv)
$ProcessedFolder = $pfolders.Folders[0]
# Read and process emails
$PropertySet = New-Object Microsoft.Exchange.WebServices.Data.PropertySet([Microsoft.Exchange.WebServices.Data.BasePropertySet]::FirstClassProperties)
$PropertySet.RequestedBodyType = [Microsoft.Exchange.WebServices.Data.BodyType]::Text;
$numOfEmailsToRead = 10
$index = 0
do {
    $view = New-Object Microsoft.Exchange.WebServices.Data.ItemView($numOfEmailsToRead,$index)
    $findResults = $s.FindItems($inbox.Id, $view)
    foreach ($mailitem in $findResults.Items) {
        $OriginalSender = $false
        $SubjectMatch = $false
        $mailitem.Load($propertySet)
        write-host "From: $($mailitem.From.Name)"
        write-host "Address: $($mailitem.From.Address)"
        write-host "Subject: $($mailitem.Subject)"
        write-host "State: $($mailitem.IsRead)"
        write-host "Body: $($mailitem.Body)"
        foreach ($FromName in $FromAddress) {
            if ($FromName -eq $mailitem.From.Address) {
                $OriginalSender = $true
                break
            }
        }
        foreach ($SFilter in $SubjectFilter) {
            if ($mailitem.Subject.ToLower() -like ("*"+$SFilter+"*")) {
                foreach ($Exclude in $SubjectExclusion) {
                    if ($mailitem.Subject.ToLower() -like ("*"+$Exclude+"*")) {
                        $SubjectMatch = $false
                        foreach ($SBody in $BodySearch) {
                            if ($mailitem.Body.ToString() -like ("*"+$SBody+"*")) {
                                $SubjectMatch = $true
                                break
                            }
                        }
                        break
                    } else {
                        $SubjectMatch = $true
                    }
                }
                break
            }
        }
        if (($SubjectMatch) -and ($OriginalSender)) {
            # move message to previously located destination folder.
            $mailitem.IsRead = $false
            $mailitem.Update([Microsoft.Exchange.WebServices.Data.ConflictResolutionMode]::AutoResolve)
            [VOID]$mailitem.Move($ErrorsFolder.Id)
            write-host ("Moved ("+$mailitem.Subject+": ["+$mailitem.DateTimeReceived+"]) to '"+$ErrorsFolder.Id+"'")
        } else {
            $mailitem.IsRead = $true
            $mailitem.Update([Microsoft.Exchange.WebServices.Data.ConflictResolutionMode]::AutoResolve)
            [VOID]$mailitem.Move($ProcessedFolder.Id)
            write-host "Marked as read"
        }
        write-host ""
    }
    $index += $numOfEmailsToRead
} while ($findResults.MoreAvailable) # Do/While there are more emails to process
Disconnect-AzureAD
Set-Location -Path ($env:SystemRoot+"\System32")