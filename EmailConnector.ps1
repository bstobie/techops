[CmdletBinding()]
param (
    [parameter(Position = 0, Mandatory = $false)][bool]$bTesting = $true,
    [parameter(Position = 1, Mandatory = $false)][string]$sUsername = "svc_lmdatacllctr",
    [parameter(Position = 2, Mandatory = $false)][string]$sDomain = ("bcor.onmicrosoft.com"),
    [parameter(Position = 3, Mandatory = $false)][bool]$bReset = $false
)
$ActionPref = "SilentlyContinue"
Import-Module -Name .\Modules\ProcessCredentials
Set-Variable -Name StartFolder -Value (Get-Location).Path
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
Set-Variable -Name ScriptName -Value ($MyInvocation.MyCommand.Name)
Set-Variable -Name ScriptPath -Value (Split-Path -Path ($MyInvocation.MyCommand.Definition))
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
Install-PackageProvider -Name "NuGet" -Force -WarningAction $ActionPref | Out-Null
Install-Module -Name PowerShellGet -AllowClobber -Force -WarningAction $ActionPref | Out-Null
Set-Variable -Name Modules -Value @("Microsoft.Graph","AzureAD")
foreach ($Module in $Modules) {
    try {
        Install-module -Name $Module -Scope AllUsers -Force | Out-Null
        Get-InstalledModule $Module
    }
    catch {
        $Error.Clear()
    }
}
Set-Variable -Name AzureUser -Value ($sUsername).ToLower()
Set-Variable -Name AzureDomain -Value ($sDomain).ToLower()
if ($bTesting) {
    $AzureUser = "Bob.Stobie"
    $AzureDomain = "avantax.com"
}
$AzureUserDomain = ($AzureUser + "@" + $AzureDomain)
$AzureUserCredential = Set-Credentials -SecureUser ($AzureUserDomain) -Domain $AzureDomain -ResetPassword $bReset
if (!($AzureUserCredential)) {
    $AzureUserCredential = Get-Credential -Credential ($AzureUserDomain) -Message ("Enter your credentials:")
}
try {
    Connect-AzureAD -Credential $AzureUserCredential
}
catch {
    $Error.Clear()
}
finally {
    Set-Location -Path $StartFolder
}