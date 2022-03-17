[CmdletBinding()]
param (
    [parameter(Position = 0, Mandatory = $false)][string]$CADomain = "corpid.net"
)
function Get-AdminUserName {
    param (
        [parameter(Position = 0, Mandatory = $true)][string]$DomainName
    )
    $GN = ((Get-ADUser -Identity $env:USERNAME).GivenName).ToLower()
    $SN = (Get-ADUser -Identity $env:USERNAME).Surname
    Set-Variable -Name ShortName -Value $null
    if ($GN -like "admin*") {
        $GN = ($GN.Replace("admin", ""))
    }
    $GN = ($GN.Trim()).Substring(0, 1).ToUpper() + (($GN.Replace("admin", "")).Trim()).Substring(1)
    [string]$FullName = ($GN + "." + $SN)
    [string]$UserName = (($GN[0]) + $SN)
    [string]$TrimName = ($UserName).Substring(0,5)
    if ($DomainName -like "*.*") {
        switch ($DomainName.ToLower()) {
            {($_ -eq "1stglobal.com")}  {$ServerAdmin = ("a_" + $UserName).ToLower();       Break}
            {($_ -eq "bcor.ad")}        {$ServerAdmin = ($UserName + "x").ToLower();        Break}
            {($_ -eq "bcor.it")}        {$ServerAdmin = ("admin_" + $TrimName).ToLower();   Break}
            {($_ -eq "corpid.net")}     {$ServerAdmin = ("DA-" + $FullName).ToLower();      Break}
            {($_ -eq "hdv.corp")}       {$ServerAdmin = ($UserName + "x").ToLower();        Break}
            {($_ -eq "taxact.com")}     {$ServerAdmin = ("admin_" + $TrimName).ToLower();   Break}
            default {
                $ServerAdmin = ("admin_" + $TrimName).ToLower()
                $DomainName = "irv.hdv.corp"
                Break
            }
        }
    }
    else {
        switch ($DomainName) {
            {($_ -eq "1STGLOBAL")}  {$ServerAdmin = ("a_" + $UserName).ToLower();       $DomainName = "1stglobal.com";  Break}
            {($_ -eq "BCOR")}       {$ServerAdmin = ($UserName + "x").ToLower();        $DomainName = "bcor.ad";        Break}
            {($_ -eq "BCORIT")}     {$ServerAdmin = ("admin_" + $TrimName).ToLower();   $DomainName = "bcor.it";        Break}
            {($_ -eq "CORPID")}     {$ServerAdmin = ("DA-" + $FullName).ToLower();      $DomainName = "corpid.net";     Break}
            {($_ -eq "HDVCORP")}    {$ServerAdmin = ($UserName + "x").ToLower();        $DomainName = "hdv.corp";       Break}
            {($_ -eq "TAXACT")}     {$ServerAdmin = ("admin_" + $TrimName).ToLower();   $DomainName = "taxact.com";     Break}
            default {
                $ServerAdmin = ("admin_" + $TrimName).ToLower()
                $DomainName = "irv.hdv.corp"
                Break
            }
        }
    }
    return $ServerAdmin, $DomainName
}
function Get-CertificateRequestFile {
    param (
        [string]$InitialDirectory = $PSScriptRoot
    )
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    $ShowDialog = New-Object System.Windows.Forms.OpenFileDialog
    $ShowDialog.InitialDirectory = $InitialDirectory
    $ShowDialog.Filter = "CSR File (*.csr)|*.csr|Request File (*.req)|*.req|Text File (*.txt)|*.txt|All Files (*.*)|*.*"
    $ShowDialog.ShowDialog() | Out-Null
    return $ShowDialog.FileName
}
function Get-CertificateTemplates {
    $script:IssuingCA = certutil -config - -ping
    $script:IssuingCA = $script:IssuingCA | Where-Object { ($_ -match '\\') -and ($_ -notmatch 'Connecting')}
    $TemplateList = certutil -CATemplates -config $script:IssuingCA
    return $TemplateList
}
function Get-HostDomain {
    param (
        [parameter(Position = 0, Mandatory = $true)][string]$DomainName
    )
    switch ($DomainName) {
        {($_ -eq "1STGLOBAL")}  {$DomainName = "1stglobal.com";     Break}
        {($_ -eq "BCOR")}       {$DomainName = "bcor.ad";           Break}
        {($_ -eq "BCORIT")}     {$DomainName = "bcor.it";           Break}
        {($_ -eq "COLO")}       {$DomainName = "colo.ext.hdv.corp"; Break}
        {($_ -eq "CORPID")}     {$DomainName = "corpid.net";        Break}
        {($_ -eq "HDV")}        {$DomainName = "hdvest.com";        Break}
        {($_ -eq "HDVCORP")}    {$DomainName = "hdv.corp";          Break}
        {($_ -eq "HDVEXT")}     {$DomainName = "ext.hdv.corp";      Break}
        {($_ -eq "IRV")}        {$DomainName = "irv.hdv.corp";      Break}
        {($_ -eq "TAXACT")}     {$DomainName = "taxact.com";        Break}
    }
    return $DomainName
}
function Test-ADAuthentication {
    param (
        $UserName,
        $SecureString
    )
    $BSTR=[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    $UnEncrypted=[System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    $null -ne (New-Object System.DirectoryServices.DirectoryEntry "", $UserName, $UnEncrypted).psbase.name
    Remove-Variable -Name UnEncrypted -Force -ErrorAction SilentlyContinue
}
$ListPSVars = Get-Variable -Exclude ("CADomain") | Select-Object -ExpandProperty Name
$Error.Clear(); Clear-History; Clear-Host
$ScriptPath = Split-Path -Path ($MyInvocation.MyCommand.Definition)
$EAPreference = "SilentlyContinue"
$ServerAdmin, $AdminDomain = (Get-AdminUserName -DomainName $CADomain)
Import-Module ProcessCredentials
Import-Module ProcessCustomRequest
Set-Variable -Name AdminCreds -Value $null
Set-Variable -Name DeviceList -Value @("")
Set-Variable -Name IssuingCA -Value (certutil -config - -ping)[0]
Set-Variable -Name TemplateName -Value "Corpid.net-MECMClientCertificate-Request"
Set-Variable -Name RemoteCCRs -Value ($ScriptPath + "\RemoteCCRs")
if (!(Test-Path -Path $RemoteCCRs)) {
    New-Item -Path $RemoteCCRs -ItemType Directory | Out-Null
}
try {
    $AdminCreds = SetCredentials -SecureUser ($ServerAdmin + "@" + $AdminDomain) -Domain $AdminDomain
    if (!($AdminCreds)) {
        $AdminCreds = Get-Credential -Credential ($ServerAdmin + "@" + $AdminDomain) -ErrorAction $EAPreference
    }
    if (Test-ADAuthentication -UserName $AdminCreds.UserName -SecureString $AdminCreds.Password) {
        $CollectionPath = ($ScriptPath + "\Collections")
        if (Test-Path -Path $CollectionPath) {
            foreach ($DeviceCollections in Get-ChildItem -Path $CollectionPath) {
                if ($DeviceCollections.Extension -eq ".csv") {
                    $DeviceList = Import-Csv -Path $DeviceCollections.FullName
                    foreach ($DeviceInfo in $DeviceList) {
                        $RemoteHost = ($DeviceInfo."Computer Name").ToUpper()
                        $HostDomain = (Get-HostDomain -DomainName $DeviceInfo."Domain Name")
                        $RequestFile = Set-CustomCertificateRequest -ComputerName $RemoteHost -ComputerDomain $HostDomain -ScriptPath $RemoteCCRs
                        if ($RequestFile -like "*" + 0) {
                            foreach ($RequestFile in Get-ChildItem -Path $RemoteCCRs) {
                                if ($RequestFile -like ($RemoteHost + "*.csr")) {
                                    $SaveAs = ($RequestFile.FullName).Replace("csr","cer")
                                    Break
                                }
                            }
                            if ($RequestFile.FullName -like "*.csr") {
                                try {
                                    $EnrollResult = certreq -submit -config $IssuingCA -attrib ("CertificateTemplate:" + $TemplateName) $RequestFile.FullName $SaveAs
                                    if ($EnrollResult -like "*Certificate retrieved(Issued) Issued") {
                                        Write-Host ($EnrollResult[1] + " for hostname: " + $RemoteHost)
                                        $Results = Copy-CertificateFile -ComputerName $RemoteHost -ComputerDomain $HostDomain -ScriptPath $RemoteCCRs
                                        if ($Results -eq 0) {
                                            Write-Host ("Placed certificate for $RemoteHost on the devices system drive.")
                                            $Results = Install-Certificate -ComputerName $RemoteHost -ComputerDomain $HostDomain
                                            Write-Host $Results
                                        }
                                    }
                                }
                                catch {
                                    $Message = ("Error while attempting to request certificate from: " + $IssuingCA + " using the template: " + $TemplateName + ".")
                                    Write-Host $Message
                                    $Error.Clear()
                                }
                            }
                        }
                        $Error.Clear(); Clear-History; Clear-Host
                    }
                }
            }
        }
        else {
            $RequestFile = Set-CustomCertificateRequest -ComputerName ($env:COMPUTERNAME).ToUpper() -ComputerDomain ($env:USERDNSDOMAIN).ToLower()
        }
    }
    else {
        $Message = ("Failed to authenticate to " + $CADomain + " with username: " + $ServerAdmin + ".  Error message: 'password not validated'.")
        Write-Host $Message
        $Error.Clear()
    }
}
catch {
    $Error.Clear()
}
finally {
    $AddListPSVars = @(
        "MaximumHistoryCount", "NestedPromptLevel", "OutputEncoding", "profile", "ProgressPreference", "PSCulture",
        "PSDefaultParameterValues", "psEditor", "PSEmailServer", "PSSessionApplicationName", "PSSessionConfigurationName",
        "PSSessionOptions", "PSUICulture", "PWD", "StackTrace", "VerbosePreference", "WarningPreference", "WhatIfPreference"
    )
    foreach ($AddVar in $AddListPSVars) {
        $ListPSVars += $AddVar
    }
    Get-Variable * | Remove-Variable -Exclude $ListPSVars -Force -ErrorAction SilentlyContinue
}