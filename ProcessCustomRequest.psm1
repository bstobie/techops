function Copy-CertificateFile {
    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $true)][string]$ComputerName,
        [parameter(Position = 1, Mandatory = $true)][string]$ComputerDomain,
        [parameter(Position = 2, Mandatory = $true)][string]$ScriptPath
    )
    $CertFile = ($ScriptPath + "\" + $ComputerName + "*.cer")
    $ChainFile = ($ScriptPath + "\" + $ComputerName + "*.rsp")
    Import-Module ProcessCredentials
    $ServerAdmin, $AdminDomain = (Get-AdminAccount -DomainName $ComputerDomain)
    $AdminCreds = SetCredentials -SecureUser ($ServerAdmin + "@" + $AdminDomain) -Domain $AdminDomain
    if (!($AdminCreds)) {
        $AdminCreds = Get-Credential -Credential ($ServerAdmin + "@" + $AdminDomain) -ErrorAction $EAPreference
    }
    Set-Variable -Name HostFQDN -Value $null
    if (!($ComputerName -eq ($ComputerName + "." + $ComputerDomain))) {
        $HostFQDN = ($ComputerName + "." + $ComputerDomain)
    }
    else {
        $HostFQDN = $ComputerName
    }
    $RemoteShare = ("\\" + $HostFQDN + "\C$")
    $PSDrvName = (New-PSDrive -Name ($ComputerName) -PSProvider "FileSystem" -Root $RemoteShare -Credential $AdminCreds)
    Copy-Item -Path $CertFile -Destination ($PSDrvName.Name + ":") -Force | Out-Null
    Copy-Item -Path $ChainFile -Destination ($PSDrvName.Name + ":") -Force | Out-Null
    Remove-PSDrive -Name $PSDrvName
    return 0
}
function Get-AdminAccount {
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
function Install-Certificate {
    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $true)][string]$ComputerName,
        [parameter(Position = 1, Mandatory = $true)][string]$ComputerDomain
    )
    $ServerAdmin, $AdminDomain = (Get-AdminAccount -DomainName $ComputerDomain)
    $AdminCreds = SetCredentials -SecureUser ($ServerAdmin + "@" + $AdminDomain) -Domain $AdminDomain
    if (!($AdminCreds)) {
        $AdminCreds = Get-Credential -Credential ($ServerAdmin + "@" + $AdminDomain) -ErrorAction $EAPreference
    }
    if (!($ComputerName -like ("*.*"))) {
        $HostFQDN = ($ComputerName + "." + $ComputerDomain)
    }
    else {
        $HostFQDN = $ComputerName
    }
    try {
        Invoke-Command -ComputerName $HostFQDN -Credential $AdminCreds -ScriptBlock {
            param ($HostFQDN)
#            Import-Certificate -FilePath ("C:\" + $HostFQDN + ".cer") -CertStoreLocation 'Cert:\LocalMachine\My' -Verbose
            Import-Certificate -FilePath ("C:\" + $HostFQDN + ".rsp") -CertStoreLocation 'Cert:\LocalMachine\My' -Verbose
        } -ArgumentList $HostFQDN
        return 0
    }
    catch {
        $Error.Clear()
        return 1
    }
}
function Set-CustomCertificateRequest {
    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $true)][string]$ComputerName,
        [parameter(Position = 1, Mandatory = $true)][string]$ComputerDomain,
        [parameter(Position = 2, Mandatory = $true)][string]$ScriptPath
    )
    Import-Module ProcessCredentials
    $EAPreference = "SilentlyContinue"
    $ServerAdmin, $AdminDomain = (Get-AdminAccount -DomainName $ComputerDomain)
    $AdminCreds = SetCredentials -SecureUser ($ServerAdmin + "@" + $AdminDomain) -Domain $AdminDomain
    if (!($AdminCreds)) {
        $AdminCreds = Get-Credential -Credential ($ServerAdmin + "@" + $AdminDomain) -ErrorAction $EAPreference
    }
    try {
        Set-Variable -Name PriorLocation -Value (Get-Location)
        Set-Variable -Name HostFQDN -Value $null
        if (!($ComputerName -eq ($ComputerName + "." + $ComputerDomain))) {
            $HostFQDN = ($ComputerName + "." + $ComputerDomain)
        }
        else {
            $HostFQDN = $ComputerName
        }
        $RemoteShare = ("\\" + $HostFQDN + "\C$")
        $PSDrvName = (New-PSDrive -Name ($ComputerName) -PSProvider "FileSystem" -Root $RemoteShare -Credential $AdminCreds)
        Set-Location ($PSDrvName.Name + ":")
        try {
            Set-Variable -Name RequestFor -Value $HostFQDN
            Set-Variable -Name FriendlyName -Value "MECM Client Authentication Certificate"
            $CCRFile = ($PSDrvName.Name + ":\" + $RequestFor + ".*")
            if (Test-Path -Path $CCRFile) {
                Remove-Item -Path $CCRFile -Force -ErrorAction $EAPreference | Out-Null
            }
            Write-Host "Creating Certificate Request(CSR) for $RequestFor `r"
            Invoke-Command -ComputerName $HostFQDN -Credential $AdminCreds -ScriptBlock {
                param ($RequestFor, $FriendlyName)
                $RequestFor = "$($RequestFor)"
                $CSRPath = "C:\$($RequestFor).csr"
                $INFPath = "C:\$($RequestFor).inf"
                $Signature = "`$Windows NT$"
                $INF =
@"
[Version]
Signature= "$Signature"

[NewRequest]
Subject = "CN=$RequestFor, OU=BCOR Administrative Services, O=Blucora Inc, L=Dallas, S=Texas, C=US"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = TRUE
SMIME = False
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0
FriendlyName = "$FriendlyName"

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.2
"@
                $INF | out-file -filepath $INFPath -force
                certreq -new $INFPath $CSRPath
            } -ArgumentList $RequestFor, $FriendlyName
            if (Test-Path -Path $CCRFile) {
                Copy-Item -Path $CCRFile -Destination $ScriptPath -Force | Out-Null
                return 0
            }
            else {
                return 13827
            }
        }
        catch {
            $Error.Clear()
            return 71
        }
    }
    catch {
        $Error.Clear()
        return 1
    }
    finally {
        Set-Location -Path ($PriorLocation) -ErrorAction SilentlyContinue
    }        
}
Export-ModuleMember -Function Copy-CertificateFile
Export-ModuleMember -Function Install-Certificate
Export-ModuleMember -Function Set-CustomCertificateRequest