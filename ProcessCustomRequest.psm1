Import-Module -Name AdminTools
function Copy-CertificateFile {
    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $true)][string]$ComputerName,
        [parameter(Position = 1, Mandatory = $true)][string]$ComputerDomain,
        [parameter(Position = 2, Mandatory = $true)][string]$ScriptPath
    )
    $CertFile = ($ScriptPath + "\" + $ComputerName + ".cer")
    $ChainFile = ($ScriptPath + "\" + $ComputerName + ".rsp")
    $ServerAdmin, $AdminDomain = (Get-SvcAcctName -DomainName $ComputerDomain)
    if ($ComputerName -like ("*.*")) {
        $ComputerName = $ComputerName.Split(".")[0]
    }
    $HostFQDN = ($ComputerName + "." + $ComputerDomain)
    $RemoteShare = ("\\" + $HostFQDN + "\C$")
    $PSDrvName = (New-PSDrive -Name ($ComputerName) -PSProvider "FileSystem" -Root $RemoteShare -Credential $ServerAdmin)
    Copy-Item -Path $CertFile -Destination ($PSDrvName.Name + ":") -Force | Out-Null
    Copy-Item -Path $ChainFile -Destination ($PSDrvName.Name + ":") -Force | Out-Null
    Remove-PSDrive -Name $PSDrvName
    return 0
}
function Get-MyCertStore {
    param (
        [parameter(Position = 0, Mandatory = $true)][string]$ComputerName,
        [parameter(Position = 1, Mandatory = $true)][string]$ComputerDomain
    )
    $ServerAdmin, $AdminDomain = (Get-SvcAcctName -DomainName $ComputerDomain)
    if ($ComputerName -like ("*.*")) {
        $ComputerName = $ComputerName.Split(".")[0]
    }
    $HostFQDN = ($ComputerName + "." + $ComputerDomain)
    try {
        $Results = Invoke-Command -ComputerName $HostFQDN -Credential $ServerAdmin -ScriptBlock {
            Get-ChildItem -Path cert:\LocalMachine\My | Select-Object FriendlyName
        }
        return $Results
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
    $EAPreference = "SilentlyContinue"
    $ServerAdmin, $AdminDomain = (Get-SvcAcctName -DomainName $ComputerDomain)
    try {
        Set-Variable -Name PriorLocation -Value (Get-Location)
        Set-Variable -Name HostFQDN -Value $null
        if ($ComputerName -like ("*.*")) {
            $ComputerName = $ComputerName.Split(".")[0]
        }
        $HostFQDN = ($ComputerName + "." + $ComputerDomain)
        $Results = Test-NetConnection -ComputerName $HostFQDN -CommonTCPPort SMB
        if ($Results.TcpTestSucceeded) {
            $RemoteShare = ("\\" + $HostFQDN + "\C$")
            $PSDrvName = (New-PSDrive -Name ($ComputerName) -PSProvider "FileSystem" -Root $RemoteShare -Credential $ServerAdmin)
            Set-Location ($PSDrvName.Name + ":") -ErrorAction Stop
            try {
                $Results = Get-MyCertStore -ComputerName $ComputerName -ComputerDomain $ComputerDomain
                if (!($Results.FriendlyName -like "MECM Client*")) {
                    Set-Variable -Name RequestFor -Value $HostFQDN
                    Set-Variable -Name FriendlyName -Value "MECM Client Authentication Certificate"
                    $CCRFile = ($PSDrvName.Name + ":\" + $RequestFor + ".*")
                    if (Test-Path -Path $CCRFile) {
                        Remove-Item -Path $CCRFile -Force -ErrorAction $EAPreference | Out-Null
                    }
                    Start-Sleep -Seconds 5
                    $Results = Test-NetConnection -ComputerName $HostFQDN -CommonTCPPort WINRM
                    if ($Results.TcpTestSucceeded) {
                        Write-Host "Creating Certificate Request(CSR) for $RequestFor `r"
                        Start-Sleep -Seconds 5
                        Invoke-Command -ComputerName $HostFQDN -Credential $ServerAdmin -ScriptBlock {
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
                            return ("CSR transfer complete.")
                        }
                        else {
                            Write-Host ("ERROR:`tFailed to connect to " + $HostFQDN + " due to Kerberos Authentication error.")
                            return 13827
                        }
                    }
                    else {
                        Write-Host ("WARNING:`tFailed to connect to " + $HostFQDN + " using WinRM.")
                        return 1
                    }
                }
                else {
                    Write-Host ($ComputerName + " already has a cert with friendly name: 'MECM Client Authentication Certificate'")
                    return 2
                }
            }
            catch {
                Write-Host ("WARNING:`tFailed to connect to " + $HostFQDN + " due to too many connections to the remote computer.")
                return 71
            }
        }
        else {
            Write-Host ("WARNING:`tFailed to connect to " + $HostFQDN + " using SMB.")
            return 445
        }
    }
    catch {
        Write-Host ("WARNING:`tFailed to connect to " + $HostFQDN + " using WinRM.")
        return 1
    }
    finally {
        Set-Location -Path ($PriorLocation) -ErrorAction SilentlyContinue
        $Error.Clear()
    }        
}
function Set-PKICertificate {
    [CmdletBinding()]
    param (
        [parameter(Position = 0, Mandatory = $true)][string]$ComputerName,
        [parameter(Position = 1, Mandatory = $true)][string]$ComputerDomain
    )
    $ServerAdmin, $AdminDomain = (Get-SvcAcctName -DomainName $ComputerDomain)
    if ($ComputerName -like ("*.*")) {
        $ComputerName = $ComputerName.Split(".")[0]
    }
    $HostFQDN = ($ComputerName + "." + $ComputerDomain)
    try {
        Invoke-Command -ComputerName $HostFQDN -Credential $ServerAdmin -ScriptBlock {
            param ($HostFQDN)
            Import-Certificate -FilePath ("C:\" + $HostFQDN + ".rsp") -CertStoreLocation "Cert:\LocalMachine\My" -Verbose
        } -ArgumentList $HostFQDN
        return 0
    }
    catch {
        $Error.Clear()
        return 1
    }
}
Export-ModuleMember -Function Copy-CertificateFile
Export-ModuleMember -Function Set-CustomCertificateRequest
Export-ModuleMember -Function Set-PKICertificate
