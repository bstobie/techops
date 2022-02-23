function AdminReset {
    [CmdletBinding()]
    param (
        [String][Parameter(Position = 0,Mandatory = $true)]$KeyPath,
        [String][Parameter(Position = 1,Mandatory = $true)]$PwdPath
    )
    if (Test-Path -Path $KeyPath) { Remove-Item -Path $KeyPath -Force | Out-Null }
    if (Test-Path -Path $PwdPath) { Remove-Item -Path $PwdPath -Force | Out-Null }
}
function SetCredentials {
    [CmdletBinding()]
    param (
        [String][Parameter(Position = 0, Mandatory = $true)]$SecureUser,
        [String][Parameter(Position = 1, Mandatory = $true)]$Domain,
        [string][Parameter(Position = 2, Mandatory = $false)]$SecureString,
        [byte][Parameter(Position = 3, Mandatory = $false)][ValidateSet(16,24,32)]$AES_Size = 32,
        [bool][Parameter(Position = 4, Mandatory = $false)]$ResetPassword = $false
    )
    Set-Variable -Name CredPath -Value ($env:USERPROFILE + "\AppData\Local\Credentials")
    Set-Variable -Name WorkingPath -Value ($CredPath + "\" + $Domain)
    Set-Variable -Name KeyFile -Value (($SecureUser.Split("@")[0]) + ".key")
    Set-Variable -Name PassFile -Value (($SecureUser.Split("@")[0]) + ".pwd")
    Set-Variable -Name PathKeyFile -Value ($WorkingPath + "\" + $KeyFile)
    Set-Variable -Name PathPassFile -Value ($WorkingPath + "\" + $PassFile)
    do {
        if ($ResetPassword) {
            AdminReset -KeyPath $PathKeyFile -PwdPath $PathPassFile
            $ResetPassword = $false
        }
        elseif ((Test-Path -Path $PathKeyFile) -and (Test-Path -Path $PathPassFile)) {
            $SecureString = Get-Content -Path $PathPassFile | ConvertTo-SecureString -Key (Get-Content $PathKeyFile) -ErrorAction Stop
            Return New-Object System.Management.Automation.PsCredential($SecureUser, $SecureString)
        }
        else {
            if (!(Test-Path -path $WorkingPath)) {
                New-Item -Path $WorkingPath -ItemType Directory | Out-Null
            }
            else {
                AdminReset -KeyPath $PathKeyFile -PwdPath $PathPassFile
            }
            $intCount = -1
            $PrivateKey = New-Object Byte[] $AES_Size
            do {
                $intCount++
                $PrivateKey[$intCount] = Get-Random -Minimum 0 -Maximum 255
            } until ($intCount -ge ($AES_Size - 1))
            $PrivateKey | Out-File ($PathKeyFile)
            if (!($SecureString)) {
                $SecureString = Read-Host -Prompt ("Enter your [" + $SecureUser + "] credentials") -AsSecureString
            }
            $SecureString | ConvertFrom-SecureString -Key (Get-Content $PathKeyFile) | Set-Content $PathPassFile
        }
    } while ($ResetPassword -eq $false)
}
Export-ModuleMember -Function SetCredentials
