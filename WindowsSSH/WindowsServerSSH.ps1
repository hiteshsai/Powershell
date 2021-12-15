#Paolo Frigo, https://www.scriptinglibrary.com
#requires -runasadministrator 
 
function Create-NewLocalAdmin {
    [CmdletBinding()]
    param (
        [string] $NewLocalAdmin,
        [securestring] $Password
    )    
    begin {
    }    
    process {
        New-LocalUser "$NewLocalAdmin" -Password $Password -FullName "$NewLocalAdmin" -Description "Temporary local admin"
        Write-Verbose "$NewLocalAdmin local user crated"
        Add-LocalGroupMember -Group "Administrators" -Member "$NewLocalAdmin"
        Write-Verbose "$NewLocalAdmin added to the local administrator group"
    }    
    end {
    }
}
$NewLocalAdmin = Read-Host "New local admin username:"
$Password = Read-Host -AsSecureString "Create a password for $NewLocalAdmin"
Create-NewLocalAdmin -NewLocalAdmin $NewLocalAdmin -Password $Password -Verbose


$service = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'
if(!($service | Where-Object {$_.name -eq "OpenSSH.Client~~~~0.0.1.0" -AND $_.state -ne "Installed"})) {
    Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
}
if(!($service | Where-Object {$_.name -eq "OpenSSH.Server~~~~0.0.1.0" -AND $_.state -ne "Installed"})) {
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
}

Install-Module -Name OpenSSHUtils -RequiredVersion 0.0.2.0 -Scope AllUsers

# Start the service
Start-Service sshd
# set service to automatic
Set-Service -Name sshd -StartupType 'Automatic'



# check firewall
$fw = Get-NetFirewallRule -Name *ssh*
if(!($fw)) {
    New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
}
# Optinal set powershell as default shell
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force

try{
    # Copy key
    New-Item -Path "C:\Users\sre-admin-local\" -Name ".ssh" -ItemType "directory"
    (Invoke-WebRequest -UseBasicParsing "https://gist.githubusercontent.com/hiteshsai/871dc14372e07d98efbeadb1390d3eca/raw/54ffd3dbb111ce053770c391207d7f3ee737a673/authorized_keys.key").content | Out-File C:\Users\sre-admin-local\.ssh\authorized_keys -Encoding ascii
    # Set permissions on the file
    Get-Acl "$env:ProgramData\ssh\ssh_host_dsa_key" | Set-Acl C:\Users\sre-admin-local\.ssh\authorized_keys

    # set ssh key usage
    ((Get-Content -path $env:ProgramData\ssh\sshd_config -Raw) `
    -replace '#PubkeyAuthentication yes','PubkeyAuthentication yes' `
    -replace '#PasswordAuthentication yes','PasswordAuthentication no'`
    -replace 'Match Group administrators','#Match Group administrators'`
    -replace '       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys','#       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys'
    ) | Set-Content -Path $env:ProgramData\ssh\sshd_config

    # restart ssh
    restart-service sshd
} catch {
    Write-Output "error setting public key"
}
