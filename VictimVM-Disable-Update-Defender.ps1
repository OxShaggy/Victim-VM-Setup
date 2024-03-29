<#
This script is for automating the setup of a malware analysis machine
    Disable updates and stop update service
    Disable defendor
    Diable smart screen
    Turn on network discovery for file sharing with host system
    Run debloat script
    Run flare install script

Requirements:
    run as admin
    Windows10SysPrepDebloater.ps1
    Install.ps1 from flare
    manually turn off tampering protection
    
V1.0
#>

# check for admin rights
If ($IsWindows -Eq $True) {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
		Start-Process 'pwsh' -Verb 'runAs' -ArgumentList ("& '" + $MyInvocation.MyCommand.Definition + "'")
		Break
	}
}

# stop update service
# set the Windows Update service to "disabled"
sc.exe config wuauserv start=disabled

# display the status of the service
sc.exe query wuauserv

# stop the service, in case it is running
sc.exe stop wuauserv

# display the status again, because we're paranoid
sc.exe query wuauserv

# double check it's REALLY disabled - Start value should be 0x4
REG.exe QUERY HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv /v Start 

# stop windows update
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Value 1

# Turn on network discovery
Get-NetFirewallRule -DisplayGroup 'Network Discovery'|Set-NetFirewallRule -Profile 'Private, Domain' -Enabled true

# Disable defender, tamper protection needs to be turned off first
# Not sure if this command works: Remove-WindowsFeature Windows-Defender, Windows-Defender-GUI
# Disable realtime monitoring
Set-MpPreference -DisableRealtimeMonitoring $true
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force

# Disable automatic sample submission
Set-MpPreference -SubmitSamplesConsent NeverSend

# Disable cloud protection
Set-MpPreference -MAPSReporting Disable

# Disable smartscreen
{
    Write-host "Disabling SmartScreen Filter..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0
    }

# Set dark mode
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Value 0

# Run debloater script
.\Windows10SysPrepDebloater.ps1 -Sysprep -Debloat -Privacy

# start flare install script
.\install.ps1 




<#
    -----This will need work. I need to figure out how to set up loops for each section and if that section is not being run, skip and go to the next.-----

    $no = @("no","nah","nope","n")
$yes = @("yes","yup","yeah","y")

do
{
    $answ = read-host "Yes or no?"
}
until($no -contains $answ -or $yes -contains $answ)

if($no -contains $answ)
{
    # Do no stuff
}
elseif($yes -contains $answ)
{
    # Do yes stuff
}

#>