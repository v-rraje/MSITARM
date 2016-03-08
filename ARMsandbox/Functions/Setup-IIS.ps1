#Requires -RunAsAdministrator

function Setup-IIS {
       Param(
         [string] [Parameter(Mandatory=$true)] $AzureIp,
         [string] [Parameter(Mandatory=$true)] $SubscriptionId,
         [string] [Parameter(Mandatory=$true)] $ResourceGroupLocation,
         [string] [Parameter(Mandatory=$true)] $ResourceGroupName,
         [string] $OuPath = 'OU=ITManaged,OU=ITServices,DC=redmond,DC=corp,DC=microsoft,DC=com',
         [string] $TemplateFile =  'template.json',
         [string] $TemplateParameterFile = 'templateParams.json',
         [switch] $InstallIIS,         
         [switch] $InstallWebdeploy, 
         [switch] $InstallWPI,
         [switch] $PromptToContinue
       )

       Set-StrictMode -Version 3
       $error.Clear()


            if($InstallIIS) {
                
               get-WinRMStatus  $($AzureIp) -waitfor -creds $DomainCreds
               Write-host -f Gray  'Installing IIS'
               $InstallResults= invoke-command -ComputerName $AzureIp -ScriptBlock $IISSetup -Credential $DomainCreds -SessionOption (New-PsSessionOption -SkipCACheck -SkipCNCheck)
                           
            }

            if($error) {
                write-host -f red $error
                write-host -f red "Stopping due to errors"
                $error.Clear()
                return $false
            }

            if($InstallWPI){
               get-WinRMStatus  $($AzureIp) -waitfor -creds $DomainCreds
               Write-host -f Gray  'Installing Web Platform Installer(x64) 5.0'
               $InstallResults= invoke-command -ComputerName $AzureIp -ScriptBlock $WebPlatformInstaller -Credential $DomainCreds -SessionOption (New-PsSessionOption -SkipCACheck -SkipCNCheck)
                           
            }
            if($error) {
                write-host -f red $error
                write-host -f red "Stopping due to errors"
                $error.Clear()
                return $false
            }

            if($InstallWebdeploy -and $InstallWPI){
               get-WinRMStatus  $($AzureIp) -waitfor -creds $DomainCreds
               Write-host -f Gray  'Installing Web Deploy 3.5 (requires WPI)'
               $InstallResults= invoke-command -ComputerName $AzureIp -ScriptBlock $InstallWebDeploy35 -Credential $DomainCreds -SessionOption (New-PsSessionOption -SkipCACheck -SkipCNCheck)
                           
            }
}