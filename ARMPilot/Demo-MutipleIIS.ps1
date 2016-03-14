
# Scenario - Build 1 IIS server by namepart
import-module cloudms

#Get domain credentials that need to be used for domain joining the VMs
$username= Read-Host -Prompt "Domain UserName (domainname\alias)"
$password =Read-Host -Prompt "Password for $username" -AsSecureString
$domainUserCredential = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $password
 
# Image IIS

        $params = @{
                   "TemplateFile"="templateIIS.json"; 
                   "TemplateParameterFile"="templateIISParams.json"; 
                   "SubscriptionId"="e4a74065-cc6c-4f56-b451-f07a3fde61de"; 
                   "ResourceGroupLocation"="central us"; 
                   "ResourceGroupName"="cptApp1";
                   
                  }

#Enter your name and specifications for the IIS server.
     Invoke-ARM -TemplateFile $params.TemplateFile `
                -TemplateParameterFile $params.TemplateParameterFile `
                -SubscriptionId $params.SubscriptionId `
                -ResourceGroupLocation $params.ResourceGroupLocation `
                -ResourceGroupName $params.ResourceGroupName 

    Install-VMDomainJoin -resourceGroupName $params.ResourceGroupName  `
                         -DomainCredential $domainUserCredential `
                         -Domain $domain
     
# Build IIS

$mof=InstallIIS_DSC -outputPath $PSScriptRoot\InstallIIS_DSC `
                    -MachineName ArmPilot-IIS-0 

    Get-ChildItem -Path $mof.Directoryname | ConvertTo-MrMOFv4 -Verbose

    Start-DscConfiguration $PSScriptRoot\InstallIIS_DSC -ComputerName ArmPilot-IIS-0   -Verbose -Wait

