# Scenario - Build 1 by Name
#
#

import-module cloudms

#Get domain credentials that need to be used for domain joining the VMs
$username= Read-Host -Prompt "Domain UserName (domainname\alias)"
$password =Read-Host -Prompt "Password for $username" -AsSecureString
$domainUserCredential = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $password

# Image Single VM
$params = @{
                   "TemplateFile"="C:\Users\trworth\Source\Repos\SI-HDC-CPT-ARM\ARMPilot\template-SingleVM.json"; 
                   "TemplateParameterFile"="C:\Users\trworth\Source\Repos\SI-HDC-CPT-ARM\ARMPilot\templateParams.json"; 
                   "SubscriptionId"="e4a74065-cc6c-4f56-b451-f07a3fde61de"; 
                   "ResourceGroupLocation"="central us"; 
                   "ResourceGroupName"="cptApp1";
                   
                  }
                  
#Enter your name and specifications for the IIS server.
Invoke-ARM -TemplateFile $params.TemplateFile `
       -TemplateParameterFile $params.TemplateParameterFile `
       -SubscriptionId $params.SubscriptionId `
       -ResourceGroupLocation $params.ResourceGroupLocation `
       -ResourceGroupName $params.ResourceGroupName `
       -Vm "MyArmTestVM"

      





