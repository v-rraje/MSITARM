#
# DeploymentDemo.ps1
#
# Scenario - Build 1 by Name
# Scenario - Build 1 IIS and 1 SQL server by namepar
#
#import-module cloudms

#Get domain credentials that need to be used for domain joining the VMs
$username= Read-Host -Prompt "Domain UserName (domainname\alias)"
$password =Read-Host -Prompt "Password for $username" -AsSecureString
$domainUserCredential = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $password



# Image IIS
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

      
# Image SQL

$params = @{
                   "TemplateFile"="templateSQL.json"; 
                   "TemplateParameterFile"="templateSQLParams.json"; 
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

Install-VMDomainJoin -resourceGroupName $params.ResourceGroupName  -DomainCredential $domainUserCredential -Domain $domain

# Build IIS

Setup-IIS -Servers @{"Servername"="ArmPilot-SQL-0"} -outputPath $PSScriptRoot\InstallIIS_DSC -ResourceGroupName $params.ResourceGroupName  -DomainCredential  $domainUserCredential

$mof=InstallIIS_DSC -outputPath $PSScriptRoot\InstallIIS_DSC -MachineName ArmPilot-IIS-0
Get-ChildItem -Path $mof.Directoryname | ConvertTo-MrMOFv4 -Verbose
Start-DscConfiguration $PSScriptRoot\InstallIIS_DSC -ComputerName ArmPilot-IIS-0   -Verbose -Wait

# Build SQL
Setup-SQL -Servers @{"Servername"="ArmPilot-SQL-0"} -outputPath $PSScriptRoot\InstallSQL_DSC -ResourceGroupName $params.ResourceGroupName  -DomainCredential  $domainUserCredential

$mof=InstallSQL_DSC -outputPath $PSScriptRoot\InstallSQL_DSC -MachineName ArmPilot-SQL-0
Get-ChildItem -Path $mof.Directoryname | ConvertTo-MrMOFv4 -Verbose
Start-DscConfiguration $PSScriptRoot\InstallSQL_DSC -ComputerName ArmPilot-SQL-0   -Verbose -Wait




