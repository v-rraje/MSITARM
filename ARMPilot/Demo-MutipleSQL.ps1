# Scenario - Build 1 SQL server by namepart

# Image SQL

import-module cloudms

#Get domain credentials that need to be used for domain joining the VMs
$username= Read-Host -Prompt "Domain UserName (domainname\alias)"
$password =Read-Host -Prompt "Password for $username" -AsSecureString
$domainUserCredential = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $password

    $params = @{
                "TemplateFile"="templateSQL.json"; 
                "TemplateParameterFile"="templateSQLParams.json"; 
                "SubscriptionId"="e4a74065-cc6c-4f56-b451-f07a3fde61de"; 
                "ResourceGroupLocation"="central us"; 
                "ResourceGroupName"="cptApp1";
                   
                }

     Invoke-ARM -TemplateFile $params.TemplateFile `
                -TemplateParameterFile $params.TemplateParameterFile `
                -SubscriptionId $params.SubscriptionId `
                -ResourceGroupLocation $params.ResourceGroupLocation `
                -ResourceGroupName $params.ResourceGroupName 

# Build SQL

Setup-SQL -Servers @{"Servername"="ArmPilot-SQL-0"} `
          -outputPath $PSScriptRoot\InstallSQL_DSC `
          -ResourceGroupName $params.ResourceGroupName `
          -DomainCredential  $domainUserCredential

$mof=InstallSQL_DSC -outputPath $PSScriptRoot\InstallSQL_DSC -MachineName ArmPilot-SQL-0

Get-ChildItem -Path $mof.Directoryname | ConvertTo-MrMOFv4 -Verbose
Start-DscConfiguration $PSScriptRoot\InstallSQL_DSC -ComputerName ArmPilot-SQL-0   -Verbose -Wait