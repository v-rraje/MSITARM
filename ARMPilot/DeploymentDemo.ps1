#
# DeploymentDemo.ps1
#
# Scenario - Build 1 IIS and 1 SQL server
#
import-module cloudms

show-HelpOnImage

# Image IIS
$params = @{
                   "TemplateFile"="template.json"; 
                   "TemplateParameterFile"="templateIISParams.json"; 
                   "SubscriptionId"="e4a74065-cc6c-4f56-b451-f07a3fde61de"; 
                   "ResourceGroupLocation"="central us"; 
                   "ResourceGroupName"="cptApp1";
                   
                  }

#Enter your name and specifications for the IIS server.
Invoke-ARMtemplate -TemplateFile $params.TemplateFile `
       -TemplateParameterFile $params.TemplateParameterFile `
       -SubscriptionId $params.SubscriptionId `
       -ResourceGroupLocation $params.ResourceGroupLocation `
       -ResourceGroupName $params.ResourceGroupName `
       -PromptToContinue
       
# Image SQL

reset-cache

$params = @{
                   "TemplateFile"="templateSQL.json"; 
                   "TemplateParameterFile"="templateSQLParams.json"; 
                   "SubscriptionId"="e4a74065-cc6c-4f56-b451-f07a3fde61de"; 
                   "ResourceGroupLocation"="central us"; 
                   "ResourceGroupName"="cptApp1";
                   
                  }

#Enter your name and specifications for the IIS server.
Invoke-ARMtemplate -TemplateFile $params.TemplateFile `
       -TemplateParameterFile $params.TemplateParameterFile `
       -SubscriptionId $params.SubscriptionId `
       -ResourceGroupLocation $params.ResourceGroupLocation `
       -ResourceGroupName $params.ResourceGroupName `
       -PromptToContinue

# Build IIS

$mof=InstallIIS_DSC -outputPath $PSScriptRoot\InstallIIS_DSC -MachineName ArmPilot-IIS-0
Get-ChildItem -Path $mof.Directoryname | ConvertTo-MrMOFv4 -Verbose
Start-DscConfiguration $PSScriptRoot\InstallIIS_DSC -ComputerName ArmPilot-IIS-0   -Verbose -Wait

# Build SQL

$mof=InstallSQL_DSC -outputPath $PSScriptRoot\InstallSQL_DSC -MachineName ArmPilot-SQL-0
Get-ChildItem -Path $mof.Directoryname | ConvertTo-MrMOFv4 -Verbose
Start-DscConfiguration $PSScriptRoot\InstallSQL_DSC -ComputerName ArmPilot-SQL-0   -Verbose -Wait




