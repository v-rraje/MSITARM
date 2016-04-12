# Scenario - Build 1 by Name

if (Get-Module -ListAvailable -Name CloudMS) {
  import-module cloudms_beta -Force
} else {
    Write-Host "Module CloudMS does not exist, you must instal it first."
    break;
}

$params = @{
                   "TemplateFile"="./Disks/DiskArray.json"; 
                   "TemplateParameterFile"="./Disks/Diskparams.json"; 
                   "SubscriptionId"="e4a74065-cc6c-4f56-b451-f07a3fde61de"; 
                   "ResourceGroupLocation"="central us"; 
                   "ResourceGroupName"="cptApp1";
                   "Domain"="Redmond.corp.microsoft.com";
                   "vmName"="trworthapp-03";
                   "diskCount"="2";
                  }

#import-module cloudms


write-host "-----------------------------"
Write-host "Invoke-Arm"            
write-host "-----------------------------"

$Diskparams = Import-DiskTemplates -templatefile $params.templatefile -TemplateParameterFile $params.TemplateParameterFile -VM $params.vmName
     $diskparams.DiskCount = $params.DiskCount

#Enter your name and specifications for the IIS server.
Invoke-ArmParam -TemplateFile $params.TemplateFile `
                        -params $Diskparams `
                        -SubscriptionId $params.SubscriptionId `
                        -ResourceGroupLocation $params.ResourceGroupLocation `
                        -ResourceGroupName $params.ResourceGroupName

