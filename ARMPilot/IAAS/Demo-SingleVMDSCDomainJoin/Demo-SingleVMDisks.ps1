# Scenario - Build 1 by Name

$params = @{
                   "TemplateFile"=".\template-SingleVM.json"; 
                   "TemplateParameterFile"=".\templateSQLParams.json"; 
                   "SubscriptionId"="e4a74065-cc6c-4f56-b451-f07a3fde61de"; 
                   "ResourceGroupLocation"="central us"; 
                   "ResourceGroupName"="cptApp1";
                   "Domain"="Redmond.corp.microsoft.com";
                   "vmName"="trworthdsc15"
                  }

if (Get-Module -ListAvailable -Name CloudMS) {
    import-module cloudms
} else {
    Write-Host "Module CloudMS does not exist, you must instal it first."
    break;
}

# Image 
#Get domain credentials that need to be used for domain joining the VMs
$username= Read-Host -Prompt "Domain UserName (domainname\alias)"
$password =Read-Host -Prompt "Password for $username" -AsSecureString
$domainUserCredential = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $password

 $TempParams = Import-Templates -templatefile $params.templatefile -TemplateParameterFile $Params.TemplateParameterFile -vm $params.vmName
 $u=$([string] $TempParams.localAdminUserName)
 $p= ConvertTo-SecureString $([string] $TempParams.localAdminPassword) -asplaintext -force
 $params.Domain = $TempParams.domainName

 $LocalUserCredential = New-Object System.Management.Automation.PSCredential -ArgumentList $u,$p

write-host "-----------------------------"
Write-host "Invoke-Arm"            
write-host "-----------------------------"

                 
#Enter your name and specifications for the IIS server.
$serversBuilt=Invoke-ARMDSC -TemplateFile $params.TemplateFile `
                        -TemplateParameterFile $params.TemplateParameterFile `
                        -SubscriptionId $params.SubscriptionId `
                        -ResourceGroupLocation $params.ResourceGroupLocation `
                        -ResourceGroupName $params.ResourceGroupName `
                        -Vm $params.vmName `
                        -creds $domainUserCredential 

