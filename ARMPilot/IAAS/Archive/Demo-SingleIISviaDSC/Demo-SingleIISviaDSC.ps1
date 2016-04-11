# Scenario - Build a single web server using DSC to install IIS

$params = @{
                   "TemplateFile"         =".\template-SingleVM.json"; 
                   "TemplateParameterFile"=".\templateParams.json"; 
                   "DscConfigurationPath" =".\DSC\DeployWebServer"; 
                   "SubscriptionId"       ="e4a74065-cc6c-4f56-b451-f07a3fde61de"; 
                   "ResourceGroupLocation"="west us"; 
                   "ResourceGroupName"    ="cptApp1";
                   "Domain"               ="Redmond.corp.microsoft.com"
                   "VmName"               ="cimcim-55"
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

 $TempParams = Import-Templates -templatefile $params.templatefile -TemplateParameterFile $Params.TemplateParameterFile -vm $params.VmName
 $u=$([string] $TempParams.localAdminUserName)
 $p= ConvertTo-SecureString $([string] $TempParams.localAdminPassword) -asplaintext -force
 $params.Domain = $TempParams.domainName

 $LocalUserCredential = New-Object System.Management.Automation.PSCredential -ArgumentList $u,$p

write-host "-----------------------------"
Write-host "Invoke-Arm"            
write-host "-----------------------------"
                 
#Enter your name and specifications for the IIS server.
$serversBuilt=Invoke-ARM -TemplateFile $params.TemplateFile `
                        -TemplateParameterFile $params.TemplateParameterFile `
                        -SubscriptionId $params.SubscriptionId `
                        -ResourceGroupLocation $params.ResourceGroupLocation `
                        -ResourceGroupName $params.ResourceGroupName `
                        -Vm $params.VmName `
                        -creds $domainUserCredential 

write-host "-----------------------------"
Write-host "Install-VMDomainJoin"
write-host "-----------------------------"

Install-VMDomainJoin -Servers $serversBuilt `
                        -SubscriptionId $params.SubscriptionId `
                        -resourceGroupName $params.ResourceGroupName  `
                        -DomainCredential $domainUserCredential `
                        -LocalCredential $localUserCredential `
                        -Domain $params.domain


write-host "-----------------------------"
write-host "Install-AdditionalAdmin"
write-host "-----------------------------"

Install-AdditionalAdmins -Servers $serversBuilt `
                         -SubscriptionId $params.SubscriptionId `
                         -resourceGroupName $params.ResourceGroupName `
                         -creds $domainUserCredential `
                         -AdditionalAdminList $TempParams.additionalAdmins


write-host "-----------------------------"
write-host "Install-IIS via DSC"
write-host "-----------------------------"

$ip = (Get-AzureRmNetworkInterface -Name ($params.VmName + 'nic1') -ResourceGroupName $params.ResourceGroupName).IpConfigurations[0].PrivateIpAddress
Remove-Item -Path $($params.DscConfigurationPath + "\" + $ip + ".mof") -ErrorAction SilentlyContinue
Copy-Item -Path $($params.DscConfigurationPath + "\localhost.mof") -Destination $($params.DscConfigurationPath + "\" + $ip + ".mof")
try{
    $Session = New-CimSession -ComputerName $ip -Credential $domainUserCredential -ErrorAction Stop
    $Config  = Start-DscConfiguration -Path $params.DscConfigurationPath -CimSession $Session -Wait -Force -ErrorAction Stop
    write-host -Fore Green 'Complete.'
}
catch{
        $error[0]
}
Remove-Item -Path $($params.DscConfigurationPath + "\" + $ip + ".mof") -ErrorAction SilentlyContinue
