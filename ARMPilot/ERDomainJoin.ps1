Param(
         [string] [Parameter(Mandatory=$true)] $SubscriptionId,
         [string] [Parameter(Mandatory=$true)] $ResourceGroupLocation,
         [string] [Parameter(Mandatory=$true)] $ResourceGroupName,
         [string] $TemplateFile,
         [string] $TemplateParameterFile,
         [string] $domain="redmond.corp.microsoft.com",
         [string] [Parameter(Mandatory=$true)] $vm,
         [switch] $NoImage
        
       )


if(!$noImage) {
    #Image the VM using the resource group through ARM template
    #Get-AzureConnection is called within Invoke-ARM

    Write-Host (Get-Date).ToString()
    Invoke-Arm -$SubscriptionId $subscriptionId -ResourceGroupName $ResourceGroupName -TemplateFile $TemplateFile -TemplateParameterFile $TemplateParameterFile -Verbose -vmName $vm
    Write-Host (Get-Date).ToString()

}



#Get domain credentials that need to be used for domain joining the VMs
$username= Read-Host -Prompt "Domain UserName (domainname\alias)"
$password =Read-Host -Prompt "Password for $username" -AsSecureString
$domainUserCredential = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $password

#Iterate through all the RM VMs in the resource group and domain join them if they are already not...

Install-VMDomainJoin. -resourceGroupName $ResourceGroupName -DomainCredential $domainUserCredential -Domain $domain

