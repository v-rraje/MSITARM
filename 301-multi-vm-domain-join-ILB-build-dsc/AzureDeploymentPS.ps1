      # Login to Azure Subscription

      $subscriptionId = 'ef108bd8-8365-4b10-bd33-a9115e60ffb4se'
      # sign in
Write-Host 'Logging in...'
try{
$context = Get-AzureRmContext -ErrorAction silentlycontinue
}
catch{}
if($context -eq $null)
{
	Add-AzureRmAccount;
}
# select subscription
Write-Host "Selecting subscription '$subscriptionId'";
Select-AzureRmSubscription -SubscriptionID $subscriptionId;


      $templatePath = $PSScriptRoot
      $TemplateFile = $templatePath + "\azuredeploy.json" 
      $TemplateParameterFile = $templatePath + "\azuredeploy.parameters.json" 
      # Provide location for Deployment. IT should be West US
      $Location = "East US 2"
      $AvSet = "TestAvSet"
      # Provide resource group name. It should be starting from ICTO number e.g. 2357-Alfred-UAT
      $resourceGroupName = "tdrapp13"
      
      # Provide storage account details. e.g. 2357alfreduatsa
      $destStorageAccount = "tdr558"
      
      # Provide the VMName. E.G. alfrediaasuat
      $vmName = 'tdrewe'



      # Create requested resource group
    $exists = Get-AzureRmResourceGroup -Location $Location | Where-Object {$_.ResourceGroupName -eq $resourceGroupName}
    if (!$exists) {
        New-AzureRMResourceGroup -Name $resourceGroupName -Location $Location -Force
    }

      #Create the new storage account
      New-AzureRMStorageAccount -AccountName $destStorageAccount -Location $Location -ResourceGroupName $ResourceGroupName -Type "Standard_LRS"
      
    # Get my pwd for domain joining this VM
    if (!$cred) { $cred = (Get-Credential).GetNetworkCredential() }

   
      # Do the new Azure deployment 
      New-AzureRmResourceGroupDeployment -Name ($env:computername + (split-path ((ls).DirectoryName[0]) -leaf)).substring(0,5) -ResourceGroupName $resourceGroupName `
            -TemplateFile $TemplateFile `
            -TemplateParameterFile $TemplateParameterFile `
            -vmName $vmName   `
            -domainJoinUserName ($cred.Domain+'\'+$cred.UserName) `
            -domainJoinPassword $cred.SecurePassword `
            -localAdminUserName 'azmin' `
            -localAdminPassword $cred.SecurePassword `
            -localAdmins ($cred.Domain+'\'+$cred.UserName) `
            -userImageStorageAccountName $destStorageAccount `
            -numberOfInstances 2 
           

