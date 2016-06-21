
    try {
            
              #Check if the user is already logged in for this session
              $AzureRmContext = Get-AzureRmContext | out-null
              Write-verbose "Connected to Azure"

       } catch {

              #Prompts user to login to Azure account'
              Login-AzureRmAccount | out-null
              Write-verbose "logged into Azure."
              $error.Clear()
       }
	
    Set-AzureRmContext -SubscriptionId "e4a74065-cc6c-4f56-b451-f07a3fde61de" | out-null
    
    $deploymentName=(('ARMDomainVM('+$("Azuredeploy")) +'-'+ ((Get-Date).ToUniversalTime()).ToString('MMdd-HHmm')+')')
    Write-host -f Gray "New-AzureRMResourceGroupDeployment -Name $deploymentName starting..."
  
           
   New-AzureRmResourceGroupDeployment -Name $deploymentName `
                                    -ResourceGroupName "trwortharmv1tst" `
                                    -TemplateFile ".\azuredeployportalMSSQLServer.json" `
                                    -TemplateParameterFile "C:\Users\trworth\Source\Repos\azuredeploySQL.parameters.json" `
                                    -Force -Verbose 



 