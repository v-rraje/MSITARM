
#Authenticate against Azure and set context to your subscription
$subID ='e4xxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'

Login-AzureRmAccount -SubscriptionId $subID

Set-AzureRmContext -SubscriptionId $subID

#Import Module
Import-Module .\CPTARM -Force 

#Sample commands
Get-Help Set-DevOpsPermissions -Full

Set-DevOpsPermissions -subscriptionID $subID -appRG ResourceGroupName -ERRG ARMERVNETUSCPOC -DevOpsUpn 'user@microsoft.com' -Verbose

Set-DevOpsPermissions -subscriptionID $subID -appRG ResourceGroupName -ERRG ARMERVNETUSCPOC -DevOpsGroupName 'SG Display Name' -Verbose

#Discover our commandlets
#get-command -Module CPTARM

#get details just like any other commandlet
#help add-policy -Full

#help Add-SDOManagedExpressRouteUserRole -Full



