#Authenticate
#Add-AzureRmAccount 
$subID ='e4xxx065-cc6c-4f56-b451-f07a3fdxxxxe' #Fake Sub

#Sandbox Corp
Set-AzureRmContext -SubscriptionId $subID

#Import Module
Import-Module -Name .\arm_module.psm1 #navigate to the directory, first

#Sample commands
Set-DevOpsPermissions -subscriptionID $subID -appRG ndavids -ERRG ARMERVNETUSCPOC -email 'ndavids@microsoft.com' -Verbose



#Discover our commandlets
#get-command -Module arm_module

#get details just like any other commandlet
#help add-policy -full
#help Add-SDOManagedExpressRouteUserRole -full
#help Set-DevOpsPermissions -Full

