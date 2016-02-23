
# Authenticate against Azure and set context to your subscription
$subID ='e4xxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'

Login-AzureRmAccount -SubscriptionId $subID

Set-AzureRmContext -SubscriptionId $subID

# Import Module
Import-Module .\CPTARM.psm1 -Force 

# Sample commands
Get-Help Set-DevOpsPermissions -Full

# Add a user by UPN
Set-DevOpsPermissions -subscriptionID $subID -appRG ResourceGroupName -ERRG ARMERVNETUSCPOC -DevOpsUpn 'user@microsoft.com' -Verbose

# Add multiple users by SG membership
Set-DevOpsPermissions -subscriptionID $subID -appRG ResourceGroupName -ERRG ARMERVNETUSCPOC -DevOpsGroupName 'SG Display Name' -Verbose





