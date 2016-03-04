Param(
    [string] $subId
)


function Usage
	{
		$usageText = @"
Please pass a SubID
Example: ./pilotsetup.ps1 -subID 28077388-3f00-4938-9481-e4e87bc59972
"@     
		Write-Host -f yellow $usageText
		exit	
	}

If ($subID -eq "") {Usage} 

#$subID = '28077388-3f00-4938-9481-e4e87bc59972'
try {
        #Check if the user is already logged in for this session
        $AzureRmContext = Get-AzureRmContext
} catch {
        #Prompts user to login to Azure account
        Login-AzureRmAccount
}

Set-AzureRmContext -SubscriptionId $subID

try {
    Import-Module .\CPTARM.psm1 -Force 
}
catch {
    Throw 'Please navigate to the same directory where CPTARM.psm1 is and try again'
}

#Here's where we do the subscription setup - this is policy
Add-Policy -policy SDOStdPolicyNetworkAllowV1 -subscriptionID $subID -Verbose
#Add-Policy -policy SDOStdPolicyRegion -subscriptionID $subID -Verbose
Add-Policy -policy SDOStdPolicyTags -subscriptionID $subID -Verbose

#Here's where we do the subscription setup - this creating the custom role
Add-SDOManagedExpressRouteUserRole -subscriptionID $subID -Verbose


