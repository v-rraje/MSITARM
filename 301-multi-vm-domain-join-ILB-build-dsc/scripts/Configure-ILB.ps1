# Name: ConfigureSQLserver
#
[CmdletBinding()]
param
    (
[parameter(Mandatory=$true, Position=0)]
[string] $AOAGListenerName,

[parameter(Mandatory=$true, Position=1)]
[string] $AOAGName,

[parameter(Mandatory=$true, Position=2)]
[string] $Nodes,

[parameter(Mandatory=$true, Position=3)]
[string] $FailoverClusterName,

[parameter(Mandatory=$true, Position=4)]
[string] $SubscriptionId,

[Parameter(Mandatory)]
[string] $uri="https://s1events.azure-automation.net/webhooks?token=jGBacOjhtiV7i1B0fdC3z4%2fZ596MvENZcXQ%2ftXsYqAA%3d"
        
)
{

$response = $null

$headers = @{"From"="user@contoso.com";"Date"="05/28/2015 15:47:00"}

$Params  = @(
            @{ AOAGListenerName=$AOAGListenerName;AOAGName=$AOAGName;Nodes=$Nodes;FailoverClusterName=$FailoverClusterName;SubscriptionId=$SubscriptionId }
            )

$body = ConvertTo-Json -InputObject $params

$response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body 
$response


}