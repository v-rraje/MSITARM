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
[string] $ServernamePart,

[parameter(Mandatory=$true, Position=3)]
[string] $InstanceCount,

[parameter(Mandatory=$true, Position=4)]
[string] $FailoverClusterName,

[parameter(Mandatory=$true, Position=5)]
[string] $SubscriptionId,

[Parameter(Mandatory=$true, Position=6)]
[string] $uri,

[Parameter(Mandatory=$true, Position=7)]
[string] $SecretKey
        
)
{

$response = $null

$headers = @{"From"="user@contoso.com";"Date"="05/28/2015 15:47:00"}

(1..$InstanceCount) | %{ if($_ -ne $instanceCount) { $nodes += "$servernamepart$_,"} else {$nodes += "$servernamepart$_"} }

$Params  = @(
            @{ AOAGListenerName=$AOAGListenerName;AOAGName=$AOAGName;Nodes=$Nodes;FailoverClusterName=$FailoverClusterName;SubscriptionId=$SubscriptionId }
            )

$body = ConvertTo-Json -InputObject $params

$response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body 
$response


}