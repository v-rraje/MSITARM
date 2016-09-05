# Name: ConfigureSQLserver
#
param
    (
[string] $AOAGListenerName,
[string] $AOAGName,
[string] $ServernamePart,
[string] $InstanceCount,
[string] $FailoverClusterName,
[string] $SubscriptionId,
[string] $uri,
[string] $SecretKey
)
{

    $response = $null

    $headers = @{"From"="user@contoso.com";"Date"="$($(get-date).ToShortDateString())"}

    (1..$InstanceCount) | %{ if($_ -ne $instanceCount) { $nodes += "$servernamepart$_,"} else {$nodes += "$servernamepart$_"} }

    $Params  = @(
                @{ AOAGListenerName=$AOAGListenerName;AOAGName=$AOAGName;Nodes=$Nodes;FailoverClusterName=$FailoverClusterName;SubscriptionId=$SubscriptionId }
                )

    $body = ConvertTo-Json -InputObject $params

    $startRunbook = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body
    $jobID = $startRunbook.JobIds[0]

    write-host $jobID

}