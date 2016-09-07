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
[string] $SecretClientId,
[string] $Secreturikey,
[string] $SecretKey,
[string] $SecretSubId,
[string] $SecretTenantId,
[string] $SecretRg,
[string] $SecretAcct

)

 (1..$InstanceCount) | %{ if($_ -ne $instanceCount) { $nodes += "$servernamepart$_,"} else {$nodes += "$servernamepart$_"} }
     
    $i = 0
    $serversOnline=$false

    do {
            Write-Host "Testing Connections to $nodes"

            $i++
            $Online=$true
                foreach($ComputerName in $Nodes.split(",")) {
        
                    $test1 = test-connection $ComputerName -Count 1 -Quiet
                    $Result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {Get-Service | Where-Object {($_.Name -eq "WinRM") -and ($_.Status -eq "Running")}} -ErrorAction Stop 
                    $test2 = !$Result?

                    if(!$test1 -or !$test2) {$Online=$false}
                }
            $serversOnline = $online
            if(!$Online) {sleep -Seconds 300}

            #1 sleep 300 seconds, 12 sleeps is one hour, 48 is 4 hrs,  300 sleeps is 25 hrs
            if($i -gt 300) {throw "Servers $nodes are not resolving online" }

    } until($serversOnline)


    if($serversOnline) {
        Write-Host "$nodes are online"

        Import-Module cloudmsaad

        $response = $null
        $uri = "https://s1events.azure-automation.net/webhooks?token={0}" -f $Secreturikey
        $headers = @{"From"="user@contoso.com";"Date"="$($(get-date).ToShortDateString())"}
               

        $Params  = @(
                    @{ AOAGListenerName=$AOAGListenerName;AOAGName=$AOAGName;Nodes=$Nodes;FailoverClusterName=$FailoverClusterName;SubscriptionId=$SubscriptionId }
                    )

        $body = ConvertTo-Json -InputObject $params
    
        $startRunbook = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body
        $jobID = $startRunbook.JobIds[0]

            if($jobID) {

                write-host $jobID

                $jobstatusURL = "https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Automation/automationAccounts/{2}/jobs/{3}?api-version=2015-10-31" -f $SecretSubId,$SecretRg,$SecretAcct,$jobID

                $i=0
    
                #check status of runbook
                do{
                    $i++
                    $getRunbookStatus = Invoke-AzureRestGetAPI -Uri $jobstatusURL -clientId $SecretClientId -key $SecretKey -tenantId $SecretTenantId
        
                    $runbookStatus = $getRunbookStatus.properties.status
            
                    if($runbookStatus) {
                        write-output "$(Get-Date) JobID: $jobID Status: $runbookStatus"
                        sleep -Seconds 300
                        if ($i -ge 300)
                        {
                            Write-Output "Exceeded timeout, stopping status check of runbook"
                            $runbookStatus = "Failed"
                        }
                    }else {write-host "job failed..."; $runbookStatus = "Failed"; break;}
                }
                until($runbookStatus -eq "Completed" -or $runbookStatus -eq "Failed")

            }

        }