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
try {

    Import-Module cloudmsaad

    $response = $null
    $uri = "https://s1events.azure-automation.net/webhooks?token={0}" -f $Secreturikey
    $headers = @{"From"="user@contoso.com";"Date"="$($(get-date).ToShortDateString())"}

    (1..$InstanceCount) | %{ if($_ -ne $instanceCount) { $nodes += "$servernamepart$_,"} else {$nodes += "$servernamepart$_"} }

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
                    sleep -Seconds 5
                    if ($i -ge 100)
                    {
                        Write-Output "Exceeded timeout, stopping status check of runbook"
                        $runbookStatus = "Completed"
                    }
                }else {write-host "job failed..."; break;}
            }
            until($runbookStatus -eq "Completed")

        }

    } catch { 
            [string]$errorMessage = $_.Exception.Message
            if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureDataPath: $errorMessage"
            }
            throw new Exception($errorMessage)
    }
