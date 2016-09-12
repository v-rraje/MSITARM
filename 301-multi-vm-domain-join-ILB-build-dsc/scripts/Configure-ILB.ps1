# Name: ConfigureSQLserver
#
param
    (
[string] $AOAGListenerName,
[string] $AOAGName,
[string] $ServernamePart,
[string] $InstanceCount,
[string] $Domain,
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

 $nodes=""

 (1..$InstanceCount) | %{ if($_ -ne $instanceCount) { $nodes += "$servernamepart$_,"} else {$nodes += "$servernamepart$_"} }
   
 
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
                            
               $jobstatusURL = "see Dashboard for status http://co1cptdevweb01:4433/?searchText={0}&f_mtype=SQLAO-Configuration&f_dateType=all" -f $AOAGListenerName
                
               write-host $jobstatusURL

            }

        } catch {
         [string]$errorMessage = $_.Exception.Message
         if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureDataPath: $errorMessage"
         }
            throw $errorMessage
        }