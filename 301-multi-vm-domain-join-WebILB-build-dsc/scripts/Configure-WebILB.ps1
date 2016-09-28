# Name: ConfigureWebILB
#
param
    (
[string] $DeploymentName,
[string] $servernamepart,
[string] $domain,
[int]    $InstanceCount,
[string] $SubscriptionId,
[string] $WebILBName,
[string] $SQLILBName,
[string] $ILBSubId,
[string] $ILBkey
)
try {

 $nodes=""

 (1..$InstanceCount) | %{ if($_ -ne $instanceCount) { $nodes += "$servernamepart$_,"} else {$nodes += "$servernamepart$_"} }
   
 
        Import-Module cloudmsaad
         
        $response = $null
        $uri = "https://s1events.azure-automation.net/webhooks?token={0}" -f $ILBkey
        
        $headers = @{"From"="user@contoso.com";"Date"="$($(get-date).ToShortDateString())"}
               

        $Params  = @(
                    @{ Nodes=$Nodes;DeploymentName=$DeploymentName;webilbname=$webilbname;sqlibname=$sqlibname;SubscriptionId=$SubscriptionId }
                    )

        $body = ConvertTo-Json -InputObject $params
    
        $startRunbook = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body
        $jobID = $startRunbook.JobIds[0]

            if($jobID) {
                            
               $jobstatusURL = "see Dashboard. 'http://co1cptdevweb01:4433/?searchText={0}&f_mtype=WebILB-Configuration&f_dateType=all'  " -f $webilbname
                
               write-host $jobstatusURL

            }

        } catch {
         [string]$errorMessage = $_.Exception.Message
         if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureDataPath: $errorMessage"
         }
            throw $errorMessage
        }