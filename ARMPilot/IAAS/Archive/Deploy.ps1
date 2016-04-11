Param(
         [string] [Parameter(Mandatory=$true)] $SubscriptionId,
         [string] [Parameter(Mandatory=$true)] $ResourceGroupLocation,
         [string] [Parameter(Mandatory=$true)] $ResourceGroupName,
         [string] $Domain = 'Redmond.corp.microsoft.com',
         [string] $TemplateFile =  'template.json',
         [string] $TemplateParameterFile = 'templateParams.json',
         [string] $VM,
		 [System.Management.Automation.PSCredential] $DomainCreds    
       )
       
       $serversBuilt=$null
       if($VM) {
        $serversBuilt=Invoke-ARM -TemplateFile $params.TemplateFile `
                             -TemplateParameterFile $params.TemplateParameterFile `
                             -SubscriptionId $params.SubscriptionId `
                             -ResourceGroupLocation $params.ResourceGroupLocation `
                             -ResourceGroupName $params.ResourceGroupName `
                             -Vm $VM`
                             -creds $domainUserCredential 
        } else {

        $serversBuilt=Invoke-ARM -TemplateFile $params.TemplateFile `
                             -TemplateParameterFile $params.TemplateParameterFile `
                             -SubscriptionId $params.SubscriptionId `
                             -ResourceGroupLocation $params.ResourceGroupLocation `
                             -ResourceGroupName $params.ResourceGroupName `
                             -creds $domainUserCredential 

        }

         Install-VMDomainJoin -Servers $serversBuilt `
                        -SubscriptionId $params.SubscriptionId `
                        -resourceGroupName $params.ResourceGroupName  `
                        -DomainCredential $domainUserCredential `
                        -LocalCredential $localUserCredential `
                        -Domain $params.domain

        Install-AdditionalAdmins -Servers $serversBuilt `
                                 -SubscriptionId $params.SubscriptionId `
                                 -resourceGroupName $params.ResourceGroupName `
                                 -creds $domainUserCredential `
                                 -AdditionalAdminList $TempP