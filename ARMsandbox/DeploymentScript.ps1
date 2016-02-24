function deploy {
       Param(
         [string] [Parameter(Mandatory=$true)] $SubscriptionId,
         [string] [Parameter(Mandatory=$true)] $ResourceGroupLocation,
         [string] [Parameter(Mandatory=$true)] $ResourceGroupName,
         [string] $OuPath = 'OU=ITManaged,OU=ITServices,DC=redmond,DC=corp,DC=microsoft,DC=com',
         [string] $TemplateFile = (Get-Location).Path + '\template.json',
         [string] $TemplateParameterFile = (Get-Location).Path + '\templateParams.json'
       )

       if (Get-Module -ListAvailable | Where-Object { $_.Name -eq 'AzureResourceManager' -and $_.Version -ge '0.9.9' }) {
              Throw "The version of the Azure PowerShell cmdlets installed on this machine are not compatible with this script.  For help updating this script visit: http://go.microsoft.com/fwlink/?LinkID=623011"
       }

       Import-Module Azure -ErrorAction SilentlyContinue

       try {
              #Check if the user is already logged in for this session
              $AzureRmContext = Get-AzureRmContext
       } catch {
              #Prompts user to login to Azure account
              Login-AzureRmAccount
       }

       #Selects the Azure subscription to be used
       Set-AzureRmContext -SubscriptionId $SubscriptionId
       
       Set-StrictMode -Version 3

       $OptionalParameters = New-Object -TypeName Hashtable
       $TemplateFilePath = [System.IO.Path]::Combine($PSScriptRoot, $TemplateFile)
       $TemplateParameterFilePath = [System.IO.Path]::Combine($PSScriptRoot, $TemplateParameterFile)
       		
		#Request for domain join credentials
		Write-Host 'Please enter the credentials for domain joining' -foregroundcolor cyan
		$DomainCreds = Get-Credential
		
		#Request for local account credentials
		Write-Host 'Please enter the credentials as the local account for the VM' -foregroundcolor cyan
		$LocalCreds = Get-Credential

       #Get contents of the template parameters file
       'Reading template file contents...'
       $JsonParams = Get-Content $TemplateParameterFile | ConvertFrom-Json
       
       #Get server name
       $ServerName = $JsonParams.parameters.vmName.value
       
       #Get number of VMs to be created
       $NumberOfInstances = $JsonParams.parameters.numberOfInstances.value
       
       #Get domain name
       $DomainName = $JsonParams.parameters.domainName.value

       New-AzureRmResourceGroupDeployment -Name (('ARMDomainJoinVM-') + ((Get-Date).ToUniversalTime()).ToString('MMdd-HHmm')) `
                                                                 -ResourceGroupName $ResourceGroupName `
                                                                 -TemplateFile $TemplateFilePath `
                                                                 -TemplateParameterFile $TemplateParameterFilePath `
                                                                 -Force -Verbose


       for ($i = 0; $i -lt $NumberOfInstances; $i++) {
            #Check VM status
            $VmIsReady = $false
            while(!$VmIsReady) {
                'Checking VM ' + $ServerName + $i + ' status...'
                Start-Sleep -s 30
				
				$VmStatuses = (Get-AzureRmVm -ResourceGroupName $ResourceGroupName -Name ($ServerName + $i) -Status).VMAgent.Statuses.DisplayStatus
				If($VmStatuses -eq 'Ready'){
					'VM is ready and running'
					$VmIsReady = $true
				}	
			}
		  
		  #Get IP address of the VM
		  'Getting VM IP address...'
		  $AzureIp = (Get-AzureRmNetworkInterface -Name ($ServerName + $i) -ResourceGroupName $ResourceGroupName).IpConfigurations[0].PrivateIpAddress
		  $AzureIp
		  
		  #Setting PrivateIpAllocationMethod to Static
		  'Setting Private IP allocation method to Static...'
		  $Nic = (Get-AzureRmNetworkInterface -Name ($ServerName + $i) -ResourceGroupName $ResourceGroupName)
		  $Nic.IpConfigurations[0].PrivateIpAllocationMethod = 'Static'
		  Set-AzureRmNetworkInterface -NetworkInterface $Nic
		  
		  'Waiting for 5 minutes before domain joining...'
		  Start-Sleep -s 300
		  
		  #Domain join the VM
		  'Domain joining the VM...'
		  Add-Computer -ComputerName $AzureIp -DomainName $DomainName -Credential $DomainCreds -LocalCredential $LocalCreds
		  
		  #Restart the VM to reflect the changes
		  'Restarting the VM to reflect changes...'
		  Restart-AzureRmVm -ResourceGroupName $ResourceGroupName -Name ($ServerName + $i)
       }
}

deploy -SubscriptionId e4a74065-cc6c-4f56-b451-f07a3fde61de -ResourceGroupLocation "central us" -ResourceGroupName "cptApp1" 
