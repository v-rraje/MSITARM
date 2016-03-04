function deploy {
       Param(
         [string] [Parameter(Mandatory=$true)] $SubscriptionId,
         [string] [Parameter(Mandatory=$true)] $ResourceGroupLocation,
         [string] [Parameter(Mandatory=$true)] $ResourceGroupName,
         [string] $OuPath = 'OU=ITManaged,OU=ITServices,DC=redmond,DC=corp,DC=microsoft,DC=com',
         [string] $TemplateFile = (Get-Location).Path + '\template.json',
         [string] $TemplateParameterFile = (Get-Location).Path + '\templateParams.json'
       )

       #Check if PS Module is installed
       try {
            Import-Module Azure -ErrorAction SilentlyContinue
       }
       catch {
            Throw 'You need to install Azure Powershell.  For help updating this module visit: https://azure.microsoft.com/en-us/downloads/'
       }

       #Check if PS Module is right version
       if (Get-Module -ListAvailable | Where-Object { $_.Name -eq 'AzureResourceManager' -and $_.Version -ge '0.9.9' }) {
              Throw "The version of the Azure PowerShell cmdlets installed on this machine are not compatible with this script.  For help updating this script visit: http://go.microsoft.com/fwlink/?LinkID=623011"
       }

       #check if Path to resource JSON is ok
       If (Test-Path -Path $TemplateFile)
       {
            Write-Output "$TemplateFile found"
       }
       Else
       {
            Write-Output "$TemplateFile not found, please navigate to the directory where deployscript.ps1 is located and re-run"
            return $false           
       }

       #check if Path to parameter JSON is ok
       If (Test-Path -Path $TemplateParameterFile)
       {
            Write-Verbose "$TemplateParameterFile found"
       }
       Else
       {
            Write-Output "$TemplateFile not found, please navigate to the directory where deployscript.ps1 is located and re-run"
            return $false             
       }


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

       $sleep = $false	

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
		  $AzureIp = (Get-AzureRmNetworkInterface -Name ($ServerName + $i + 'nic1') -ResourceGroupName $ResourceGroupName).IpConfigurations[0].PrivateIpAddress
		  $AzureIp
		  
		  #Setting PrivateIpAllocationMethod to Static
		  'Setting Private IP allocation method to Static...'
		  $Nic = (Get-AzureRmNetworkInterface -Name ($ServerName + $i + 'nic1') -ResourceGroupName $ResourceGroupName)
		  $Nic.IpConfigurations[0].PrivateIpAllocationMethod = 'Static'
		  Set-AzureRmNetworkInterface -NetworkInterface $Nic
		  	  
            if(!$sleep){  # only need to wait once
                'Waiting for 5 minutes before beginning domain join(s)...'
		        Start-Sleep -s (5*60)
                $sleep = $true
            }

            #Get the domain user's SID
            'Getting domain user SID...'
            $DomainCredsString =  $DomainCreds.UserName
            $index = $DomainCredsString.IndexOf('\')
             
            $domain = $DomainCredsString.Substring(0, $index)
            $alias =  $DomainCredsString.Substring($index + 1,$DomainCredsString.length - $index -1)
    
            $objUser = New-Object System.Security.Principal.NTAccount($domain, $alias)
            $Sid = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
            $strSid = $Sid.Value  


            #Add the Domain user to the administrators group on the new VM by SID 
            'Configuring remove computer''s administrators group...'
            
            $script = {
                $ip = $args[0]
                iex $("winrm set winrm/config/client `'@{TrustedHosts=`"$ip`"}`'")
            }

            Invoke-Command -ScriptBlock $script -ArgumentList $AzureIp
            
            $script = {
                $mysid = $args[0]
                $computer = [ADSI]("WinNT://localhost,computer")
                $AdminsGroup=Get-WmiObject -Class Win32_Group -computername localhost -Filter "SID='S-1-5-32-544' AND LocalAccount='True'"
                $grp = $computer.psbase.children.find($AdminsGroup.Name)
                $grp.Add("WinNT://$($mysid)")
            }
    
            invoke-command -computername $AzureIp -ScriptBlock $script -Credential $LocalCreds -ArgumentList $strSid -SessionOption (New-PsSessionOption -SkipCACheck -SkipCNCheck)
          		  
		    
            # Get the destination OU for our domain...
            if($DomainName -imatch "redmond"){
                $OU           = "OU=ITManaged,OU=ITServices,DC=REDMOND,DC=CORP,DC=MICROSOFT,DC=COM"
            }
            elseif ($DomainName -imatch "europe"){
                $OU           = "OU=ITManaged,OU=ITServices,DC=europe,DC=corp,DC=microsoft,DC=com"
            }
            elseif ($DomainName -imatch "northamerica"){
                $OU           = "OU=ITManaged,OU=ITServices,DC=northamerica,DC=corp,DC=microsoft,DC=com"
            }
            elseif ($DomainName -imatch "southpacific"){
                $OU           = "OU=ITManaged,OU=ITServices,DC=southpacific,DC=corp,DC=microsoft,DC=com"
            }
            elseif ($DomainName -imatch "southamerica"){
                $OU           = "OU=ITManaged,OU=ITServices,DC=southamerica,DC=corp,DC=microsoft,DC=com"
            }
            elseif ($DomainName -imatch "africa"){
                $OU           = "OU=ITManaged,OU=ITServices,DC=africa,DC=corp,DC=microsoft,DC=com"
            }
            elseif ($DomainName -imatch "middleeast"){
                $OU           = "OU=ITManaged,OU=ITServices,DC=middleeast,DC=corp,DC=microsoft,DC=com"
            }
            elseif ($DomainName -imatch "fareast"){
                $OU           = "OU=ITManaged,OU=ITServices,DC=fareast,DC=CORP,DC=MICROSOFT,DC=COM"
            }
            else{
                $OU = "Other" 
                "Skipping OU move for domain '$($DomainName)'."             
            }
            
            if($OU -ne 'Other'){

                "Joining computer to the '$($DomainName)' domain in the ITManaged OU..."
    		    Add-Computer -ComputerName $AzureIp -DomainName $DomainName -Credential $DomainCreds -LocalCredential $LocalCreds -OUPath $OU -Restart

	        }
            else{
            

                "Joining computer to the '$($DomainName)' domain in the default OU..."
    		    Add-Computer -ComputerName $AzureIp -DomainName $DomainName -Credential $DomainCreds -LocalCredential $LocalCreds -Restart

            }	  

       
       }
}

deploy -SubscriptionId e4a74065-cc6c-4f56-b451-f07a3fde61de -ResourceGroupLocation "central us" -ResourceGroupName "cptApp1" 
