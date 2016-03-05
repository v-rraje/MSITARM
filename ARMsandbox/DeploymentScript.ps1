#Requires -RunAsAdministrator

function deploy {
       Param(
         [string] [Parameter(Mandatory=$true)] $SubscriptionId,
         [string] [Parameter(Mandatory=$true)] $ResourceGroupLocation,
         [string] [Parameter(Mandatory=$true)] $ResourceGroupName,
         [string] $OuPath = 'OU=ITManaged,OU=ITServices,DC=redmond,DC=corp,DC=microsoft,DC=com',
         [string] $TemplateFile = (Get-Location).Path + '\template.json',
         [string] $TemplateParameterFile = (Get-Location).Path + '\templateParams.json'
       )

       Set-StrictMode -Version 3
       $error.Clear()

       if($PSCmdlet.MyInvocation.BoundParameters['Verbose'] -eq $true) {
            $VerbosePreference = "Continue"
        } else {
            $VerbosePreference = "SilentlyContinue"
        }
       #check root to ensure we are in sandbox

       #Check if PS Module is installed
       try {
            Import-Module Azure -ErrorAction SilentlyContinue
       } catch {
            write-host -f red 'You need to install Azure Powershell.  For help updating this module visit: https://azure.microsoft.com/en-us/downloads/'
            return $false
       }

       #Check if PS Module is right version
       if (Get-Module -ListAvailable | Where-Object { $_.Name -eq 'AzureResourceManager' -and $_.Version -ge '0.9.9' }) {
              write-host -f red "The version of the Azure PowerShell cmdlets installed on this machine are not compatible with this script.  For help updating this script visit: http://go.microsoft.com/fwlink/?LinkID=623011"
              return $false
       }
       
       #check if Path to resource JSON is ok
       If (Test-Path -Path $TemplateFile)
       {
            Write-host -f Gray "$TemplateFile found"
       }
       Else
       {
            write-host -f red  "$TemplateFile not found, please navigate to the directory where deployscript.ps1 is located and re-run"
            return $false
                       
       }

       #check if Path to parameter JSON is ok
       If (Test-Path -Path $TemplateParameterFile)
       {
            Write-host -f Gray "$TemplateParameterFile found"
       }
       Else
       {
           write-host -f red  "$TemplateFile not found, please navigate to the directory where deployscript.ps1 is located and re-run"
           return $false
       }

       #check if add-additionaladmins.ps1 is in path
       If (Test-Path -Path ".\Add-AdditonalAdmins.ps1")
       {
        
            . .\Add-AdditonalAdmins.ps1
                write-verbose "loaded add-additionalAdmins.ps1"

       }else {

            write-host -f red 'You need to Add-AdditonalAdmins.ps1 in your local path.'
            return $false

       }

       try {
            
              #Check if the user is already logged in for this session
              $AzureRmContext = Get-AzureRmContext | out-null
              write-host -f Gray "Using Azure Cached Crentials"

       } catch {

              #Prompts user to login to Azure account
              Login-AzureRmAccount | out-null
              write-host -f Gray "logged into Azure"
       }

       #Selects the Azure subscription to be used
       Set-AzureRmContext -SubscriptionId $SubscriptionId | out-null
         
            if($error) {
                Write-host -f red "stopping due to errors"
                Write-host -f red $error[0]
                $error.Clear()
                return $false
            }

  
       $params = New-Object -TypeName Hashtable
       $TemplateFilePath = [System.IO.Path]::Combine($PSScriptRoot, $TemplateFile)
       $TemplateParameterFilePath = [System.IO.Path]::Combine($PSScriptRoot, $TemplateParameterFile)
       		
		#Request for domain join credentials
		do {
		   
		    $DomainCreds = Get-Credential -Message 'Please enter the domain credentials to join your machine to the domain.'
        
                Add-Type -AssemblyName System.DirectoryServices.AccountManagement
                $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)

		    Try 
            {
                $ValidCredential = $DS.ValidateCredentials($DomainCreds.UserName, $($DomainCreds.GetNetworkCredential().Password))
            } 
            Catch 
            {
                $ValidCredential = $false
            }
              if($validCredential -eq $false){
                Write-host -f red "Invalid Credentials"
                $cont = read-host "Try again? (Y)es"
                if($cont -ne 'Y') {
                    write-host -f Gray "stopping"
                    return $false
                }
               }

        } until ($validcredential -eq $true -or $cont -ne 'Y')
        $error.Clear()
        		
		#Request for local account credentials
		$LocalCreds = Get-Credential -Message 'Please enter the credentials as the local account for the VM'

       #Get contents of the template parameters file
       Write-host -f Gray 'Reading template file contents...'
       $JsonParams = Get-Content $TemplateParameterFile | ConvertFrom-Json
            
       #ensure we have values for VM's, Additional Admins and Diagnostics Storage.
       
        if($JsonParams.parameters.vmName.value.length -eq 0 -or $JsonParams.parameters.vmName.value -eq "[prompt]" ) {
            $JsonParams.parameters.vmName.value = read-host "VMName? " 
        }
	   if($JsonParams.parameters.storageAccountName.value.length -eq 0 -or $JsonParams.parameters.storageAccountName.value -eq "[prompt]" ) {
            $JsonParams.parameters.storageAccountName.value = read-host "storageAccountName for diagnostics? " 
        }
        if($JsonParams.parameters.AdditionalAdmins.value.length -eq 0 -or $JsonParams.parameters.AdditionalAdmins.value -eq "" ) {
            $JsonParams.parameters.AdditionalAdmins.value = read-host "Additional Admins to add? " 
        }
        if($JsonParams.parameters.numberOfInstances.value -eq 0 ) {
            $JsonParams.parameters.numberOfInstances.value = $(read-host "number of instances? ")
            if(!$($JsonParams.parameters.numberOfInstances.value -ge 1)){
                write-host -f red "Number of instances must be => 1"
                return $false
            }
        }
        if($JsonParams.parameters.vmName.value.length -eq 0 -or $JsonParams.parameters.vmName.value -eq "none" ) {
            $JsonParams.parameters.vmName.value = read-host "VMName? " 
        }

       #Get server name
       $ServerName = $JsonParams.parameters.vmName.value
      

       #Get number of VMs to be created
       $NumberOfInstances = $JsonParams.parameters.numberOfInstances.value
       
       #Get domain name
       $DomainName = $JsonParams.parameters.domainName.value

       #populate parameters with local account 
       $JsonParams.parameters.LocalAdminUserName.Value = $LocalCreds.UserName
       $JsonParams.parameters.LocalAdminPassword.Value = $($LocalCreds.GetNetworkCredential().Password)
     
        try {
        #build a Hashtable with Parameters
        $params = @{
                   "localAdminUserName"=$JsonParams.parameters.LocalAdminUserName.Value; `
                   "localAdminPassword"=$JsonParams.parameters.LocalAdminPassword.Value; `
                   "vmName"=$JsonParams.parameters.vmName.Value; `
                   "additionalAdmins"=$JsonParams.parameters.additionalAdmins.Value; 
                   "APPid"=$JsonParams.parameters.APPid.Value; `
                   "domainName"=$JsonParams.parameters.domainName.Value; `
                   "env"=$JsonParams.parameters.env.Value; `
                   "numberOfInstances"=$JsonParams.parameters.numberOfInstances.Value; `
                   "orgID"=$JsonParams.parameters.orgID.Value; `
                   "sku"=$JsonParams.parameters.sku.Value; `
                   "snoozeDate"=$JsonParams.parameters.snoozeDate.Value; `
                   "storageAccountType"=$JsonParams.parameters.storageAccountType.Value; `
                   "userImageStorageAccountName"=$JsonParams.parameters.userImageStorageAccountName.Value; `
                   "vmSize"=$JsonParams.parameters.vmSize.Value; `
                   "vnetId"=$JsonParams.parameters.vnetId.Value; `
                   "storageAccountName"=$JsonParams.parameters.storageAccountName.Value; `
                  }

            } catch {
         
            write-host -f red $error[0]
            $error.Clear()
            return $false
            }

           do {
            $building= get-AzureRmResourceGroupDeployment -ResourceGroupName $resourceGroupName | ? {$_.provisioningstate -ne 'Failed' -and $_.provisioningstate -ne 'Succeeded' -and $_.provisioningstate -ne 'Canceled'}
            if($building) {
                Write-host -f Gray 'Another Deployment is in progress, sleeping.'
                write-host -f Gray "$($building.DeploymentName) is $($building.ProvisioningState) at $($building.Timestamp) "
                Start-Sleep -s 30
            }
           } until (!$building)

            try {

           $buildTemplate= New-AzureRmResourceGroupDeployment -Name (('ARMDomainJoinVM-') + ((Get-Date).ToUniversalTime()).ToString('MMdd-HHmm')) `
                                                                 -ResourceGroupName $ResourceGroupName `
                                                                 -TemplateFile $TemplateFilePath `
                                                                 -TemplateParameterObject $params `
                                                                 -Force -Verbose

                write-host -f Gray "$($buildTemplate.DeploymentName) status of $($buildTemplate.ProvisioningState) on $($buildTemplate.Timestamp)"
            } catch {
                Write-host -f red "stopping due to errors"
                Write-host -f red $error[0]
                $error.Clear()
                return $false
            }
           

        $sleep = $false	

        for ($i = 0; $i -lt $NumberOfInstances; $i++) {
            #Check VM status
            $VmIsReady = $false
            while(!$VmIsReady) {
                $s=$ServerName+$i
               Write-host -f Gray  "Checking VM $($s) status..."
                Start-Sleep -s 30
				
				$VmStatuses = (Get-AzureRmVm -ResourceGroupName $ResourceGroupName -Name ($ServerName + $i) -Status).VMAgent.Statuses.DisplayStatus
				If($VmStatuses -eq 'Ready'){
					Write-host -f Gray 'VM is ready and running'
					$VmIsReady = $true
				}	
			}
		  
		  #Get IP address of the VM
		  Write-host -f Gray 'Getting VM IP address...'
		  $AzureIp = (Get-AzureRmNetworkInterface -Name ($ServerName + $i + 'nic1') -ResourceGroupName $ResourceGroupName).IpConfigurations[0].PrivateIpAddress
		   Write-host -f Gray "$($ServerName + $i) => IPAddress = $AzureIp"
		  
		  #Setting PrivateIpAllocationMethod to Static
		  Write-host -f Gray 'Setting Private IP allocation method to Static...'
		  $Nic = (Get-AzureRmNetworkInterface -Name ($ServerName + $i + 'nic1') -ResourceGroupName $ResourceGroupName)
		  $Nic.IpConfigurations[0].PrivateIpAllocationMethod = 'Static'
		  $nicData= Set-AzureRmNetworkInterface -NetworkInterface $Nic
		   
            write-host -f Gray "$($nicData.ResourceGroupName) status of $($nicData.ProvisioningState)"

            Write-host -f Gray 'Configuring WinRM...'
            
                $script = {
                    $ip = $args[0]
                    iex $("winrm set winrm/config/client `'@{TrustedHosts=`"$ip`"}`'")
                }

                $result = Invoke-Command -ScriptBlock $script -ArgumentList $AzureIp
                        
            if(!$sleep){  # only need to wait once
                Write-host -f Gray 'Waiting for 1 minutes for the NIC to setup...'
		        Start-Sleep -s (1*60)
                $sleep = $true
            }


             $isInDomain=$(invoke-command -computername $AzureIp -scriptblock {((gwmi win32_computersystem).partofdomain)} -ErrorAction SilentlyContinue -Credential ($DomainCreds) -SessionOption (New-PsSessionOption -SkipCACheck -SkipCNCheck))

          if(!$isInDomain) {
            $error.clear()  #above generates error until machine is Domain joined
            
            try {
            
                #Get the domain user's SID
               Write-host -f Gray  'Getting domain user SID...'
                $DomainCredsString =  $DomainCreds.UserName
                $index = $DomainCredsString.IndexOf('\')
             
                $domain = $DomainCredsString.Substring(0, $index)
                $alias =  $DomainCredsString.Substring($index + 1,$DomainCredsString.length - $index -1)
    
                $objUser = New-Object System.Security.Principal.NTAccount($domain, $alias)
                $Sid = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
                $strSid = $Sid.Value  


                #Add the Domain user to the administrators group on the new VM by SID 
               
                $script = {
                    try{
                    $mysid = $args[0]
                    $myuser = $args[1]
                    $mypwd = $args[2]

                    $computer = [ADSI]("WinNT://localhost,computer")
                    $AdminsGroup=Get-WmiObject -Class Win32_Group -computername localhost -Filter "SID='S-1-5-32-544' AND LocalAccount='True'"
                    $grp = $computer.psbase.children.find($AdminsGroup.Name)
                    $grp.Add("WinNT://$($mysid)")
                    }catch{
                        if(!$([string] $error[0] -match 'already a member')) {
                         throw $error[0]
                        } else {
                            $error.clear()
                        }

                    }

                    #Create a sched task on the RB server to configure WinRM via PSExec...
                    $A = New-ScheduledTaskAction  -Execute "PSExec.exe" -Argument "\\$($env:Computername) -acceptEula -s -h -n 10 cmd /c winrm quickconfig -q -force"
                    $T = New-ScheduledTaskTrigger -AtStartup
                    $S = New-ScheduledTaskSettingsSet
                    $D = New-ScheduledTask -Action $A -Trigger $T -Settings $S
                    
                    $task=Register-ScheduledTask "winrm quickconfig" -InputObject $D -Password $mypwd -User $($env:computername+"\"+$myuser)
                
                    write-output "$($task.TaskName) is $($task.State) to run AtStartup"
                }
    
                invoke-command -computername $AzureIp -ScriptBlock $script -Credential $LocalCreds -ArgumentList $strSid,$LocalCreds.UserName,$($LocalCreds.GetNetworkCredential().Password) -SessionOption (New-PsSessionOption -SkipCACheck -SkipCNCheck)
                                

          	 } catch{
                write-host -f red $error[0]
                return $false
             }

            #only if the above completes succeffully do we want to join the domain.
            if(!$error) { 
		        
                try {

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

                           Write-host -f Gray  "Joining computer to the '$($DomainName)' domain in the ITManaged OU..."
    		                Add-Computer -ComputerName $AzureIp -DomainName $DomainName -Credential $DomainCreds -LocalCredential $LocalCreds -OUPath $OU -Restart

	                    }
                        else{
            

                            Write-host -f Gray "Joining computer to the '$($DomainName)' domain in the default OU..."
    		                Add-Computer -ComputerName $AzureIp -DomainName $DomainName -Credential $DomainCreds -LocalCredential $LocalCreds -Restart

                        }	  
            
                    } catch {
                        write-error $error
                        break;
                    }
            }
            }          

            if($JsonParams.parameters.additionalAdmins.value.length -gt 0) {
                
                do {
                    Start-Sleep -s 60
                    $VmStatuses = (Get-AzureRmVm -ResourceGroupName $ResourceGroupName -Name ($ServerName + $i) -Status).VMAgent.Statuses.DisplayStatus
				    If($VmStatuses -eq 'Ready'){
					   Write-host -f Gray  'VM is ready and running after reboot'
					    $VmIsReady = $true
				    } else {
                        Write-host -f Gray  'VM isnt ready and running after reboot...sleeping.'
                        Start-Sleep -s 60
                    }
                } until ($VmIsReady -eq $true)
            
                Write-host -f Gray  'Adding Additional Admins'
                Add-AdditionalAdmins -computername $AzureIp -UserAccounts $JsonParams.parameters.additionalAdmins.value -cred $DomainCreds 

            }
         
       }
}

deploy -SubscriptionId e4a74065-cc6c-4f56-b451-f07a3fde61de -ResourceGroupLocation "central us" -ResourceGroupName "cptApp1" #-Verbose
