
if (Get-Module -ListAvailable -Name CloudMS) {
   import-module cloudms_beta -Force
} else {
    Write-Host "Module CloudMS does not exist, you must instal it first."
    break;
}

 
 $baseURL = "http://cptteamb.blob.core.windows.net/cloudmsvm"
 $basePath="."

 $global:ProvisionVM = $true
 $global:ProvisionDataDisks = $true
 $global:BuildServer = $true
 $global:ConfigurePullServer = $true

 function Global:start-work(){

    $vmName= Read-Host -Prompt "VM Name?"
    $vmType= Read-Host -Prompt "Type (IIS/SQL/App)?"
    $AzureSku=[string]$(Read-Host -Prompt "Azure SKU(A2,A3,A4,D4,Standard_d2)?")

    $params = @{
                   "TemplateURI"="$baseURL/template-SingleVM.json"; 
                   "TemplateParameterFile"="$basePath\params-Windows.json"; 
                   "SubscriptionId"="e4a74065-cc6c-4f56-b451-f07a3fde61de"; 
                   "ResourceGroupLocation"="central us"; 
                   "ResourceGroupName"="cptApp1";
                   "Domain"="Redmond.corp.microsoft.com";
                   "vmName"=$vmName;
                   "AzureSku"=$AzureSku
                  }

    if($vmType -eq 'SQL') {$params.TemplateParameterFile="$basePath\Params-SQL.json";}

    if($ProvisionVM) {

        $username= Read-Host -Prompt "Domain UserName (domainname\alias)"
        $password =Read-Host -Prompt "Password for $username" -AsSecureString
        $domainUserCredential = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $password

         $TempParams = Import-ProvisionVMParameters -TemplateParameterFile $Params.TemplateParameterFile -vm $params.vmName
 
         $u=$([string] $TempParams.localAdminUserName)
         $p= ConvertTo-SecureString $([string] $TempParams.localAdminPassword) -asplaintext -force
         $params.Domain = $TempParams.domainName

         $LocalUserCredential = New-Object System.Management.Automation.PSCredential -ArgumentList $u,$p

        write-host -f green "-----------------------------"
        Write-host -f green "  Provision Virtual Machine    "            
        write-host -f green "-----------------------------"
              
        $serversBuilt=Invoke-ARMDomainVM -TemplateURI $params.TemplateURI `
                                -TemplateParameterFile $params.TemplateParameterFile `
                                -SubscriptionId $params.SubscriptionId `
                                -ResourceGroupLocation $params.ResourceGroupLocation `
                                -ResourceGroupName $params.ResourceGroupName `
                                -Vm $params.vmName `
                                -AzureSku $params.AzureSku `
                                -creds $domainUserCredential 

    }
 
    if($ProvisionDataDisks) {

        write-host -f green "-----------------------------"
        Write-host -f green "  Provision DataDisks"            
        write-host -f green "-----------------------------"

        $params.TemplateURI="$baseURL\template-DataDisks.json"; 
        $params.TemplateParameterFile="$basePath\Params-DataDisks.json"; 

        $diskparams = Import-FormatDiskParameters -TemplateParameterFile $Params.TemplateParameterFile -VM $Params.vmName

	    $diskparams.AzureSKU = $([string] $params.AzureSku)
             
        Invoke-ARMParam -TemplateURI $params.TemplateURI `
                                -params $diskparams `
                                -SubscriptionId $params.SubscriptionId `
                                -ResourceGroupLocation $params.ResourceGroupLocation `
                                -ResourceGroupName $params.ResourceGroupName 
                        
    }

    if($vmType -eq 'IIS' -and $BuildServer) {

    write-host -f green "-----------------------------"
    Write-host -f green "  Build IIS"            
    write-host -f green "-----------------------------"

    $params.TemplateURI="$baseURL\Template-BuildIIS.json"; 
    $params.TemplateParameterFile="$basePath\Params-IIS.json"; 
                   
        Invoke-ARMParam -TemplateURI $params.TemplateURI `
                            -TemplateParameterFile $params.TemplateParameterFile `
                            -SubscriptionId $params.SubscriptionId `
                            -ResourceGroupLocation $params.ResourceGroupLocation `
                            -ResourceGroupName $params.ResourceGroupName 

    }

     if($vmType -eq 'IIS' -and $BuildServer) {

    write-host -f green "-----------------------------"
    Write-host -f green "  Build SQL"            
    write-host -f green "-----------------------------"

    $params.TemplateURI="$baseURL\Template-BuildSQL.json"; 
    $params.TemplateParameterFile="$basePath\Params-SQL.json"; 
                   
        Invoke-ARMParam -TemplateURI $params.TemplateURI `
                            -TemplateParameterFile $params.TemplateParameterFile `
                            -SubscriptionId $params.SubscriptionId `
                            -ResourceGroupLocation $params.ResourceGroupLocation `
                            -ResourceGroupName $params.ResourceGroupName 

    }


    if($ConfigurePullServer) {

        write-host -f green "-----------------------------"
        Write-host -f green "  Configure PUll server"            
        write-host -f green "-----------------------------"

        $params.TemplateURI="$baseURL\template-ConfigureDSCPull.json"; 
        $params.TemplateParameterFile="$basePath\params-ConfigureDSCPull.json"; 
                   
        $serversBuilt=Invoke-ARMParam -TemplateURI $params.TemplateURI `
                                -TemplateParameterFile $params.TemplateParameterFile `
                                -SubscriptionId $params.SubscriptionId `
                                -ResourceGroupLocation $params.ResourceGroupLocation `
                                -ResourceGroupName $params.ResourceGroupName 
    }
}

 write-host ""
 get-Work
 write-host ""