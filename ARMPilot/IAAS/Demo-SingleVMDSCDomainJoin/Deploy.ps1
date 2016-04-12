
if (Get-Module -ListAvailable -Name CloudMS) {
   import-module cloudms -Force
} else {
    Write-Host "Module CloudMS does not exist, you must instal it first."
    break;
}

 $global:ProvisionVM = $true
 $global:ProvisionDataDisks = $true
 $global:BuildServer = $true
 $global:ConfigurePullServer = $true

 function Global:start-work(){
    $baseURL="."
    $basePath = $(get-location).path

    $vmName= Read-Host -Prompt "VM Name?"
    $vmType= Read-Host -Prompt "Type (IIS/SQL/App)?"
    $AzureSku=[string]$(Read-Host -Prompt "Azure SKU(A2,A3,A4,D4,Standard_d2)?")

    $params = @{
                   "TemplateFile"=".\template-SingleVM.json"; 
                   "TemplateParameterFile"=".\params-Windows.json"; 
                   "SubscriptionId"="e4a74065-cc6c-4f56-b451-f07a3fde61de"; 
                   "ResourceGroupLocation"="central us"; 
                   "ResourceGroupName"="cptApp1";
                   "Domain"="Redmond.corp.microsoft.com";
                   "vmName"=$vmName;
                   "AzureSku"=$AzureSku
                  }

    if($vmType -eq 'SQL') {$params.TemplateParameterFile=".\Params-SQL.json";}

    if($ProvisionVM) {

        $username= Read-Host -Prompt "Domain UserName (domainname\alias)"
        $password =Read-Host -Prompt "Password for $username" -AsSecureString
        $domainUserCredential = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $password

         write-host -f gray "Loading Parameters $($Params.TemplateParameterFile) for $($params.vmName)"
         $TempParams = Import-ProvisionVMParameters -TemplateParameterFile $Params.TemplateParameterFile -vm $params.vmName
       
         $u=$([string] $TempParams.localAdminUserName)
         $p= ConvertTo-SecureString $([string] $TempParams.localAdminPassword) -asplaintext -force
         $LocalUserCredential = New-Object System.Management.Automation.PSCredential -ArgumentList $u,$p
         $params.Domain = $TempParams.domainName
         
        write-host -f green "-----------------------------"
        Write-host -f green "  Provision Virtual Machine    "            
        write-host -f green "-----------------------------"
              
        $serversBuilt=Invoke-ARMDomainVM -TemplateFile $params.TemplateFile `
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

        $params.TemplateFile=".\template-DataDisks.json"; 
        $params.TemplateParameterFile=".\Params-DataDisks.json"; 

        write-host -f gray "Loading Parameters $($Params.TemplateParameterFile) for $($params.vmName)"
        $diskparams = Import-FormatDiskParameters -TemplateParameterFile $Params.TemplateParameterFile -VM $Params.vmName

	    $diskparams.AzureSKU = $([string] $params.AzureSku)
             
        Invoke-ARMParam -TemplateFile $params.TemplateFile `
                                -params $diskparams `
                                -SubscriptionId $params.SubscriptionId `
                                -ResourceGroupLocation $params.ResourceGroupLocation `
                                -ResourceGroupName $params.ResourceGroupName 
                        
    }

    if($vmType -eq 'IIS' -and $BuildServer) {

    write-host -f green "-----------------------------"
    Write-host -f green "  Build IIS"            
    write-host -f green "-----------------------------"

     $params.TemplateFile=".\template-BuildIIS.json"; 
     $params.TemplateParameterFile=".\Params-BuildIIS.json"; 

    $IISparams = Import-BuildParameters -TemplateParameterFile $Params.TemplateParameterFile -VM $Params.vmName

        Invoke-ARMParam -TemplateFile $params.TemplateFile `
                            -params $IISparams `
                            -SubscriptionId $params.SubscriptionId `
                            -ResourceGroupLocation $params.ResourceGroupLocation `
                            -ResourceGroupName $params.ResourceGroupName 

    }

    if($ConfigurePullServer) {

        write-host -f green "-----------------------------"
        Write-host -f green "  Configure PUll server"            
        write-host -f green "-----------------------------"

        $params.TemplateFile=".\template-ConfigureDSCPull.json"; 
        $params.TemplateParameterFile=".\params-ConfigureDSCPull.json"; 

        $DSCPullServerparams = Import-DSCPullParameters -TemplateParameterFile $Params.TemplateParameterFile -VM $Params.vmName
                           
        $serversBuilt=Invoke-ARMParam -TemplateFile $params.TemplateFile `
                                 -params $DSCPullServerparams `
                                -SubscriptionId $params.SubscriptionId `
                                -ResourceGroupLocation $params.ResourceGroupLocation `
                                -ResourceGroupName $params.ResourceGroupName 
    }
}

 write-host ""
 get-Work
 write-host ""