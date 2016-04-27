Deploy from Azure Portal (UI Experience) 

\IAAS\Demo-SingleVMDSCDomainJoin\azuredeploy.json
Description: SingleVM that leverages DSC for domain join
Steps:
	1.  Create your storage acount that you want to deploy to.  
		New-AzureRmStorageAccount -ResourceGroupName "yourRG" -AccountName "yourStorageAccountName" -Location "centralus" -Type "Standard_GRS" -Tags @{Name = "AppID"; Value = "enteryourValue"}, @{Name="OrgID";Value="enteryourValue"},@{Name="Env";Value="enteryourValue"}
		Create a blob container called "vhds".  You can do this through the Azure Portal. 
	2.  Logon to http://portal.azure.com
	3.  New and search for "Template Deployment"
	4.  Copy and paste the contents of deploy.json into "Edit Template"
	5.  Update all Parameters
	6.  Follow the rest of the UI


Deploy from Powershell (Dev Experience) 

This is a two step process, first you need to install the module and then you need to run the deployment script.

Module Installation Steps

	1. Open a Powershell window as Administrator
	2. Register-PSRepository -Name 'CloudMSPSRepository' -SourceLocation \\co1-cu-sjobs01\CloudMSPSRepository -PublishLocation http://co1-cu-sjobs01/ -InstallationPolicy Trusted -ScriptSourceLocation \\co1-cu-sjobs01\CloudMSPSRepository
	3. Install-PackageProvider -Name NuGet -Force 
	3. Install-Module CloudMS -force
	4. Import-Module CloudMS -force

Domain Joined VM provisioning Steps 

\IAAS\Demo-SingleVMDSCDomainJoin\deploy.ps1
Description: SingleVM that leverages DSC for domain join, configuration, and set-up of DSC pull configurations for server hardening
Steps:
	1.  Create your storage acount that you want to deploy to.  
		New-AzureRmStorageAccount -ResourceGroupName "yourRG" -AccountName "yourStorageAccountName" -Location "centralus" -Type "Standard_GRS" -Tags @{Name = "AppID"; Value = "enteryourValue"}, @{Name="OrgID";Value="enteryourValue"},@{Name="Env";Value="enteryourValue"}
		Create a blob container called "vhds".  You can do this through the Azure Portal. 
	2.  Update Parameters
			Params-Windows.json or params-SQL.json
			•	"userImageStorageAccountName"
			•	"domainName"
			•	"vnetId"
			•	"ouPath"
			•	"appID"
			•	"orgID"
			•	"env"
			Deploy.ps1
			•	SubscriptionId 
			•	ResourceGroupName 
	2. Open a Powershell window as Administrator
	3. Change directory to location of deploy.ps1
	4. .\deploy.ps1 
	5.  start-work

