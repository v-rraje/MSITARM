Deploy from Azure Portal (UI Experience) 

\301-single-vm-domain-join-build-dsc
Description: SingleVM that leverages DSC for domain join
Steps:
	1.  Create your storage acount that you want to deploy to.  
		New-AzureRmStorageAccount -ResourceGroupName "yourRG" -AccountName "yourStorageAccountName" -Location "centralus" -Type "Standard_GRS" -Tags @{Name = "AppID"; Value = "enteryourValue"}, @{Name="OrgID";Value="enteryourValue"},@{Name="Env";Value="enteryourValue"}
		Create a blob container called "vhds".  You can do this through the Azure Portal. 
	2.  Logon to http://portal.azure.com
	3.  New and search for "Template Deployment"
	4.  Copy and paste the contents of azuredeploy.json into "Edit Template"
	5.  Update all Parameters
	6.  Follow the rest of the UI


