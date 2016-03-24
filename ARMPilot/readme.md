
CloudMS Module

Module built on Powershell 3.0
Module Installer built on Powershell 5.0

Module Installation Steps

	1. Open a Powershell window as Administrator
	2. Execute Initialize-CloudMS.ps1 (example . .\Initialize-CloudMS.ps1)


Workflow Test Scenarios

Steps:
	1. Open a Powershell window as Administrator
	2. Change directory to templates
	3. Execute Demo-SingleVM

		.\Demo-SingleVM.ps1 

Open Powershell as Admini

1. Create 1 VM using the name provided (Automation example)
	using template-SingleVM.json and templateParams.json, 

		see Demo-SingleVM.ps1

uses: template.json 
	 templateParams.json

2. Create 1 or more VM's using the name part provided
	using a NamePart and template-MultipleVM.json and templateParams.json

		see Demo-MultipleVM.ps1

uses: template-MultipleVM.json 
	 templateParams.json

	
3. Create 1 or More IIS vms using the name part provided
	using a NamePart and template-MultipleVM.json and templateIISParams.json

		see Demo-MutipleIIS.ps1

uses: templateIIS.json 
	 templateIISParams.json


4. Create 1 or more SQL VMs using the name part provided
	using a NamePart and template-MultipleVM.json and templateSQLParams.json

		see Demo-MutipleSQL.ps1

uses: templateSQL.json 
	 templateSQLParams.json



Main Module Functions get-help for info

Invoke-Arm -parameter validation

Invoke-ArmFiles -no parameter validation

Install-AdditionalAdmins -Adds Additional Admins

Install-VMDomainJoin -DomainJoins VMS

Import-Templates -Imports templates and param into Hashtable.

Get-AzureRMVMInResourceGroup - gets VMS in resource group.
						Optional servers filter 

Get-VMBuildStatus gets VM status (can wait) 
Get-VMWinRMStatus checks if WINRM working (can wait)

