#Requires -RunAsAdministrator
Function Initialize-CloudMS(){

$repoName='CloudMSPSRepository'
$ModuleName='CloudMS'

if($PSVersionTable.PSVersion.Major -ge 5) {
		write-host -ForegroundColor Green "Powershell 5.0 found"
	} else {

		write-host -ForegroundColor Red "Install PS version 5 for autoupdates. see https://www.microsoft.com/en-us/download/details.aspx?id=50395"
        return
	}

$Exists=Get-PSRepository | ? {$_.SourceLocation -match "co1-cu-sjobs01"}

if(!$Exists){

	$ret=Register-PSRepository -Name $repoName -SourceLocation \\co1-cu-sjobs01\e$\PackageRoot -PublishLocation http://co1-cu-sjobs01/ -InstallationPolicy Trusted -ScriptSourceLocation \\co1-cu-sjobs01\e$\PackageRoot
  
} else {
	$repoName = $exists.name
}
	
 $module = find-module -Repository $repoName -Name $moduleName | select version

 install-module -name $moduleName -RequiredVersion $module.Version -force
}
Initialize-CloudMS