#
# Initialize_CloudMS.ps1
#
Function Initialize-CloudMS(){
$repoName='CloudMSPSRepository'
$ModuleName='CloudMS'

$Exists=Get-PSRepository | ? {$_.SourceLocation -match "co1-cu-sjobs01"}

if(!$Exists){

	$ret=Register-PSRepository -Name $repoName -SourceLocation \\co1-cu-sjobs01\e$\PackageRoot -PublishLocation http://co1-cu-sjobs01/ -InstallationPolicy Trusted -ScriptSourceLocation \\co1-cu-sjobs01\e$\PackageRoot
  
} else {
	$repoName = $exists.name
}
	
 $module = find-module -Repository $repoName -Name $moduleName | select version

 install-module -name $moduleName -RequiredVersion $module.Version -force
}