1.	Open Powershell ISE and navigate to the directory where this module is locally on your computer
2.	Open sample.ps1 in powershell ISE editor.  
3.	Update $subID to the sandbox subscription ID
4.	Run sample.ps1
5.	Get help on each command
#Discover our commandlets
get-command -Module arm_module

#get details just like any other commandlet
help add-policy -full
help Add-SDOManagedExpressRouteUserRole -full
help Set-DevOpsPermissions -Full 
6.	Set-DevOpsPermissions is the commandlet you use for assigning DevOps permissions
