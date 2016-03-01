#requires -Version 2 -Modules Azure, AzureRM.Resources
function Add-SDOManagedExpressRouteUserRole
{
    #this allows for cmdlet-style parameter binding capabilities
    [CmdletBinding()]
    Param
	(
    [Parameter(Mandatory=$true)]
    [string]$subscriptionID
	)

    #variables
    $role = 'SDO Managed ExpressRoute User'
    $subScope = '/subscriptions/{0}/' -f $subscriptionID
    $subIDparent = '28077388-3f00-4938-9481-e4e87bc59972' #SDO-Managed-CoreRP 

    #Switch subscriptions to parent
    Write-Verbose 'Getting SDO Managed ExpressRoute User role'
    Select-AzureRMSubscription -SubscriptionID $subIDparent | Out-Null
    $roleDef = Get-AzureRMRoleDefinition $role

    #Switch to child sub and add it to ER role
    Write-Verbose 'Try assigning child subscription'
    Select-AzureRmSubscription -SubscriptionId $subscriptionID | Out-Null

    Write-Verbose "Checking if $role exists already permissions"
    If (($roleDef.AssignableScopes | Where-Object {$_ -like "*$subscriptionID*"}) -eq $null)
    {
    $roleDef.AssignableScopes.Add($subScope)
    Write-Verbose "Added scope for $subScope"        
    }
    Else
    {        
    Write-Verbose "Scope exists for $subScope, skip adding to role definition" 
    }

    #Switch back to parent and set ER role
    Write-Verbose 'Save changes'
    Select-AzureRMSubscription -SubscriptionID $subIDparent | Out-Null
    Set-AzureRmRoleDefinition -Role $roleDef | Out-Null

    #back to child sub
    Select-AzureRmSubscription -SubscriptionId $subscriptionID | Out-Null

    #Check if role exists now
    Write-Verbose -Message "Checking to see if $role exists"
    $checkRole = Get-AzureRmRoleDefinition -Name $role
    If ($checkRole -eq $null)
    {
        Write-Verbose -Message "Adding $role failed"
        return $false  
    }

    Write-Verbose -Message "$role exists on $subscriptionID"
    return $true
	

    <#
            .SYNOPSIS
            Creates a custom role called "SDO Managed ExpressRoute User". 
            .DESCRIPTION
            This is the reader role plus Microsoft.Network/virtualNetworks/subnets/join/action/* permissions.  It is a necessary for domain joining resources
            .INPUTS
            None. 
            .OUTPUTS
            $true or $false
            -Verbose gives step by step output
            .EXAMPLE 
            $subID = e8a32032-cc6c-4x56-b451-f07x3fdx47xx 		 		 
            Add-SDOManagedExpressRouteUserRole -subscriptionID $subID -Verbose
    #>	
}