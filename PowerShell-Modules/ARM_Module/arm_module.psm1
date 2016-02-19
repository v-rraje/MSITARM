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

function Add-Policy
{
    #this allows for cmdlet-style parameter binding capabilities
    [CmdletBinding()]
    Param( 
        [Parameter(Mandatory=$true)]
        [ValidateSet('SDOStdPolicyTags','SDOStdPolicyNetwork','SDOStdPolicyRegion')] 
        [String] 
        $policy,
        
        [Parameter(Mandatory=$true)]
        [string]$subscriptionID
     )

    #string manipulation
    $scope = '/subscriptions/{0}/' -f $subscriptionID
    Write-Verbose -Message "SubscriptionID is $subscriptionID"

    #string manipulation
    $policy = $policy.ToLower()
    
    #Create policy and assign it at the subscription level
    switch ($policy) 
    { 
        'sdostdpolicytags' 
        {
            try
            {
                #Set Policy for SDOStdPolicyTags
                $polDef = New-AzureRmPolicyDefinition -Name SDOStdPolicyTags -Description 'Mandatory tags for billing and ServiceNow integration' -Policy '{
                  "if": {
                    "not": {
                      "AnyOf": [
                        {
                          "AllOf": [
                            {
                              "field": "tags",
                              "containsKey": "appID"
                            },
                            {
                              "field": "tags",
                              "containsKey": "env"
                            },
                            {
                              "field": "tags",
                              "containsKey": "orgID"
                            }
                          ]
                        },
                        {
                          "AllOf": [
                            {
                              "field": "tags",
                              "containsKey": "orgID"
                            },
                            {
                              "field": "tags",
                              "containsKey": "AppTechComponentID"
                            }
                          ]
                        }
                      ]
                    }
                  },
                  "then": {
                    "effect": "deny"
                  }
                }'
                
          
                #apply at subscription level
                New-AzureRmPolicyAssignment -Name SDOStdPolicyTags -PolicyDefinition $polDef -Scope $scope | Out-Null
          
                Write-Verbose 'SDOStdPolicyTags policy created successfully'
            }
            catch 
            {
                Write-Verbose 'SDOStdPolicyTags policy creation failed'
                exit
            }
        } 
        'sdostdpolicynetwork' 
        {
            try
            {
                #Set Policy for SDOStdPolicyNetwork
                $polDef = New-AzureRmPolicyDefinition -Name SDOStdPolicyNetwork -Description 'No endpoints, no V1 resources, and some network resources' -Policy '{
                    "if": {
                    "anyOf": [
                    {
                    "source": "action",
                    "like": "Microsoft.Network/publicIPAddresses/*"
                    },
                    {
                    "source": "action",
                    "like": "Microsoft.Network/routeTables/*"
                    },
                    {
                    "source": "action",
                    "like": "Microsoft.Network/networkSecurityGroups/*"
                    },
                    {
                    "source": "action",
                    "like": "Microsoft.ClassicCompute/*"
                    },
                    {
                    "source": "action",
                    "like": "Microsoft.ClassicStorage/*"
                    },
                    {
                    "source": "action",
                    "like": "Microsoft.ClassicNetwork/*"
                    }
                    ]
                    },
                    "then": {
                    "effect": "deny"
                    }
                }'
                
                         
                #apply at subscription level
                New-AzureRmPolicyAssignment -Name SDOStdPolicyNetwork -PolicyDefinition $polDef -Scope $scope | Out-Null
          
                Write-Verbose 'SDOStdPolicyNetwork policy created successfully'
            }
            catch 
            {
                Write-Verbose 'SDOStdPolicyTags policy creation failed'
                exit
            }

        } 
        'sdostdpolicyregion' 
        {
            try
            {
                #Set Policy for SDOStdPolicyRegion
                $polDef = New-AzureRmPolicyDefinition -Name SDOStdPolicyRegion -Description 'All resources in Central US' -Policy '{
                  "if": {
                    "not": {
                      "field": "location",
                      "in": [ "centralus" ]
                    }
                  },
                  "then": {
                    "effect": "deny"
                  }
                }'
                

          
                #apply at subscription level
                New-AzureRmPolicyAssignment -Name SDOStdPolicyRegion -PolicyDefinition $polDef -Scope $scope | Out-Null
          
                Write-Verbose 'SDOStdPolicyRegions policy created successfully'
            }
            catch 
            {
                Write-Verbose 'SDOStdPolicyRegions policy policy creation failed'
                exit
            }
        } 
        default 
        {
            write-output 'Should never get here, switch statement didnt match a case'
        }
    }

    return $true

    <#
            .SYNOPSIS
            Creates and applies standard SDO policies at the subscription level
            .DESCRIPTION
            This is broken by 3 functional areas: network, tags, and 
            .INPUTS
            Policy from this set: 'SDOStdPolicyTags','SDOStdPolicyNetwork','SDOStdPolicyRegion' 
            .OUTPUTS
            $true or $false
            -Verbose gives step by step output
            .EXAMPLE
            $subID = e8a32032-cc6c-4x56-b451-f07x3fdx47xx 		  		 
            Add-Policy -policy SDOStdPolicyNetwork -subscriptionID  $subID -Verbose
            .EXAMPLE 
            $subID = e8a32032-cc6c-4x56-b451-f07x3fdx47xx 	
            Add-Policy -policy SDOStdPolicyTags -subscriptionID  $subID -Verbose
            .EXAMPLE 
            $subID = e8a32032-cc6c-4x56-b451-f07x3fdx47xx 
            Add-Policy -policy SDOStdPolicyRegion -subscriptionID  $subID -Verbose

    #>	
}

function Set-DevOpsPermissions
{
    #this allows for cmdlet-style parameter binding capabilities
    [CmdletBinding()]
    Param( 
        [Parameter(Mandatory=$true)]
        [String] $subscriptionID,

        [Parameter(Mandatory=$true)]
        [String] $appRG,

        [Parameter(Mandatory=$true)]
        [String] $ERRG,

        [Parameter(Mandatory=$false)]
        [String] $location='Central US',

        [parameter(parametersetname="byemail")]
        $email,

        [parameter(parametersetname="byGroupName")]
        $groupName,

        [parameter(parametersetname="byObjectID")]
        $objectID


     )

     switch($PsCmdlet.ParameterSetName)

    {

        "byemail" {
            
            Write-Verbose 'Checking if Email acccount exists'
            $objAD = Get-AzureRmADUser -Mail $email
            $objectID = $objAD.Id
            If ($objectID -eq $null) 
            {
                Write-Output 'Please specify a valid email address such as someuser@microsoft.com'
                Write-Output "If this is a group, you will have to use -objectID here's an example"   
                Write-Output "Get-AzureRmADGroup -SearchString 'Cloud Platform Tools - Team B'" 
                return $false
            } 
             
        }

        "byGroupName" {

            Write-Verbose -Message "Checking if group alias '$($groupName)'exists..."
            $objAD = Get-AzureRmADGroup -SearchString $groupName
            
            If ($objAD.Count -ne 1) { # may return more than one result if a partial match is found
            
                Write-Output "Please specify a valid, full security group display name.  For example, use 'CPT-Reports' instead of 'CPT'."
                Write-Output "If this is a group with multiple matches, you will have to use -objectID here's an example"   
                Write-Output "Get-AzureRmADGroup -SearchString 'Cloud Platform Tools - Team B'" 
                Return $false
            
            }

            $objectID = $objAD.Id
            
            Write-Verbose -Message "Found ObjectId: '$objectID'." 
        
        }

        "byObjectID" { 
        
              Write-Verbose -Message "Using $objectID"
       
        }

    }


     #check if er rg exists, if not exit
     Write-Verbose 'Checking if ER Resource Group exists'
     $ERRGexist = Get-AzureRmResourceGroup -Name $ERRG
     If ($ERRGexist -eq $null) 
     {
        Write-Output 'Please specify a valid ExpressRoute Resource Group -parameter ERRG' | Out-Null   
        exit
     }

     #check if app rg exists, if not create it
     Write-Verbose 'Checking if Application Resource Group exists'
     $appRGexist = Get-AzureRmResourceGroup -Name $appRG -ErrorAction SilentlyContinue
     If ($appRGexist -eq $null) 
     {
        New-AzureRmResourceGroup -Name $appRG -Location $location| Out-Null  
     }

     #Get AppRGID
     $AppRGIDs = (Get-AzureRmResourceGroup -Name $appRG).ResourceID

     #assign nt group to er rg -> SDO Managed ExpressRoute User
     $roledef = 'SDO Managed ExpressRoute User'
     Write-Verbose "Checking $roledef permissions"
     If ((Get-AzureRmRoleAssignment -ObjectId $objectID -RoleDefinitionName $roledef -ResourceGroupName $ERRG) -eq $null)
     {
        Write-Verbose 'Assigning ExpressRoute permissions'
        New-AzureRmRoleAssignment -ObjectId $objectID -RoleDefinitionName $roledef -ResourceGroupName $ERRG | Out-Null
     }
     Else
     {        
        Write-Verbose 'ExpressRoute RG permissions already assigned, skipping' 
     }


     #assign nt group to er rg -> SDO Managed ExpressRoute User
     $roledef = 'SDO Managed ExpressRoute User'
     Write-Verbose "Checking $roledef permissions"
     If ((Get-AzureRmRoleAssignment -ObjectId $objectID -RoleDefinitionName $roledef -ResourceGroupName $ERRG) -eq $null)
     {
        Write-Verbose "Assigning $roledef permissions"
        New-AzureRmRoleAssignment -ObjectId $objectID -RoleDefinitionName $roledef -ResourceGroupName $ERRG | Out-Null
     }
     Else
     {        
        Write-Verbose "$roledef permissions already assigned, skipping" 
     }

     #assign User Access Administrator to application rg
     $roledef = 'User Access Administrator'
     $assignID = (Get-AzureRmRoleAssignment -ObjectId $objectID -RoleDefinitionName $roledef -ResourceGroupName $appRG).scope
     Write-Verbose "Checking $roledef permissions"
     If ($assignID -ne $AppRGIDs)
     {
        Write-Verbose "Assigning $roledef permissions"
        New-AzureRmRoleAssignment -ObjectId $objectID -RoleDefinitionName $roledef -ResourceGroupName $appRG | Out-Null
     }
     Else
     {        
        Write-Verbose "$roledef permissions already assigned, skipping" 
     }

     #assign Contributor to application rg
     $roledef = 'Contributor'
     $assignID = (Get-AzureRmRoleAssignment -ObjectId $objectID -RoleDefinitionName $roledef -ResourceGroupName $appRG).scope
     Write-Verbose "Checking $roledef permissions"
     If ($assignID -ne $AppRGIDs)
     {
        Write-Verbose "Assigning $roledef permissions"
        New-AzureRmRoleAssignment -ObjectId $objectID -RoleDefinitionName $roledef -ResourceGroupName $appRG | Out-Null
     }
     Else
     {        
        Write-Verbose "$roledef permissions already assigned, skipping" 
     }

     #assign reader at subscription level
     $roledef = 'Reader'
     $scope = '/subscriptions/{0}/' -f $subscriptionID
     Write-Verbose "Checking $roledef permissions"
     If ((Get-AzureRmRoleAssignment -ObjectId $objectID -RoleDefinitionName $roledef) -eq $null)
     {
        Write-Verbose "Assigning $roledef permissions"
        New-AzureRmRoleAssignment -ObjectId $objectID -RoleDefinitionName $roledef -Scope $scope | Out-Null
     }
     Else
     {        
        Write-Verbose "$roledef permissions already assigned, skipping" 
     }


    return $true

    <#
            .SYNOPSIS
            Applies standard DevOps role permissions for a given resource group
            .DESCRIPTION
             Applies these permissions for a given user or group
             Subscription permissions: Reader
             Application resource group: User Access Administrator, Contributor
             ExpressRoute resource group: SDO Managed ExpressRoute User                
            .INPUTS
            Individual Users: use -email
            Groups: use -groupname
            ObjectId:   
            .OUTPUTS
            $true or $false
            -Verbose gives step by step output
            .EXAMPLE
            Set-DevOpsPermissions -subscriptionID e4a7xxx65-css6c-4fcd-b4s1-f0xxx3fde61de -appRG cptapp7 -ERRG ARMERVNETUSCPOC -groupName 'Cloud Platform Tools - Team B' -Verbose
            .EXAMPLE
            Set-DevOpsPermissions -subscriptionID e4a7xxx65-css6c-4fcd-b4s1-f0xxx3fde61de -appRG cptapp7 -ERRG ARMERVNETUSCPOC -email cptarm@microsoft.com -Verbose
            .EXAMPLE
            Set-DevOpsPermissions -subscriptionID e4a7xxx65-css6c-4fcd-b4s1-f0xxx3fde61de -appRG ISRMCS -ERRG ARMERVNETUSCPOC -objectID c8240b0d-77d3-4f56-8497-2a6cb9e20990  -Verbose

    #>	
}


Export-ModuleMember -Function Add-Policy
Export-ModuleMember -Function Add-SDOManagedExpressRouteUserRole
Export-ModuleMember -Function Set-DevOpsPermissions


