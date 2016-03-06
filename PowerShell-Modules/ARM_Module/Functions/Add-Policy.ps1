function Add-Policy
{
    #this allows for cmdlet-style parameter binding capabilities
    [CmdletBinding()]
    Param( 
        [Parameter(Mandatory=$true)]
        [ValidateSet('SDOStdPolicyTags','SDOStdPolicyNetwork','SDOStdPolicyRegion','SDOStdPolicyNetworkAllowV1')] 
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
        'sdostdpolicynetworkallowv1' 
        {
            try
            {
                #Set Policy for SDOStdPolicyNetwork
                $polDef = New-AzureRmPolicyDefinition -Name SDOStdPolicyNetworkAllowV1 -Description 'No endpoints, only some network resources, and allow V1' -Policy '{
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
                    }
                    ]
                    },
                    "then": {
                    "effect": "deny"
                    }
                }'
                
                         
                #apply at subscription level
                New-AzureRmPolicyAssignment -Name SDOStdPolicyNetworkAllowV1 -PolicyDefinition $polDef -Scope $scope | Out-Null
          
                Write-Verbose 'SDOStdPolicyNetworkAllowV1 policy created successfully'
            }
            catch 
            {
                Write-Verbose 'SDOStdPolicyNetworkAllowV1 policy creation failed'
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
            .EXAMPLE 
            $subID = e8a32032-cc6c-4x56-b451-f07x3fdx47xx 
            Add-Policy -policy SDOStdPolicyNetworkAllowV1 -subscriptionID  $subID -Verbose

    #>	
}


