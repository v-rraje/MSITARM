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

        [parameter(parametersetname="UserEmail")]
        $UserEmail,

        [parameter(parametersetname="GroupDisplayName")]
        $GroupDisplayName

     )

     switch($PsCmdlet.ParameterSetName){

        "UserEmail" {
            
            Write-Verbose -Message "Checking if UPN '$($UserEmail)' exists..."
            $objAD = Get-AzureRmADUser -UserPrincipalName $UserEmail
            
            If(!$objAD){ 

                Write-Output "Please specify a valid email such as 'someuser@microsoft.com'"
                Return $false
            
            } 

            $objectID = $objAD.Id

            Write-Verbose -Message "Found ObjectId: '$objectID'." 
             
        }

        "GroupDisplayName" {

            Write-Verbose -Message "Checking if group alias '$($GroupDisplayName)'exists..."
            $objAD = Get-AzureRmADGroup -SearchString $GroupDisplayName
            
            If ($objAD.Count -ne 1) { # may return more than one result if a partial match is found
            
                Write-Output "Please specify a valid, full security group display name.  For example, use 'CPT-Reports' instead of 'CPT'."
                Return $false
            
            }

            $objectID = $objAD.Id
            
            Write-Verbose -Message "Found ObjectId: '$objectID'." 
        
        }

    }

     #check if er rg exists, if not exit
     Write-Verbose -Message 'Checking if ER Resource Group exists'
     $ERRGexist = Get-AzureRmResourceGroup -Name $ERRG
     If ($ERRGexist -eq $null) 
     {
        Write-Output 'Please specify a valid ExpressRoute Resource Group -parameter ERRG' | Out-Null   
        Return $false
     }

     #check if app rg exists, if not create it
     Write-Verbose -Message 'Checking if Application Resource Group exists'
     $appRGexist = Get-AzureRmResourceGroup -Name $appRG -ErrorAction SilentlyContinue
     If ($appRGexist -eq $null) 
     {
        New-AzureRmResourceGroup -Name $appRG -Location $location| Out-Null  
     }


     #assign nt group to er rg -> SDO Managed ExpressRoute User
     $roledef = 'SDO Managed ExpressRoute User'
     Write-Verbose -Message "Checking $roledef permissions"
     If ((Get-AzureRmRoleAssignment -ObjectId $objectID -RoleDefinitionName $roledef -ResourceGroupName $ERRG) -eq $null)
     {
        Write-Verbose -Message 'Assigning ExpressRoute permissions'
        New-AzureRmRoleAssignment -ObjectId $objectID -RoleDefinitionName $roledef -ResourceGroupName $ERRG | Out-Null
     }
     Else
     {        
        Write-Verbose -Message 'ExpressRoute RG permissions already assigned, skipping' 
     }


     #assign nt group to er rg -> SDO Managed ExpressRoute User
     $roledef = 'SDO Managed ExpressRoute User'
     Write-Verbose -Message "Checking $roledef permissions"
     If ((Get-AzureRmRoleAssignment -ObjectId $objectID -RoleDefinitionName $roledef -ResourceGroupName $ERRG) -eq $null)
     {
        Write-Verbose -Message "Assigning $roledef permissions"
        New-AzureRmRoleAssignment -ObjectId $objectID -RoleDefinitionName $roledef -ResourceGroupName $ERRG | Out-Null
     }
     Else
     {        
        Write-Verbose -Message "$roledef permissions already assigned, skipping" 
     }

     #assign User Access Administrator to application rg
     $roledef = 'User Access Administrator'
     Write-Verbose -Message "Checking $roledef permissions"
     If ((Get-AzureRmRoleAssignment -ObjectId $objectID -RoleDefinitionName $roledef -ResourceGroupName $appRG) -eq $null)
     {
        Write-Verbose -Message "Assigning $roledef permissions"
        New-AzureRmRoleAssignment -ObjectId $objectID -RoleDefinitionName $roledef -ResourceGroupName $appRG | Out-Null
     }
     Else
     {        
        Write-Verbose -Message "$roledef permissions already assigned, skipping" 
     }

     #assign Contributor to application rg
     $roledef = 'Contributor'
     Write-Verbose -Message "Checking $roledef permissions"
     If ((Get-AzureRmRoleAssignment -ObjectId $objectID -RoleDefinitionName $roledef -ResourceGroupName $appRG) -eq $null)
     {
        Write-Verbose -Message "Assigning $roledef permissions"
        New-AzureRmRoleAssignment -ObjectId $objectID -RoleDefinitionName $roledef -ResourceGroupName $appRG | Out-Null
     }
     Else
     {        
        Write-Verbose -Message "$roledef permissions already assigned, skipping" 
     }

     #assign reader at subscription level
     $roledef = 'Reader'
     $scope = '/subscriptions/{0}/' -f $subscriptionID
     Write-Verbose -Message "Checking $roledef permissions"
     If ((Get-AzureRmRoleAssignment -ObjectId $objectID -RoleDefinitionName $roledef) -eq $null)
     {
        Write-Verbose -Message "Assigning $roledef permissions"
        New-AzureRmRoleAssignment -ObjectId $objectID -RoleDefinitionName $roledef -Scope $scope | Out-Null
     }
     Else
     {        
        Write-Verbose -Message "$roledef permissions already assigned, skipping" 
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
            see examples
            .OUTPUTS
            $true or $false
            -Verbose gives step by step output
            .EXAMPLE
            Set-DevOpsPermissions -subscriptionID e8a32032-cc6c-4x56-b451-f07x3fdx47xx -appRG cptApp1 -ERRG ARMERVNETUSCPOC -GroupDisplayName 'Cloud Platform Tools - Team B' -Verbose
            .EXAMPLE
            Set-DevOpsPermissions -subscriptionID e8a32032-cc6c-4x56-b451-f07x3fdx47xx -appRG cptApp2 -ERRG ARMERVNETUSCPOC -UserEmail 'cptarm@microsoft.com' -Verbose  
    #>	
}
