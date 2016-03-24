Function Get-DomainOU() {
<#
  .SYNOPSIS
    this Function will Get the OU for a Domain.
  .DESCRIPTION
  The function takes a CSV list of users and groups and adds them to the local administrators group.
  .EXAMPLE
    Add-AdditionalAdmins -computer "vanilla-img-70" -UserAccounts "redmond\ericq" -cred $(get-credential)
  .EXAMPLE
    Add-AdditionalAdmins -computer "vanilla-img-70" -UserAccounts "redmond\ericq,redmond\cptteamb,redmond\kiranp" -cred $cred
  .PARAMETER computername
    The computer name to work with. Just one.
  .PARAMETER UserAccounts
    a comma separated list of users and/or groups to add to the local administrators
  #>
  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory=$True,
      HelpMessage='What Domain?')]
    [ValidateLength(3,30)]
    [string]$DomainName
    
  )
   
   [string] $OU = "Other" 

   # Get the destination OU for our domain...
                        if($DomainName -imatch "redmond"){
                            $OU           = "OU=ITManaged,OU=ITServices,DC=REDMOND,DC=CORP,DC=MICROSOFT,DC=COM"
                        }
                        elseif ($DomainName -imatch "europe"){
                            $OU           = "OU=ITManaged,OU=ITServices,DC=europe,DC=corp,DC=microsoft,DC=com"
                        }
                        elseif ($DomainName -imatch "northamerica"){
                            $OU           = "OU=ITManaged,OU=ITServices,DC=northamerica,DC=corp,DC=microsoft,DC=com"
                        }
                        elseif ($DomainName -imatch "southpacific"){
                            $OU           = "OU=ITManaged,OU=ITServices,DC=southpacific,DC=corp,DC=microsoft,DC=com"
                        }
                        elseif ($DomainName -imatch "southamerica"){
                            $OU           = "OU=ITManaged,OU=ITServices,DC=southamerica,DC=corp,DC=microsoft,DC=com"
                        }
                        elseif ($DomainName -imatch "africa"){
                            $OU           = "OU=ITManaged,OU=ITServices,DC=africa,DC=corp,DC=microsoft,DC=com"
                        }
                        elseif ($DomainName -imatch "middleeast"){
                            $OU           = "OU=ITManaged,OU=ITServices,DC=middleeast,DC=corp,DC=microsoft,DC=com"
                        }
                        elseif ($DomainName -imatch "fareast"){
                            $OU           = "OU=ITManaged,OU=ITServices,DC=fareast,DC=CORP,DC=MICROSOFT,DC=COM"
                        }
                        else{
                            $OU = "Other" 
                           # "Skipping OU move for domain '$($DomainName)'."             
                        }
 
 Return $ou           
}





