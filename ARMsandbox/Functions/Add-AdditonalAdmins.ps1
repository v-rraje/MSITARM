Function Add-AdditionalAdmins() {
<#
  .SYNOPSIS
    this Function will add additional administrators to a Server.
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
      HelpMessage='What computer name would you like to target?')]
    [ValidateLength(3,30)]
    [string]$computername,
	
    [Parameter(Mandatory=$true,
      HelpMessage='What Users and/or groups would you like to add?')]
    [string]$UserAccounts,

    [Parameter(Mandatory=$true,
      HelpMessage='What Domain credentials can be used?')]
    [System.Management.Automation.PSCredential]$creds
    
  )

write-verbose  ("testing {0}" -f $computername)
    if(Test-Connection -ComputerName $computername -Count 1 -Quiet) {
        write-verbose "$computername is Online"
    }

$script={
    $UserAccounts=$args[0]
    $DomainGroups=$args[1]


    $users = $UserAccounts -split(",")
    foreach($user in $users) {

    $split=$user -split("\\")
    
    $Domain=$split[0]
    $UserName=$split[1]
   
    $computerName = "$env:computername" 
    try {
    $computer = [ADSI]("WinNT://" + $computerName + ",computer")
    $Group = $computer.psbase.children.find("administrators") 
 
    $members= $Group.psbase.invoke("Members") | %{$_.GetType().InvokeMember("Name", ‘GetProperty’, $null, $_, $null) }
    } catch {
        write-error $Error[0]
        break;
    }

    $exists = $members | ?{$_ -eq $UserName}
  
    if(!$exists) {
        try {
            write-host -f gray "adding $domain\$UserName"
            ([ADSI]"WinNT://$computerName/Administrators,group").Add("WinNT://$domain/$UserName")  
        } catch { 
            write-host -f red "Failed to add $domain\$UserName to $computerName"
            $error.Clear()
        }


    }else {
        write-host -f gray "$domain\$UserName is already an Administrator"
    }
    }    
  
    $members= $Group.psbase.invoke("Members") | %{$_.GetType().InvokeMember("Name", ‘GetProperty’, $null, $_, $null) }
    
    write-host -f gray "Current Administrators"
    $members |%{ write-host -f green "`t$_"}
  
}

Invoke-Command -ComputerName $computername -ScriptBlock $script -ArgumentList $UserAccounts -Credential $creds -SessionOption (New-PsSessionOption -SkipCACheck -SkipCNCheck) 

}





