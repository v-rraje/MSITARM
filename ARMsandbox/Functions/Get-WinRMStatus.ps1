Function Get-WinRMStatus() {
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
      HelpMessage='What Server?')]
    [ValidateLength(3,30)]
    [string]$ServerName,
    [switch] $waitfor,
     [Parameter(Mandatory=$true,
      HelpMessage='What  credentials can be used?')]
    [System.Management.Automation.PSCredential]$creds
  )   

           $VmIsReady=$false

    while(!$VmIsReady) {

                Write-host -f Gray  "Checking VM $($ServerName) WINRM status..." -NoNewline
                
				try {
                    $script={
                        $c=$args[0]; 
                        if($c=$env:COMPUTERNAME) {return "Ready"}else {return "NotReady"}
                    }
				    $VmStatuses = (Invoke-Command -ComputerName $ServerName -ScriptBlock $script -ArgumentList $ServerName -Credential $creds -SessionOption (New-PsSessionOption -SkipCACheck -SkipCNCheck) -ErrorAction SilentlyContinue ) 

				    If($VmStatuses -eq 'Ready'){
					    Write-host -f Green $VmStatuses
					    $VmIsReady=$True
				    } else {
                        Write-host -f gray $VmStatuses
                        if($waitfor -eq $True) {
                            Start-Sleep -s 30
                            $VmisReady = $false
                            } else {$VmIsReady=$True}
                    }

                } catch {
                    write-verbose $error[0]
                    $error.Clear()
                    return $false
                }
	

			}
}





