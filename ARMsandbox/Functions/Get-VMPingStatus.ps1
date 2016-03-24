Function Get-VMPingStatus() {
<#
  .SYNOPSIS
    this Function will use ping to verify machine.
  .DESCRIPTION
    this Function will use ping to verify machine.
  .EXAMPLE
    
  .EXAMPLE
    
  .PARAMETER computername
   
  .PARAMETER Waitfor
    
  #>
  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory=$True,
      HelpMessage='What Server?')]
    [ValidateLength(3,30)]
    [string]$ServerName,
    [switch] $waitfor
    
  )
   
    while(!$VmIsReady) {

                Write-host -f Gray  "Checking VM $($ServerName) status..." -NoNewline
                
				try {

				$VmStatuses = $(Test-Connection -computername ($ServerName) -Count 1 -ErrorAction SilentlyContinue)

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
                    write-host -f red $error[0]
                    $error.Clear()
                    return $false
                }
	

			}

}





