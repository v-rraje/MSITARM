
Configuration DeployWinServer
{
  param (  
  [string[]]$MachineName = "localhost"
  )

  Node ($MachineName)
  {
	
        cd\
        if($(test-path -path c:\temp) -eq $false){
            md Temp
        }
        $sw = New-Object System.IO.StreamWriter(“C:\Temp\Wininstall.log”)
        $sw.WriteLine("$(Get-Date -Format g) Completed.") 
	    $sw.Close()
  }

}

