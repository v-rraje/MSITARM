
Configuration DeployWinServer
{
  param (  
  [string[]]$MachineName = "localhost"
  )

  Node ($MachineName)
  {
	   
   
   return $true
    
	    
  }

}

