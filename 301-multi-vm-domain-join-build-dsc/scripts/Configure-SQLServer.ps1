# Name: ConfigureSQLserver
#
[CmdletBinding()]
param
    (
[parameter(Mandatory=$true, Position=0)]
[string] $SQLServerAccount,

[parameter(Mandatory=$true, Position=1)]
[string] $SQLServerPassword,

[parameter(Mandatory=$true, Position=2)]
[string] $SQLAgentAccount,

[parameter(Mandatory=$true, Position=3)]
[string] $SQLAgentPassword,

[parameter(Mandatory=$true, Position=4)]
[string] $SQLAdmin,

[parameter(Mandatory=$true, Position=5)]
[string] $SQLAdminPwd,

[Parameter(Mandatory)]
[string] $baseurl="http://cloudmsarmprod.blob.core.windows.net/"
        
)
    [reflection.assembly]::LoadWithPartialName("Microsoft.SqlServer.SqlWmiManagement")
 
    $sysinfo = Get-WmiObject -Class Win32_ComputerSystem
    $server = $(“{0}.{1}” -f $sysinfo.Name, $sysinfo.Domain)

    #################Private functions####################################

    function Add-LoginToLocalPrivilege {

        #Specify the default parameterset
        [CmdletBinding(DefaultParametersetName="JointNames", SupportsShouldProcess=$true, ConfirmImpact='High')]
        param
            (
        [parameter(
        Mandatory=$true, 
        Position=0,
        ValueFromPipeline= $true
                    )]
        [string] $DomainAccount,

        [parameter(Mandatory=$true, Position=2)]
        [ValidateSet("SeManageVolumePrivilege", "SeLockMemoryPrivilege")]
        [string] $Privilege,

        [parameter(Mandatory=$false, Position=3)]
        [string] $TemporaryFolderPath = $env:USERPROFILE
        
        )

        #Determine which parameter set was used
            switch ($PsCmdlet.ParameterSetName)
        {
        "SplitNames"
                { 
        #If SplitNames was used, combine the names into a single string
                    Write-Verbose "Domain and Account provided - combining for rest of script."
                    $DomainAccount = "$Domain`\$Account"
                }
        "JointNames"
                {
        Write-Verbose "Domain\Account combination provided."
                    #Need to do nothing more, the parameter passed is sufficient.
                }
        }

        Write-Verbose "Adding $DomainAccount to $Privilege"

            Write-Verbose "Verifying that export file does not exist."
            #Clean Up any files that may be hanging around.
            Remove-TempFiles
    
        Write-Verbose "Executing secedit and sending to $TemporaryFolderPath"
            #Use secedit (built in command in windows) to export current User Rights Assignment
            $SeceditResults = secedit /export /areas USER_RIGHTS /cfg $TemporaryFolderPath\UserRightsAsTheyExist.inf

        #Make certain export was successful
        if($SeceditResults[$SeceditResults.Count-2] -eq "The task has completed successfully.")
        {

        Write-Verbose "Secedit export was successful, proceeding to re-import"
                #Save out the header of the file to be imported
        
        Write-Verbose "Save out header for $TemporaryFolderPath`\ApplyUserRights.inf"
        
        "[Unicode]
        Unicode=yes
        [Version]
        signature=`"`$CHICAGO`$`"
        Revision=1
        [Privilege Rights]" | Out-File $TemporaryFolderPath\ApplyUserRights.inf -Force -WhatIf:$false
                                    
        #Bring the exported config file in as an array
        Write-Verbose "Importing the exported secedit file."
        $SecurityPolicyExport = Get-Content $TemporaryFolderPath\UserRightsAsTheyExist.inf

        #enumerate over each of these files, looking for the Perform Volume Maintenance Tasks privilege
       [Boolean]$isFound = $false
       
        foreach($line in $SecurityPolicyExport) {

         if($line -like "$Privilege`*")  {

                Write-Verbose "Line with the $Privilege found in export, appending $DomainAccount to it"
                #Add the current domain\user to the list
                $line = $line + ",$DomainAccount"
                #output line, with all old + new accounts to re-import
                $line | Out-File $TemporaryFolderPath\ApplyUserRights.inf -Append -WhatIf:$false

                Write-host "Added $DomainAccount to $Privilege"                            
                $isFound = $true
            }
        }

        if($isFound -eq $false) {
            #If the particular command we are looking for can't be found, create it to be imported.
            Write-Verbose "No line found for $Privilege - Adding new line for $DomainAccount"
            "$Privilege`=$DomainAccount" | Out-File $TemporaryFolderPath\ApplyUserRights.inf -Append -WhatIf:$false
        }

            #Import the new .inf into the local security policy.
        
            Write-Verbose "Importing $TemporaryfolderPath\ApplyUserRighs.inf"
            $SeceditApplyResults = SECEDIT /configure /db secedit.sdb /cfg $TemporaryFolderPath\ApplyUserRights.inf 

            #Verify that update was successful (string reading, blegh.)
            if($SeceditApplyResults[$SeceditApplyResults.Count-2] -eq "The task has completed successfully.")
            {
                #Success, return true
                Write-Verbose "Import was successful."
                Write-Output $true
            }
            else
            {
                #Import failed for some reason
                Write-Verbose "Import from $TemporaryFolderPath\ApplyUserRights.inf failed."
                Write-Output $false
                Write-Error -Message "The import from$TemporaryFolderPath\ApplyUserRights using secedit failed. Full Text Below:
                $SeceditApplyResults)"
            }

        }
        else
            {
                #Export failed for some reason.
                Write-Verbose "Export to $TemporaryFolderPath\UserRightsAsTheyExist.inf failed."
                Write-Output $false
                Write-Error -Message "The export to $TemporaryFolderPath\UserRightsAsTheyExist.inf from secedit failed. Full Text Below: $SeceditResults)"
        
        }

        Write-Verbose "Cleaning up temporary files that were created."
            #Delete the two temp files we created.
            Remove-TempFiles
    
        }

    function Remove-TempFiles {

        #Evaluate whether the ApplyUserRights.inf file exists
        if(Test-Path $TemporaryFolderPath\ApplyUserRights.inf)
        {
            #Remove it if it does.
            Write-Verbose "Removing $TemporaryFolderPath`\ApplyUserRights.inf"
            Remove-Item $TemporaryFolderPath\ApplyUserRights.inf -Force -WhatIf:$false
        }

        #Evaluate whether the UserRightsAsTheyExists.inf file exists
        if(Test-Path $TemporaryFolderPath\UserRightsAsTheyExist.inf)
        {
            #Remove it if it does.
            Write-Verbose "Removing $TemporaryFolderPath\UserRightsAsTheyExist.inf"
            Remove-Item $TemporaryFolderPath\UserRightsAsTheyExist.inf -Force -WhatIf:$false
        }
    }
       
  ###############################################################
  ###############################################################

  #################Policy Changes####################################

  $ret1=  Add-LoginToLocalPrivilege "NT Service\Mssqlserver" "SeLockMemoryPrivilege"

  $ret2=  Add-LoginToLocalPrivilege "NT Service\Mssqlserver" "SeManageVolumePrivilege"
    
  ###############################################################
  ###############################################################


  ###############################################################
  #remove Execute Perms on Extended Procedures from public user/role
  ###############################################################
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile($($baseURL) + "scripts/PostConfiguration.sql","C:\SQLStartup\PostConfiguration.sql")

    if($(test-path -path 'C:\SQLStartup\PostConfiguration.sql') -eq $true) {
        
        $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
   
        if($sqlInstances -ne $null){
            write-host "Add SQL account $SQLServerAccount on $server"

            try {  
            $secpasswd = ConvertTo-SecureString $SQLAdminPwd -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential ($SQLAdmin, $secpasswd)
                                    
             $Scriptblock={         
                $SQLServerAccount=$args[0]
                ############################################                     
                $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                ############################################

                $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                $srvConn.connect();
                $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn
                                                    
                    $login = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $Srv, $SQLServerAccount
                    $login.LoginType = 'WindowsUser'
                    $login.PasswordExpirationEnabled = $false
                    $login.Create()

                    #  Next two lines to give the new login a server role, optional
                    $login.AddToRole('sysadmin')
                    $login.Alter()         

                    write-host "Added SQL account $SQLServerAccount"
                }
                
               Invoke-Command -script  $Scriptblock  -ComputerName $server -Credential $Credential -ArgumentList $SQLServerAccount

             write-host "Extended Sprocs on $server"

             #$q =  $(get-content -path "C:\SQLStartup\PostConfiguration.sql") -join [Environment]::NewLine
             $scriptblock = {Invoke-SQLCmd -ServerInstance $($env:computername) -Database 'master' -ConnectionTimeout 300 -QueryTimeout 600 -inputfile "C:\SQLStartup\PostConfiguration.sql" }
             
             Invoke-Command -script  $scriptblock -ComputerName $server -Credential $Credential
                                                            
            } catch{
                [string]$errorMessage = $Error[0].Exception
                if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 5001 -entrytype Error -message "Configure-SQLServer.ps1: $errorMessage"
                }else {$error}
            }
        }
    }
 
  ###############################################################
  ###############################################################

  ###############################################################
  # update the services
  ###############################################################
    $ServerN = $env:COMPUTERNAME
    $Service = "SQL Server (MSSQLServer)"
    
    if($SQLServerAccount -and $SQLServerPassword) {
            
        $wmi = new-object ("Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer") $env:computername
        $svc = $wmi.services | where {$_.Type -eq 'SqlServer'} 
        $svc.SetServiceAccount($SQLServerAccount,$SQLServerPassword)

         Restart-Service -displayname $Service -Force

    }


    $Service = "SQL Server Agent (MSSQLServer)"

    if($SQLAgentAccount -and $SQLAgentPassword) {

      $wmi = new-object ("Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer") $env:computername
        $svc = $wmi.services | where {$_.Type -eq 'SqlAgent'} 
        $svc.SetServiceAccount($SQLServerAccount,$SQLServerPassword)

         Restart-Service -displayname $Service -Force

    }
    
    
  ###############################################################
  ###############################################################
