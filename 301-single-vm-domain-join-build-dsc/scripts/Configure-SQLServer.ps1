[CmdletBinding()]
param
    (
[parameter(Mandatory=$true, Position=0)]
[string] $SQLServerAccount,

[parameter(Mandatory=$false, Position=1)]
[string] $SQLServerPassword,

[parameter(Mandatory=$true, Position=2)]
[string] $SQLAgentAccount,

[parameter(Mandatory=$false, Position=3)]
[string] $SQLAgentPassword
        
)
 
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

  write-host "$SQLServerAccount"

  $ret1=  Add-LoginToLocalPrivilege $SQLServerAccount "SeLockMemoryPrivilege"

  $ret2=  Add-LoginToLocalPrivilege $SQLServerAccount "SeManageVolumePrivilege"

    $ServerN = $env:COMPUTERNAME
    $Service = "MSSQLServer"

    if($SQLServerAccount -and $SQLServerPassword) {

        $svcD=gwmi win32_service -computername $ServerN -filter "name='$service'"
        $StopStatus = $svcD.StopService() 

        If ($StopStatus.ReturnValue -eq "0") # validating status - http://msdn.microsoft.com/en-us/library/aa393673(v=vs.85).aspx 
            {write-host "$ServerN -> Service Stopped Successfully"} 
            $ChangeStatus = $svcD.change($null,$null,$null,$null,$null,$null,$SQLServerAccount,$SQLServerPassword,$null,$null,$null) 
        If ($ChangeStatus.ReturnValue -eq "0")  
            {write-host "$ServerN -> Sucessfully Changed User Name"} 
        $StartStatus = $svcD.StartService() 
        If ($ChangeStatus.ReturnValue -eq "0")  
            {write-host "$ServerN -> Service Started Successfully"} 

     }

    $Service = "SQLSERVERAGENT"

    if($SQLAgentAccount -and $SQLAgentPassword) {

        $svcD=gwmi win32_service -computername $ServerN -filter "name='$service'" -Credential $cred
 
        $StopStatus = $svcD.StopService() 
        If ($StopStatus.ReturnValue -eq "0") # validating status - http://msdn.microsoft.com/en-us/library/aa393673(v=vs.85).aspx 
            {write-host "$ServerN -> Service Stopped Successfully"} 
        $ChangeStatus = $svcD.change($null,$null,$null,$null,$null,$null,$SQLAgentAccount,$SQLAgentPassword,$null,$null,$null) 
        If ($ChangeStatus.ReturnValue -eq "0")  
            {write-host "$ServerN -> Sucessfully Changed User Name"} 
        $StartStatus = $svcD.StartService() 
        If ($ChangeStatus.ReturnValue -eq "0")  
            {write-host "$ServerN -> Service Started Successfully"} 
        }



    

