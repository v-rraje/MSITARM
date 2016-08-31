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
    $null = [reflection.assembly]::LoadWithPartialName("Microsoft.SqlServer.SqlWmiManagement")
 
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

                Write-verbose "Added $DomainAccount to $Privilege"                            
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
  
  try {

    $cnt = 1
    $downloaded=$false
    do {
        try{
        write-verbose "dowload PostConfiguration.sql from $baseurl to C:\SQLStartup\"

        $WebClient = New-Object System.Net.WebClient
        $WebClient.DownloadFile($($baseURL) + "scripts/PostConfiguration.sql","C:\SQLStartup\PostConfiguration.sql")
        $downloaded = $true
        if($(test-path -path 'C:\SQLStartup\PostConfiguration.sql') -eq $true) {break;}

        }catch{
            Write-Host "Error : $_.Exception.Message"
            continue;
        }
        $cnt +=1;

    } until ($cnt -ge 3 -or $downloaded)


        if($(test-path -path 'C:\SQLStartup\PostConfiguration.sql') -eq $true) {
        
            $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
   
            if($sqlInstances -ne $null){

                write-verbose "Add SQL account $SQLServerAccount on $server"
 
                $secpasswd = ConvertTo-SecureString $SQLAdminPwd -AsPlainText -Force
                $credential = New-Object System.Management.Automation.PSCredential ($SQLAdmin, $secpasswd)
                                    
                $Scriptblock={         
                $SQLServerAccount=$args[0]
                ############################################                     
                $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                ############################################
                try {
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

                    write-verbose "Added SQL account $SQLServerAccount"

                    }catch {}
                }
                
                Invoke-Command -script  $Scriptblock  -ComputerName $server -Credential $Credential -ArgumentList $SQLServerAccount

                 write-verbose "Extended Sprocs on $server"

                 #$q =  $(get-content -path "C:\SQLStartup\PostConfiguration.sql") -join [Environment]::NewLine
                 $scriptblock = {Invoke-SQLCmd -ServerInstance $($env:computername) -Database 'master' -ConnectionTimeout 300 -QueryTimeout 600 -inputfile "C:\SQLStartup\PostConfiguration.sql" }
             
                 Invoke-Command -script  $scriptblock -ComputerName $server -Credential $Credential
              
                } else { write-error "PostConfiguration.sql not found"}

         } else { write-error "win32_service::MSSQLServer not found"}

        } catch{
            [string]$errorMessage = $_.Exception.Message
            if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                Write-EventLog -LogName Application -source AzureArmTemplates -eventID 5001 -entrytype Error -message "Configure-SQLServer.ps1: $errorMessage"
            }else {$error}

            write-error $errorMessage
        }
    
 
  ###############################################################
  ###############################################################

  ###############################################################
  # update the services
  ###############################################################
  try {

        $ServerN = $env:COMPUTERNAME
        $Service = "SQL Server (MSSQLServer)"
    
        if($SQLServerAccount -and $SQLServerPassword) {
            
            $wmi = new-object ("Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer") $env:computername
            $svc = $wmi.services | where {$_.Type -eq 'SqlServer'} 
            $svc.SetServiceAccount($SQLServerAccount,$SQLServerPassword)

             $ret = Restart-Service -displayname $Service -Force  -WarningAction Ignore
             

        }
        
        $Service = "SQL Server Agent (MSSQLServer)"

        if($SQLAgentAccount -and $SQLAgentPassword) {

          $wmi = new-object ("Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer") $env:computername
            $svc = $wmi.services | where {$_.Type -eq 'SqlAgent'} 
            $svc.SetServiceAccount($SQLAgentAccount,$SQLAgentPassword)

             $ret =  Restart-Service -displayname $Service -Force -WarningAction Ignore
            
        }

     } catch{
            [string]$errorMessage = $_.Exception.Message
            if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                Write-EventLog -LogName Application -source AzureArmTemplates -eventID 5001 -entrytype Error -message "Configure-SQLServer.ps1: $errorMessage"
            }else {$error}

            write-error $errorMessage
        }
    
    
  ###############################################################
  ###############################################################

  $status="Started"
  ## Audit Section
  if($ret1) {write-host "[Pass] NT Service\Mssqlserver to SeLockMemoryPrivilege" } else {write-host "[Failed] NT Service\Mssqlserver to SeLockMemoryPrivilege"; $status="Failed"}

  if($ret1) {write-host "[Pass] NT Service\Mssqlserver to SeManageVolumePrivilege" } else {write-host "[Failed] NT Service\Mssqlserver to SeManageVolumePrivilege"; $status="Failed"}

  $wmi = new-object ("Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer") $env:computername
  
  $svc = $wmi.services | where {$_.Type -eq 'SqlServer'} 
  if($svc.ServiceAccount -ne  $SQLServerAccount) {
    write-host "[Failed] SQL Service Account not set to $SQLServerAccount"; $status="Failed"
  } else {write-host "[pass] SQL Service Account set to $SQLServerAccount"}

  $svc = $wmi.services | where {$_.Type -eq 'SqlAgent'} 
  if($svc.ServiceAccount -ne  $SQLAgentAccount) {
    write-host "[Failed] SQL Agent Account not set to $SQLAgentAccount"; $status="Failed"
  }else {write-host "[Pass] SQL Agent Account set to $SQLAgentAccount"}
              

  if($status -eq "Failed") {
    write-error "[Failed] Deployment failed."
  } else {
    write-host "[Passed] Deployment passed."
  }



# SIG # Begin signature block
# MIIkBgYJKoZIhvcNAQcCoIIj9zCCI/MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC+rQGViktZr4+h
# BHehK/qI9cxL9+UwsaDfjQ7P47/ce6CCDZIwggYQMIID+KADAgECAhMzAAAAZEeE
# lIbbQRk4AAAAAABkMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMTUxMDI4MjAzMTQ2WhcNMTcwMTI4MjAzMTQ2WjCBgzEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjENMAsGA1UECxMETU9Q
# UjEeMBwGA1UEAxMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAky7a2OY+mNkbD2RfTahYTRQ793qE/DwRMTrvicJK
# LUGlSF3dEp7vq2YoNNV9KlV7TE2K8sDxstNSFYu2swi4i1AL3X/7agmg3GcExPHf
# vHUYIEC+eCyZVt3u9S7dPkL5Wh8wrgEUirCCtVGg4m1l/vcYCo0wbU06p8XzNi3u
# XyygkgCxHEziy/f/JCV/14/A3ZduzrIXtsccRKckyn6B5uYxuRbZXT7RaO6+zUjQ
# hiyu3A4hwcCKw+4bk1kT9sY7gHIYiFP7q78wPqB3vVKIv3rY6LCTraEbjNR+phBQ
# EL7hyBxk+ocu+8RHZhbAhHs2r1+6hURsAg8t4LAOG6I+JQIDAQABo4IBfzCCAXsw
# HwYDVR0lBBgwFgYIKwYBBQUHAwMGCisGAQQBgjdMCAEwHQYDVR0OBBYEFFhWcQTw
# vbsz9YNozOeARvdXr9IiMFEGA1UdEQRKMEikRjBEMQ0wCwYDVQQLEwRNT1BSMTMw
# MQYDVQQFEyozMTY0Mis0OWU4YzNmMy0yMzU5LTQ3ZjYtYTNiZS02YzhjNDc1MWM0
# YjYwHwYDVR0jBBgwFoAUSG5k5VAF04KqFzc3IrVtqMp1ApUwVAYDVR0fBE0wSzBJ
# oEegRYZDaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljQ29k
# U2lnUENBMjAxMV8yMDExLTA3LTA4LmNybDBhBggrBgEFBQcBAQRVMFMwUQYIKwYB
# BQUHMAKGRWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWlj
# Q29kU2lnUENBMjAxMV8yMDExLTA3LTA4LmNydDAMBgNVHRMBAf8EAjAAMA0GCSqG
# SIb3DQEBCwUAA4ICAQCI4gxkQx3dXK6MO4UktZ1A1r1mrFtXNdn06DrARZkQTdu0
# kOTLdlGBCfCzk0309RLkvUgnFKpvLddrg9TGp3n80yUbRsp2AogyrlBU+gP5ggHF
# i7NjGEpj5bH+FDsMw9PygLg8JelgsvBVudw1SgUt625nY7w1vrwk+cDd58TvAyJQ
# FAW1zJ+0ySgB9lu2vwg0NKetOyL7dxe3KoRLaztUcqXoYW5CkI+Mv3m8HOeqlhyf
# FTYxPB5YXyQJPKQJYh8zC9b90JXLT7raM7mQ94ygDuFmlaiZ+QSUR3XVupdEngrm
# ZgUB5jX13M+Pl2Vv7PPFU3xlo3Uhj1wtupNC81epoxGhJ0tRuLdEajD/dCZ0xIni
# esRXCKSC4HCL3BMnSwVXtIoj/QFymFYwD5+sAZuvRSgkKyD1rDA7MPcEI2i/Bh5O
# MAo9App4sR0Gp049oSkXNhvRi/au7QG6NJBTSBbNBGJG8Qp+5QThKoQUk8mj0ugr
# 4yWRsA9JTbmqVw7u9suB5OKYBMUN4hL/yI+aFVsE/KJInvnxSzXJ1YHka45ADYMK
# AMl+fLdIqm3nx6rIN0RkoDAbvTAAXGehUCsIod049A1T3IJyUJXt3OsTd3WabhIB
# XICYfxMg10naaWcyUePgW3+VwP0XLKu4O1+8ZeGyaDSi33GnzmmyYacX3BTqMDCC
# B3owggVioAMCAQICCmEOkNIAAAAAAAMwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29m
# dCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDExMB4XDTExMDcwODIwNTkw
# OVoXDTI2MDcwODIxMDkwOVowfjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEoMCYGA1UEAxMfTWljcm9zb2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAx
# MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKvw+nIQHC6t2G6qghBN
# NLrytlghn0IbKmvpWlCquAY4GgRJun/DDB7dN2vGEtgL8DjCmQawyDnVARQxQtOJ
# DXlkh36UYCRsr55JnOloXtLfm1OyCizDr9mpK656Ca/XllnKYBoF6WZ26DJSJhIv
# 56sIUM+zRLdd2MQuA3WraPPLbfM6XKEW9Ea64DhkrG5kNXimoGMPLdNAk/jj3gcN
# 1Vx5pUkp5w2+oBN3vpQ97/vjK1oQH01WKKJ6cuASOrdJXtjt7UORg9l7snuGG9k+
# sYxd6IlPhBryoS9Z5JA7La4zWMW3Pv4y07MDPbGyr5I4ftKdgCz1TlaRITUlwzlu
# ZH9TupwPrRkjhMv0ugOGjfdf8NBSv4yUh7zAIXQlXxgotswnKDglmDlKNs98sZKu
# HCOnqWbsYR9q4ShJnV+I4iVd0yFLPlLEtVc/JAPw0XpbL9Uj43BdD1FGd7P4AOG8
# rAKCX9vAFbO9G9RVS+c5oQ/pI0m8GLhEfEXkwcNyeuBy5yTfv0aZxe/CHFfbg43s
# TUkwp6uO3+xbn6/83bBm4sGXgXvt1u1L50kppxMopqd9Z4DmimJ4X7IvhNdXnFy/
# dygo8e1twyiPLI9AN0/B4YVEicQJTMXUpUMvdJX3bvh4IFgsE11glZo+TzOE2rCI
# F96eTvSWsLxGoGyY0uDWiIwLAgMBAAGjggHtMIIB6TAQBgkrBgEEAYI3FQEEAwIB
# ADAdBgNVHQ4EFgQUSG5k5VAF04KqFzc3IrVtqMp1ApUwGQYJKwYBBAGCNxQCBAwe
# CgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0j
# BBgwFoAUci06AjGQQ7kUBU7h6qfHMdEjiTQwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0
# cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2Vy
# QXV0MjAxMV8yMDExXzAzXzIyLmNybDBeBggrBgEFBQcBAQRSMFAwTgYIKwYBBQUH
# MAKGQmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2Vy
# QXV0MjAxMV8yMDExXzAzXzIyLmNydDCBnwYDVR0gBIGXMIGUMIGRBgkrBgEEAYI3
# LgMwgYMwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lv
# cHMvZG9jcy9wcmltYXJ5Y3BzLmh0bTBABggrBgEFBQcCAjA0HjIgHQBMAGUAZwBh
# AGwAXwBwAG8AbABpAGMAeQBfAHMAdABhAHQAZQBtAGUAbgB0AC4gHTANBgkqhkiG
# 9w0BAQsFAAOCAgEAZ/KGpZjgVHkaLtPYdGcimwuWEeFjkplCln3SeQyQwWVfLiw+
# +MNy0W2D/r4/6ArKO79HqaPzadtjvyI1pZddZYSQfYtGUFXYDJJ80hpLHPM8QotS
# 0LD9a+M+By4pm+Y9G6XUtR13lDni6WTJRD14eiPzE32mkHSDjfTLJgJGKsKKELuk
# qQUMm+1o+mgulaAqPyprWEljHwlpblqYluSD9MCP80Yr3vw70L01724lruWvJ+3Q
# 3fMOr5kol5hNDj0L8giJ1h/DMhji8MUtzluetEk5CsYKwsatruWy2dsViFFFWDgy
# cScaf7H0J/jeLDogaZiyWYlobm+nt3TDQAUGpgEqKD6CPxNNZgvAs0314Y9/HG8V
# fUWnduVAKmWjw11SYobDHWM2l4bf2vP48hahmifhzaWX0O5dY0HjWwechz4GdwbR
# BrF1HxS+YWG18NzGGwS+30HHDiju3mUv7Jf2oVyW2ADWoUa9WfOXpQlLSBCZgB/Q
# ACnFsZulP0V3HjXG0qKin3p6IvpIlR+r+0cjgPWe+L9rt0uX4ut1eBrs6jeZeRhL
# /9azI2h15q/6/IvrC4DqaTuv/DDtBEyO3991bWORPdGdVk5Pv4BXIqF4ETIheu9B
# CrE/+6jMpF3BoYibV3FWTkhFwELJm3ZbCoBIa/15n8G9bW1qyVJzEw16UM0xghXK
# MIIVxgIBATCBlTB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExAhMzAAAA
# ZEeElIbbQRk4AAAAAABkMA0GCWCGSAFlAwQCAQUAoIG4MBkGCSqGSIb3DQEJAzEM
# BgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqG
# SIb3DQEJBDEiBCDWz7ZNHuffgJdbVGRSFIeIPQcCMaY3PQ4m0yHXxMz2fDBMBgor
# BgEEAYI3AgEMMT4wPKASgBAATQBTAEkAVAAgAEEAUgBNoSaAJGh0dHBzOi8vZ2l0
# aHViLmNvbS9taWNyb3NvZnQvbXNpdGFybTANBgkqhkiG9w0BAQEFAASCAQB8fYq8
# QxYXE7gE5ELB3nYc8ya+bazyX4JkoMDdADG8v10Aso/xni5acZZpdGoa9snG+JmZ
# 9otn0kvsZYwPH96k5NPOH2C4DH24nmiCTdk58EgObt0AukByvT/RVTCKWUbu6VgW
# alVO5TTGVbLaYirU5f0VQjh7Pe7iK1YlUPxgepsglyhNxjLQXEme0X9ijqE2tizq
# UDHaaTiIXDsNYumpDhEDgI2u0QWJ6vnrkKLRuT5Sz5nQ9zZhBR8p99gJYcAPRLOk
# 73A8w3rX/WdoKJ2ymHScTNHTyGRVvpOYFj6RiciL9Lqjf/mdZu9HKu1k6wCBdQf+
# YBIM2iIk0kS6/XbLoYITSjCCE0YGCisGAQQBgjcDAwExghM2MIITMgYJKoZIhvcN
# AQcCoIITIzCCEx8CAQMxDzANBglghkgBZQMEAgEFADCCAT0GCyqGSIb3DQEJEAEE
# oIIBLASCASgwggEkAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEICc4
# UjBAhs2GoD7nJSBUeGQgTjyQXRzkPSJp0Ogb9ZMxAgZXvHGXK30YEzIwMTYwODMx
# MjEzNjQwLjAxNlowBwIBAYACAfSggbmkgbYwgbMxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIxJzAlBgNVBAsTHm5DaXBo
# ZXIgRFNFIEVTTjo5OEZELUM2MUUtRTY0MTElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZaCCDs0wggZxMIIEWaADAgECAgphCYEqAAAAAAACMA0G
# CSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3Jp
# dHkgMjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0yNTA3MDEyMTQ2NTVaMHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
# CgKCAQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWlCgCChfvtfGhLLF/Fw+Vhwna3
# PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBED/FgiIRUQwzXTbg4CLNC3ZOs1nMw
# VyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeRX4FUsc+TTJLBxKZd0WETbijG
# GvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd/XcfPfBXday9ikJNQFHRD5wGPmd/
# 9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogINeh4HLDpmc085y9Euqf03GS9
# pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQABo4IB5jCCAeIwEAYJKwYBBAGCNxUB
# BAMCAQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8RhvFM2hahW1VMBkGCSsGAQQBgjcU
# AgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8G
# A1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeG
# RWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jv
# b0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUH
# MAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2Vy
# QXV0XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSABAf8EgZUwgZIwgY8GCSsGAQQBgjcu
# AzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL1BLSS9k
# b2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0HjIgHQBMAGUAZwBhAGwA
# XwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0AC4gHTANBgkqhkiG9w0B
# AQsFAAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Ehb7Prpsz1Mb7PBeKp/vpXbRkws8LF
# Zslq3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7uVOMzPRgEop2zEBAQZvcXBf/XPle
# FzWYJFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqRUgCvOA8X9S95gWXZqbVr5MfO9sp6
# AG9LMEQkIjzP7QOllo9ZKby2/QThcJ8ySif9Va8v/rbljjO7Yl+a21dA6fHOmWaQ
# jP9qYn/dxUoLkSbiOewZSnFjnXshbcOco6I8+n99lmqQeKZt0uGc+R38ONiU9Mal
# CpaGpL2eGq4EQoO4tYCbIjggtSXlZOz39L9+Y1klD3ouOVd2onGqBooPiRa6YacR
# y5rYDkeagMXQzafQ732D8OE7cQnfXXSYIghh2rBQHm+98eEA3+cxB6STOvdlR3jo
# +KhIq/fecn5ha293qYHLpwmsObvsxsvYgrRyzR30uIUBHoD7G4kqVDmyW9rIDVWZ
# eodzOwjmmC3qjeAzLhIp9cAvVCch98isTtoouLGp25ayp0Kiyc8ZQU3ghvkqmqMR
# ZjDTu3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx16HSxVXjad5XwdHeMMD9zOZN+w2/
# XU/pnR4ZOC+8z1gFLu8NoFA12u8JJxzVs341Hgi62jbb01+P3nSISRIwggTaMIID
# wqADAgECAhMzAAAAhd/WWAkULse7AAAAAACFMA0GCSqGSIb3DQEBCwUAMHwxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTE2MDMzMDE5MjQyNFoXDTE3MDYz
# MDE5MjQyNFowgbMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# DTALBgNVBAsTBE1PUFIxJzAlBgNVBAsTHm5DaXBoZXIgRFNFIEVTTjo5OEZELUM2
# MUUtRTY0MTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCC
# ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM8H5bDdFazEemUu5+n3vBnf
# jn7cTYAENdl70mtbAz3LgpHQtnlGrjpPIaTCSgvbZLu6elBl3wwHISWqwtxixfKP
# Zp4hBIJ3x5cjZTUfFh5k82e+gSKaF8gBEIfGp5gHpe3BZAxUjAGDP4xCJo+gjSV5
# 9nggNfcnIL8IQc13J9mQVuxe6dolbM71PReZ7SxbVCi86F19LleYbndBAKV7e6z4
# LtBmHKgLlifDF4gBvo3ZD6NXJs+U3L0wJuPY00SjST5cS3YdDKCVhQT9PDBxrow/
# PfPXB7s4Xt1Ztid2jGACxPgCys2KzuXIvlNFNQ2xJMru8/+iLOAH2L3IQTJCOf8C
# AwEAAaOCARswggEXMB0GA1UdDgQWBBTKTrXYUzgEjV9mR5SNEOB4L5MWZzAfBgNV
# HSMEGDAWgBTVYzpcijGQ80N7fEYbxTNoWoVtVTBWBgNVHR8ETzBNMEugSaBHhkVo
# dHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNUaW1T
# dGFQQ0FfMjAxMC0wNy0wMS5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAC
# hj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1RpbVN0YVBD
# QV8yMDEwLTA3LTAxLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUF
# BwMIMA0GCSqGSIb3DQEBCwUAA4IBAQAByqeyOf5A3zXRHpF2CCFy5LA8PvkrnmiF
# t0JwYhNoLJXYrYRGMhj2/kPtkL2d2Abm8WgI5ywgt5zbe3SyiEQvl6Ob3UHF2E3H
# LTLLEwNQWIK0+RyYb8Cpk19PwY43Exd0teMplz7AvAxCYJaJFg+HMdNVfjyO03Ol
# 9wBkP7Va6aXNnqZ68EUS375581TjODfxjBE18AX2Vcxl/tr0dYCp5PRDkhdk/KMu
# FRm6GqwixniY8BcEpx+5SGoA7csAGIjzhTIONAIb9XgqNrRRYi8fk1+hkAYB9f5S
# rfBwNRWUazLSkesHfQtwwq8S4mCr49Ok4IiDvVED3P0pc3Ua+bFRoYIDdjCCAl4C
# AQEwgeOhgbmkgbYwgbMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xDTALBgNVBAsTBE1PUFIxJzAlBgNVBAsTHm5DaXBoZXIgRFNFIEVTTjo5OEZE
# LUM2MUUtRTY0MTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZaIlCgEBMAkGBSsOAwIaBQADFQBeRM6hMlI6sfiKgOB35nTJs7q6XqCBwjCBv6SB
# vDCBuTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjENMAsGA1UE
# CxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBOVFMgRVNOOjRERTktMEM1RS0zRTA5
# MSswKQYDVQQDEyJNaWNyb3NvZnQgVGltZSBTb3VyY2UgTWFzdGVyIENsb2NrMA0G
# CSqGSIb3DQEBBQUAAgUA23GKujAiGA8yMDE2MDgzMTE2NTYyNloYDzIwMTYwOTAx
# MTY1NjI2WjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDbcYq6AgEAMAcCAQACAhRs
# MAcCAQACAhx1MAoCBQDbctw6AgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQB
# hFkKAwGgCjAIAgEAAgMW42ChCjAIAgEAAgMHoSAwDQYJKoZIhvcNAQEFBQADggEB
# AEjcTP1nb9ni0OsNSYLT0gbMKx49ZvOrg78BUeaSc/9g97Thx3kL22hkLG5B7UrF
# jqJI8LsErImuTK87ADe2ZJ60b+kucxU4c9jF0iYx2sxPDQ+4QzHwAqOHNrLh7K6s
# MFk0P0dNJfiJ00o9RYQwlAJPLNcoslhc98QsSPE1LmEmMgMADtd6z4lmYCtEhz6U
# 0T7a+AAsMGkW+XNtQEIAhvBDzNnMUWoMtgsQd5jVMMuXtGLWbBJ/BnWGd9dSlNdz
# obfOmWo2QU8OHbhemls5ytZCXLoDuteDtXERMWjb7RirNLw5IaYz2xwld1hA4xZG
# hta4YjrRt5udWVB5QjZJoUIxggL1MIIC8QIBATCBkzB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMAITMwAAAIXf1lgJFC7HuwAAAAAAhTANBglghkgBZQMEAgEF
# AKCCATIwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEi
# BCCxaJvwd1ItPOu8gfkl4Ce/49EMypE3DV5bhBVSbNCH2zCB4gYLKoZIhvcNAQkQ
# AgwxgdIwgc8wgcwwgbEEFF5EzqEyUjqx+IqA4HfmdMmzurpeMIGYMIGApH4wfDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWlj
# cm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAACF39ZYCRQux7sAAAAAAIUw
# FgQU2E26IpBK7fp6jO44XyacUydHLoAwDQYJKoZIhvcNAQELBQAEggEAmVn9uQHq
# ksXl2kIgXI8BdV23bXxlTkp/ZjFSqBGw1sFoyBSrqqBO3GDknufeJZ4jS0FiQdgV
# qpkkyv7S92AjCfjKv0cSGIMM8E6Sm+8Q9Td2VKryNAoz84khb5kAP1oLRqBJbBmN
# PCdmm8AjCB8jOcG6v/LRJL9ya/jZgWc3p6YoNK6ZkMZCOuMaKHZE/kdO/YgxjfrS
# egGoyW9K+dZ0wHukxkaHYnReCecHbNh479AS4WyyCuRjxM/tLnGePh2Z7XUVHho7
# KKkG6YIN2I1KrDHFD/uGShHPqHYwNrWjMNi2kCo9E3ajoMtnnoK3S3Tri630e+Td
# dUf2D4+SyKbkIg==
# SIG # End signature block
