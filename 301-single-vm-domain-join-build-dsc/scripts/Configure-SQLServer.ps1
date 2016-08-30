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

# SIG # Begin signature block
# MIIkRQYJKoZIhvcNAQcCoIIkNjCCJDICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCk2LWYDORpITT6
# H2YsXfexEO1Ri27hg3dGwDchK81z1aCCDZIwggYQMIID+KADAgECAhMzAAAAZEeE
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
# CrE/+6jMpF3BoYibV3FWTkhFwELJm3ZbCoBIa/15n8G9bW1qyVJzEw16UM0xghYJ
# MIIWBQIBATCBlTB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExAhMzAAAA
# ZEeElIbbQRk4AAAAAABkMA0GCWCGSAFlAwQCAQUAoIH3MBkGCSqGSIb3DQEJAzEM
# BgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqG
# SIb3DQEJBDEiBCD0TeHhqvYZeffQIKls6QTJDS22ET/ejZymfarjOtwdPjCBigYK
# KwYBBAGCNwIBDDF8MHqgGIAWAEEAUgBNACAAcwBjAHIAaQBwAHQAc6FegFxodHRw
# czovL2dpdGh1Yi5jb20vTWljcm9zb2Z0L01TSVRBUk0vdHJlZS9kZXZlbG9wLzMw
# MS1tdWx0aS12bS1kb21haW4tam9pbi1idWlsZC1kc2Mvc2NyaXB0czANBgkqhkiG
# 9w0BAQEFAASCAQCCldcjmAF0OCxIGoD5DhiL4AixK3GNbvotSselIBpu3yJxysjl
# q8IgejDM6yeS+CRlx4Y10XnXgS0I1cd9QxJarawNrvpzGmnRZIzDojGt4zgsg6mB
# qG/OVico+663OjfDtVzVKJ8VOFUYfTg8vtWjMQ+yPtyfQsWHPf0rBPbasSSKQJ3g
# h3Ckxg9fv7Zh5GiiCrJQcpV2VjwhuCJ1cXdQ2MCEcf6MUBrV61UrjKOJy0Qwdsdu
# 4UhVd0/OHJ96PQpc9fGMtmtaY/QO0r6FlvZQhCPL+Prh5WM5i6BNhkyOTPrKv4nk
# JDbNNJgZi08HMdlVxN8AbXcisE4OFF3KwQ7yoYITSjCCE0YGCisGAQQBgjcDAwEx
# ghM2MIITMgYJKoZIhvcNAQcCoIITIzCCEx8CAQMxDzANBglghkgBZQMEAgEFADCC
# AT0GCyqGSIb3DQEJEAEEoIIBLASCASgwggEkAgEBBgorBgEEAYRZCgMBMDEwDQYJ
# YIZIAWUDBAIBBQAEICtvqYzNYUBP0iBTHR/oPQkNSNfAXjSP9jl6jN8Koti9AgZX
# vIIiAl0YEzIwMTYwODMwMDI1MDQ0LjIzMVowBwIBAYACAfSggbmkgbYwgbMxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIx
# JzAlBgNVBAsTHm5DaXBoZXIgRFNFIEVTTjozMUM1LTMwQkEtN0M5MTElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCDs0wggZxMIIEWaADAgEC
# AgphCYEqAAAAAAACMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0
# aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0yNTA3MDEy
# MTQ2NTVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIBIjANBgkqhkiG
# 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWlCgCC
# hfvtfGhLLF/Fw+Vhwna3PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBED/FgiIRU
# QwzXTbg4CLNC3ZOs1nMwVyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeRX4FU
# sc+TTJLBxKZd0WETbijGGvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd/XcfPfBX
# day9ikJNQFHRD5wGPmd/9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogINeh4
# HLDpmc085y9Euqf03GS9pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQABo4IB5jCC
# AeIwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8RhvFM2ha
# hW1VMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNV
# HRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYG
# A1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3Js
# L3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcB
# AQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kv
# Y2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSABAf8EgZUw
# gZIwgY8GCSsGAQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0
# HjIgHQBMAGUAZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0
# AC4gHTANBgkqhkiG9w0BAQsFAAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Ehb7Prpsz1
# Mb7PBeKp/vpXbRkws8LFZslq3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7uVOMzPRg
# Eop2zEBAQZvcXBf/XPleFzWYJFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqRUgCvOA8X
# 9S95gWXZqbVr5MfO9sp6AG9LMEQkIjzP7QOllo9ZKby2/QThcJ8ySif9Va8v/rbl
# jjO7Yl+a21dA6fHOmWaQjP9qYn/dxUoLkSbiOewZSnFjnXshbcOco6I8+n99lmqQ
# eKZt0uGc+R38ONiU9MalCpaGpL2eGq4EQoO4tYCbIjggtSXlZOz39L9+Y1klD3ou
# OVd2onGqBooPiRa6YacRy5rYDkeagMXQzafQ732D8OE7cQnfXXSYIghh2rBQHm+9
# 8eEA3+cxB6STOvdlR3jo+KhIq/fecn5ha293qYHLpwmsObvsxsvYgrRyzR30uIUB
# HoD7G4kqVDmyW9rIDVWZeodzOwjmmC3qjeAzLhIp9cAvVCch98isTtoouLGp25ay
# p0Kiyc8ZQU3ghvkqmqMRZjDTu3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx16HSxVXj
# ad5XwdHeMMD9zOZN+w2/XU/pnR4ZOC+8z1gFLu8NoFA12u8JJxzVs341Hgi62jbb
# 01+P3nSISRIwggTaMIIDwqADAgECAhMzAAAAmbqvi+MEOGuIAAAAAACZMA0GCSqG
# SIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTE2MDQy
# NzE3MDYxOVoXDTE3MDcyNzE3MDYxOVowgbMxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIxJzAlBgNVBAsTHm5DaXBoZXIg
# RFNFIEVTTjozMUM1LTMwQkEtN0M5MTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOIe
# cb5DBpjvg9ZADf21OXegZrYo3dZo+EHwBPPISeZ7MlqE58xEGAZRHfGPw9FPKL22
# 5yGd406KS4aNDXIKtl6uPV55eQxNilr8zwKzAJY61auCO/Cglq8+RRG40oV1PIJL
# otWSL5wF51Gg5qMmymCpv6P1+nriELNiia1wwe+6OzM8C45kZ149xPK9/KLlr4Eq
# XnZq9B1MifwbJc2Fcn7j6uDnSqFW0RWCilXerY4S657jb+5Wspk89+T5s8AB8U0S
# ql24Hwg2Q/BlmAfHzwSEYScCHmNFk0DyAFPoC4OpdqbpSEK/L/08LcL8MUBLNuav
# 2I+YSl3YRn8Uc3yXPx0CAwEAAaOCARswggEXMB0GA1UdDgQWBBSLksJsJor8+GyE
# EHcEdxlVJwHMQjAfBgNVHSMEGDAWgBTVYzpcijGQ80N7fEYbxTNoWoVtVTBWBgNV
# HR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9w
# cm9kdWN0cy9NaWNUaW1TdGFQQ0FfMjAxMC0wNy0wMS5jcmwwWgYIKwYBBQUHAQEE
# TjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2Nl
# cnRzL01pY1RpbVN0YVBDQV8yMDEwLTA3LTAxLmNydDAMBgNVHRMBAf8EAjAAMBMG
# A1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IBAQAuNxZkKaJTtDDX
# j1AYT0JdV0uPv4gMfQsWs4qi7lBJ9y2AwY6btRj5QUXtvt29ovJPXC2wyb+R/Uyr
# 2Ajlqqb/GowPmEbmByCSSTCbq7djK6z1H++7sUpVfYarZIWXp+fr94jAlv2cE5AN
# IrNmr3J+NM1Dneum6HvVJzAovNf5u9QLUe3o9dISWDklWZBxipaarpkpYFOeh+hE
# 8dI6+o2m+gkJK7BuaSHlmE+phX38Jp1VvrKb9mJFAVIz6Z9ZowQk20rUsN0ir2q8
# oz/ABQH9wM75no7zB6hD0p2KAgb+qzJScJL6QakCNYLAyQef8JA5wg4oAM0iXok3
# XfakxOQvoYIDdjCCAl4CAQEwgeOhgbmkgbYwgbMxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIxJzAlBgNVBAsTHm5DaXBo
# ZXIgRFNFIEVTTjozMUM1LTMwQkEtN0M5MTElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZaIlCgEBMAkGBSsOAwIaBQADFQCxNuJXpegpXNS+a6n5
# 95abD/g2JaCBwjCBv6SBvDCBuTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBOVFMgRVNO
# OjU3RjYtQzFFMC01NTRDMSswKQYDVQQDEyJNaWNyb3NvZnQgVGltZSBTb3VyY2Ug
# TWFzdGVyIENsb2NrMA0GCSqGSIb3DQEBBQUAAgUA229Q3TAiGA8yMDE2MDgzMDAw
# MjUwMVoYDzIwMTYwODMxMDAyNTAxWjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDb
# b1DdAgEAMAcCAQACAgL7MAcCAQACAhhuMAoCBQDbcKJdAgEAMDYGCisGAQQBhFkK
# BAIxKDAmMAwGCisGAQQBhFkKAwGgCjAIAgEAAgMW42ChCjAIAgEAAgMHoSAwDQYJ
# KoZIhvcNAQEFBQADggEBAGciH8i2KZ8yweNqYhaLed0ZpqIU81bw+ymr4lzaj9nr
# Uj1LQFS8AaiG4gI30RHO0Iq6R7y2+HFthsEgoApO1BwYkvwMrfVxJpriB41J1RS7
# 4qHWk9i5zixja890ExkWPqvpmK4qUg5D4TTIK9xZIyTRn7GloER2lfDtsd3/8yQs
# Y60M9IOaE1XYUkIcjAfPNg63oOOEpro7p5Gk6GOSrXlVZZOfjmsttah6fgA6PRMB
# l7EbfsHjQWAyJCRJ7hwxo9/DG0SYVu/BYzAdU1ZI2Qfy+kKQTDjAOJhrvz/ZuO9n
# ke1bX2INMwIbPoypj98xocPoG1xR76N66RyW53rI1JUxggL1MIIC8QIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAJm6r4vjBDhriAAAAAAA
# mTANBglghkgBZQMEAgEFAKCCATIwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCDxGHHSW4kWd6THVA2BlK+7meYMSiDc4uLewbNScQsk
# LzCB4gYLKoZIhvcNAQkQAgwxgdIwgc8wgcwwgbEEFLE24lel6Clc1L5rqfn3lpsP
# +DYlMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAACZ
# uq+L4wQ4a4gAAAAAAJkwFgQUJckD9XMrFL/wmfijHQJadAWu8mYwDQYJKoZIhvcN
# AQELBQAEggEAxbm6R9V8WPtVJOMx3mYg0JFw5QkrKx0vsk0fqFnwThTfoBz0XeGh
# NP1+v+ypBy4ZryezaUg3GkQwQvkyC7uQ2iGRROZoOTTbv8izh2qog65fJNOD5zVQ
# 7BG0VWxzhqbYXJ2SZU06S0Nuhy0P6CnuYzWWqgqkSYxYqMe9rX97/49qnuxMEsgD
# mnXr69IuMuuBUiGT7b+dMFfpHIWW0WDhYBv7MFNR2v6wUpMx2Qku3nmLxn34lx5e
# mPVeFRlAKkUl2T/wHiX+ahgjsjQnJdne3fFAYBuhLjZ63rylANYVpjBZWSdi8j6S
# NzaE0RAuyk07+QvmDEoZhnS55tLotquH2Q==
# SIG # End signature block
