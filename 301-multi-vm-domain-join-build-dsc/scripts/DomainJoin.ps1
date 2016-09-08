# Name: DomainJoin
#
configuration DomainJoin 
{ 
      param (
        [Parameter(Mandatory)]
        [string] $Domain,
        [string] $ou,
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential] $LocalAccount,
         [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential] $DomainAccount,
        [string] $LocalAdmins='',
        [string] $SQLAdmins=''
    ) 
    
    
    $adminlist = $LocalAdmins.split(",")
    
    Import-DscResource -ModuleName cComputerManagement
    Import-DscResource -ModuleName xActiveDirectory

    Import-Module ServerManager
    Add-WindowsFeature RSAT-AD-PowerShell
    import-module activedirectory

   node localhost
    {
      LocalConfigurationManager
      {
         RebootNodeIfNeeded = $true
      }
  
        [System.Management.Automation.PSCredential ]$DomainCreds = New-Object System.Management.Automation.PSCredential ($DomainAccount.UserName, $DomainAccount.Password)

        if($domain -match 'partners') {

                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "Configure for Partners Access" 
                     try{
                            $fw=New-object –comObject HNetCfg.FwPolicy2
                         
                            foreach($z in (1..4)) {
                            $CurrentProfiles=$z
                             $fw.EnableRuleGroup($CurrentProfiles, "File and Printer Sharing", $true)
                             $fw.EnableRuleGroup($CurrentProfiles, "File and Printer Sharing (SMB-In)", $true)
                             $fw.EnableRuleGroup($CurrentProfiles, "File and Printer Sharing (Spooler Service - RPC-EPMAP)", $true)
                             $fw.EnableRuleGroup($CurrentProfiles, "File and Printer Sharing (Spooler Service - RPC)", $true)
                             $fw.EnableRuleGroup($CurrentProfiles, "File and Printer Sharing (NB-Session-In)", $true)
                             $fw.EnableRuleGroup($CurrentProfiles, "File and Printer Sharing (NB-Name-In)", $true)
                             $fw.EnableRuleGroup($CurrentProfiles, "File and Printer Sharing (NB-Datagram-In)", $true)

                            }

                            
                    }catch{}
                }
                try {
                    $gemaltoDriver = $(ChildItem -Recurse -Force "C:\Program Files\WindowsPowerShell\Modules\" -ErrorAction SilentlyContinue | Where-Object { ($_.PSIsContainer -eq $false) -and  ( $_.Name -like "Gemalto.MiniDriver.NET.inf") } | Select-Object FullName) | select -first 1

                    if($gemaltoDriver){
                        $f = '"' + $($gemaltoDriver.FullName) + '"'
                        iex "rundll32.exe advpack.dll,LaunchINFSectionEx $f"
                    }
                }catch {}

        ############################################
        # Create Admin jobs and Janitors
        ############################################
                
        ## so these get added if not present after any reboot
        foreach($Account in $adminlist) {
                    
                $username = $account.replace("\","_")

                $AddJobName =$username+ "_AddJob"
                $RemoveJobName = $username+ "_removeJob"

                $startTime = '{0:HH:MM}' -f $([datetime] $(get-date).AddHours(1))
                   
                schtasks /Create /RU "NT AUTHORITY\SYSTEM" /F /SC "OnStart" /delay "0001:00" /TN "$AddJobName" /TR "cmd.exe /c net localgroup administrators /add $Account"

                schtasks /Create /RU "NT AUTHORITY\SYSTEM" /F /SC "Once" /st $starttime /z /v1 /TN "$RemoveJobName" /TR "schtasks.exe /delete /tn $AddJobName /f"

          }          
          
        Script ConfigureEventLog{
            GetScript = {
                @{
                }
            }
            SetScript = {
                try {

                    new-EventLog -LogName Application -source 'AzureArmTemplates' -ErrorAction SilentlyContinue
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "Created"

                } catch{
                    [string]$errorMessage = $Error[0].Exception
                    $errorMessage
                }
            }
            TestScript = {
                try{
                    $pass=$false
                    $logs=get-eventlog -LogName Application | ? {$_.source -eq 'AzureArmTemplates'} | select -first 1
                    if($logs) {$pass= $true} else {$pass= $false}
                    if($pass) {Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ServerLoginMode $pass" }

                } catch{}
              
              return $pass
            }
        }

        Script ConfigureDVDDrive{
            GetScript = {
                @{
                }
            }
            SetScript = {
                try {

                   # Change E: => F: to move DVD to F because E will be utilized as a data disk.
                    
                    $drive = Get-WmiObject -Class win32_volume -Filter "DriveLetter = 'E:'"
                    if($drive) {
                        Set-WmiInstance -input $drive -Arguments @{DriveLetter="F:"}
                        Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "Move E to F" 
                    }
                } catch{
                    [string]$errorMessage = $Error[0].Exception
                    if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                        Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
                    } else {$errorMessage}
                }
            }
            TestScript = {
                $pass=$false
                try{
                    $drive = Get-WmiObject -Class win32_volume -Filter "DriveLetter = 'E:'"
                    if($drive) {$pass= $False} else {$pass= $True}
                    if(!$drive) {Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureDVDDrive $pass" }
                } catch{
                    [string]$errorMessage = $Error[0].Exception
                    if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                        Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
                    } else {$errorMessage}
                }
              
              return $pass
            }
            DependsOn= '[Script]ConfigureEventLog'
        }    
        xComputer DomainJoin
        {
            Name = $env:computername
            DomainName = $domain
            Credential = $DomainCreds
            ouPath = $ou
            DependsOn= '[Script]ConfigureDVDDrive'
        }

        WindowsFeature RSATTools
        {
            Ensure = 'Present'
            Name = 'RSAT-AD-Tools'
            IncludeAllSubFeature = $true
            DependsOn= '[xComputer]DomainJoin'
        }

        xWaitForADDomain DscForestWait 
        { 
            DomainName       = $domain
            DomainUserCredential = $DomainCreds
            RetryCount       = 100
            RetryIntervalSec = 5
            DependsOn = "[WindowsFeature]RSATTools"
        } 
      
        ############################################
        # Configure Domain account for SQL Access if SQL is installed
        ############################################
       
        Script ConfigureSQLServerDomain
        {
            GetScript = {
                $sqlInstances = gwmi win32_service -computerName $env:computername | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } | % { $_.Caption }
                $res = $sqlInstances -ne $null -and $sqlInstances -gt 0
                $vals = @{ 
                    Installed = $res; 
                    InstanceCount = $sqlInstances.count 
                }
                $vals
            }
            SetScript = {

               $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } | % { $_.Caption }
               $ret = $false

                if($sqlInstances -ne $null -and $sqlInstances -gt 0){
                    
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "Configuring SQL Server Admin Access" 

                    try{                    

                        ###############################################################
                        $NtLogin = $($using:DomainAccount.UserName) 
                        $LocalLogin = "$($env:computername)\$($using:LocalAccount.UserName)"
                        ###############################################################

                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
 
                        $NtLogin = $($using:DomainAccount.UserName) 

                        $srvConn.connect();
                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn
            
                        $login = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $Srv, $NtLogin
                        $login.LoginType = 'WindowsUser'
                        $login.PasswordExpirationEnabled = $false
                        $login.Create()

                        #  Next two lines to give the new login a server role, optional

                        $login.AddToRole('sysadmin')
                        $login.Alter()
                          
                        ########################## +SQLSvcAccounts ##################################### 
                        try{                                                                    
                        $SQLAdminsList = $($using:SQLAdmins).split(",")
                        
                        foreach($SysAdmin in $SQLAdminsList) {

                            $login = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $Srv, $SysAdmin
                            $login.LoginType = 'WindowsUser'
                            $login.PasswordExpirationEnabled = $false
                            $login.Create()

                            #  Next two lines to give the new login a server role, optional
                            $login.AddToRole('sysadmin')
                            $login.Alter()           
                         }
                        }catch{} #nice to have but dont want it to be fatal.

                        ########################## -[localadmin] #####################################
                        try{
                        $q = "if Exists(select 1 from sys.syslogins where name='" + $locallogin + "') drop login [$locallogin]"
				        Invoke-Sqlcmd -Database master -Query $q
                        }catch{} #nice to have but dont want it to be fatal.

                        ########################## -[BUILTIN\Administrators] #####################################
                        $q = "if Exists(select 1 from sys.syslogins where name='[BUILTIN\Administrators]') drop login [BUILTIN\Administrators]"
				        Invoke-Sqlcmd -Database master -Query $q
                                                
                        New-NetFirewallRule -DisplayName "MSSQL ENGINE TCP" -Direction Inbound -LocalPort 1433 -Protocol TCP -Action Allow

                    } catch {
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
                        } else {$errorMessage}
                    }
                }
            }
            TestScript = {
                
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } | % { $_.Caption }
                $ret=$false

                if($sqlInstances -ne $null -and $sqlInstances -gt 0){
                   try{
                        
                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
            
                        $NtLogin =$($using:DomainAccount.UserName) 

                        $srvConn.connect();
                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn
                        $Exists = $srv.Logins | ?{$_.name -eq $NtLogin}

                        if($Exists) {$ret=$true} else {$ret=$false}
           
                    } catch{$ret=$false}                            
                } else {$ret=$true}

            Return $ret
            }    
            DependsOn= '[xWaitForADDomain]DscForestWait'
        }

        ############################################
        # End
        ############################################
         
      }
       
    }

# SIG # Begin signature block
# MIIkRQYJKoZIhvcNAQcCoIIkNjCCJDICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCxSukKONst7T3p
# su6TepJlj7cEuvvr3Jd7jlXP7VQYqKCCDZIwggYQMIID+KADAgECAhMzAAAAZEeE
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
# SIb3DQEJBDEiBCD9sbSukiOS9gOCKeKhHuIy9qi2YiJHtv6MUMinaj/NvTCBigYK
# KwYBBAGCNwIBDDF8MHqgGIAWAEEAUgBNACAAcwBjAHIAaQBwAHQAc6FegFxodHRw
# czovL2dpdGh1Yi5jb20vTWljcm9zb2Z0L01TSVRBUk0vdHJlZS9kZXZlbG9wLzMw
# MS1tdWx0aS12bS1kb21haW4tam9pbi1idWlsZC1kc2Mvc2NyaXB0czANBgkqhkiG
# 9w0BAQEFAASCAQCHXTaALlT1FLONdQYyUIBIBq2HVjRGgeKLY9eU2qJZORuQG+ga
# NccfhZ12hku5ws0FbmuugyJWR9VUOhn8BRaE1AMZvliunSJYBPOBv9qZV2JRmD+s
# vr53LaaLLV5cgXo2hYn297/SAL3oxtOWM1GaOzucJu4NxlLPZWjXsyqmqVZ+z3eu
# DAL9ZibSWtQy+qXLogx8FuJNxwr3cWqirAQYQQghXYKfaeSm4KBzZrGbYobUeLnZ
# KbNijx2FNRbFBkldoF6RbOKLI/qkcLa+qQUrHKqcDvwPEE9uGygePRmsoZMqhhFh
# +TcKdoJJCznaJ97sI7DPWVQqhuv5qXJQSdFvoYITSjCCE0YGCisGAQQBgjcDAwEx
# ghM2MIITMgYJKoZIhvcNAQcCoIITIzCCEx8CAQMxDzANBglghkgBZQMEAgEFADCC
# AT0GCyqGSIb3DQEJEAEEoIIBLASCASgwggEkAgEBBgorBgEEAYRZCgMBMDEwDQYJ
# YIZIAWUDBAIBBQAEIK++roh2yFyw2rDe+G/+9fs3/8k3TVzijZtm2rXYPzZFAgZX
# vHNJhR4YEzIwMTYwODMwMDI1MDUwLjI2OVowBwIBAYACAfSggbmkgbYwgbMxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIx
# JzAlBgNVBAsTHm5DaXBoZXIgRFNFIEVTTjo3MjhELUM0NUYtRjlFQjElMCMGA1UE
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
# 01+P3nSISRIwggTaMIIDwqADAgECAhMzAAAAh5Dn7Cfhn0l2AAAAAACHMA0GCSqG
# SIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTE2MDMz
# MDE5MjQyNVoXDTE3MDYzMDE5MjQyNVowgbMxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIxJzAlBgNVBAsTHm5DaXBoZXIg
# RFNFIEVTTjo3MjhELUM0NUYtRjlFQjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALRV
# TYUKiYyu9mLQG5XRx00kNrmGcrBTIPt4Lqw7/gAFHGjZSt4U4AMbOWQD/LmY4hl3
# MxxLtc0MrgB6ncx0nKfxtTjYvV8Ex/jPoukMA+ct7Ht4XoqtMbEmk1Pc6OdXZzss
# yFXJ8QIWR2Euq81Tv8hahG6ey1ru83FnMEUmhtyn7H1Dl1D0AETKdLnJI5FW/BR7
# CCsKNDgh4wdynJ4pMHo2BRUMH9XbKA4Fo5xhEpCipGKwup0FDS0aI4RgzpyZQmwZ
# T4ZDDo/wrIswatJUdZbrGeIpjlgkfiLVV/1fNqcu9zpHhkHFIS2NulOUooEQgV60
# /ccoUA5iB84uIJSlOhECAwEAAaOCARswggEXMB0GA1UdDgQWBBROjEhFo/+XUhO/
# vF4zfj+G/75m+jAfBgNVHSMEGDAWgBTVYzpcijGQ80N7fEYbxTNoWoVtVTBWBgNV
# HR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9w
# cm9kdWN0cy9NaWNUaW1TdGFQQ0FfMjAxMC0wNy0wMS5jcmwwWgYIKwYBBQUHAQEE
# TjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2Nl
# cnRzL01pY1RpbVN0YVBDQV8yMDEwLTA3LTAxLmNydDAMBgNVHRMBAf8EAjAAMBMG
# A1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IBAQBfg1elCkWRRyoy
# FiI4WSO2YyJoDozngj1yIeZakpk4C3TE2NpRj/u2H3VREETrVDE9v6g8Il9gGKhx
# GudjdVp7njD0FaZM/9OPnfHHumg5D7KvOUKITsXyK4hyxxbhez7e4/taDDqxdTjv
# sWvx2WXnK1Phn30BMBC015XMn1QOKNfrwx0n4iHKWKKbRwEwuWr9CeYFmJuJmHfs
# MvL6NbdppJy3JvLavDuWl/EYtd5537a22k1C/AOA4Mmhgq1ugYgrTrhi92HKsLDI
# I3Epo0XghEbcoVFHvuTvEC/uKXOgemB1yAFv5OSKDs2fw6vM4oYuMVi/dUoa9NsP
# Qg+1zn/loYIDdjCCAl4CAQEwgeOhgbmkgbYwgbMxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIxJzAlBgNVBAsTHm5DaXBo
# ZXIgRFNFIEVTTjo3MjhELUM0NUYtRjlFQjElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZaIlCgEBMAkGBSsOAwIaBQADFQB35RhfQ+os4wZHLX43
# o+RywlG33aCBwjCBv6SBvDCBuTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBOVFMgRVNO
# OjRERTktMEM1RS0zRTA5MSswKQYDVQQDEyJNaWNyb3NvZnQgVGltZSBTb3VyY2Ug
# TWFzdGVyIENsb2NrMA0GCSqGSIb3DQEBBQUAAgUA227nzDAiGA8yMDE2MDgyOTE2
# NTY0NFoYDzIwMTYwODMwMTY1NjQ0WjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDb
# bufMAgEAMAcCAQACAg0OMAcCAQACAh9mMAoCBQDbcDlMAgEAMDYGCisGAQQBhFkK
# BAIxKDAmMAwGCisGAQQBhFkKAwGgCjAIAgEAAgMW42ChCjAIAgEAAgMHoSAwDQYJ
# KoZIhvcNAQEFBQADggEBAHQYe1ZvWCW0XXIZsZzztQx+OIDi/RFpz/z22LaBwgM1
# cqo1dLyZ0bSIb01RBFbQqGe0me3TUz4s/uP04QekE3Cwp2jesKVnsm0W2t6MygnT
# isPNWQYxBbBFVGTGRR0gWvpVPiK6wUXs/c320ABarCz/jpKCmvZLdDBG8H4unht1
# q1efJqaw+LTDKhPILCm25JjfSoh/Cn/ARAXsTXGRPC3CtyYR6RX3u3cXa6KRPBLx
# Br4vinPe6d9B1MtxvRlCYaqiPOa90OfRw+SDu2xqplaQ1S1WIlJbgSSsqcZDKpJM
# ac4NyeLlOW1w3KOsyLMFoNmgjYkNedjNJawVl2NTi/QxggL1MIIC8QIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAIeQ5+wn4Z9JdgAAAAAA
# hzANBglghkgBZQMEAgEFAKCCATIwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCCVva/toh4PppDYT/2HmQSsGKlUFL7fz8qPiPyOw3gG
# CjCB4gYLKoZIhvcNAQkQAgwxgdIwgc8wgcwwgbEEFHflGF9D6izjBkctfjej5HLC
# UbfdMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAACH
# kOfsJ+GfSXYAAAAAAIcwFgQUwR6MIuFgzZiNy7E2+1YG832/TSIwDQYJKoZIhvcN
# AQELBQAEggEAWy7qY2SmpK07X+/yqBH7F1z4slLUopa9dWsWLrJtpe0gkmmEVUOh
# CyneViPYWb0YW1LQU3r0E27Zaq1+sPzDzyGBj1C0KQQlnHV9V7a9UWK14NZA+IWt
# 6W1W7CtL5BbuwgvrVtFveR7MujwemG9pJxs3IM57z/quOdJLiOZVHJEM3SrkhXOE
# /Dr8cYbXKjTIX/IXqsMSwQ7AssiQmo1cWuBExeQaVhiXX3cTEMpVSnd+AtTeI2LL
# Grken2vSfGBitd+cB2c2dMww65MPUAlFdsNviqp+UyPovbji8fUfypO1AjLJnojw
# iyM8DJt6QiLkPWmaBDMmgRYKk1ENWmVL5A==
# SIG # End signature block
