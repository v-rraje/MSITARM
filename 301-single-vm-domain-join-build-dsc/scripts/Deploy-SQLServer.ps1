# Name: DeploySQLServer
#
Configuration DeploySQLServer
{
  param (  
   [Parameter(Mandatory)]
   [string] $DataPath="H:\MSSqlServer\MSSQL\DATA",
   [Parameter(Mandatory)]
   [string] $LogPath="O:\MSSqlServer\MSSQL\DATA",
   [Parameter(Mandatory)]
   [string] $BackupPath="E:\MSSqlServer\MSSQL\bak",
   [Parameter(Mandatory)]
   [string] $TempDBPath="T:\MSSqlServer\MSSQL\DATA",
   [Parameter(Mandatory)]
   [string] $baseurl="https://raw.githubusercontent.com/Microsoft/MSITARM/"
  )

  Node localhost
  {

    

    $InstanceName =Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' -Name InstalledInstances | Select-Object -ExpandProperty InstalledInstances | ?{$_ -eq 'MSSQLSERVER'}
    $InstanceFullName = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' -Name $InstanceName | Select-Object -ExpandProperty $InstanceName;
    $DataPath   = $DataPath.replace('MSSqlServer',$InstanceFullName)
    $LogPath    = $LogPath.replace('MSSqlServer',$InstanceFullName)
    $BackupPath = $BackupPath.replace('MSSqlServer',$InstanceFullName)
    $TempDBPath = $TempDBPath.replace('MSSqlServer',$InstanceFullName)
    $ErrorPath = $(split-path $("$dataPath") -Parent)+"\Log"

  	    Script ConfigureEventLog{
            GetScript = {
                @{
                }
            }
            SetScript = {
                try {

                    new-EventLog -LogName Application -source 'AzureArmTemplates' -ErrorAction SilentlyContinue
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "Created"

                } catch{}
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

        File StartupPath {
            Type = 'Directory'
            DestinationPath = "C:\SQLStartup"
            Ensure = "Present"
            DependsOn = "[Script]ConfigureEventLog"
        }
        Script ConfigureStartupPath{
            GetScript = {
                @{
                }
            }
            SetScript = {
                   
                    try { 
 
                        $Root = "C:\SQLStartup"

                        if($(test-path -path $root) -eq $true) {
                        
                            $ACL = Get-Acl $Root
 
                            $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"

                            $propagation = [system.security.accesscontrol.PropagationFlags]"None" 

                            $acl.SetAccessRuleProtection($True, $False)

                            #Adding the Rule
                                                                                           
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("CREATOR OWNER", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                                                        
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "ReadAndExecute", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                            
                            #Setting the Change
                            Set-Acl $Root $acl
                      }                         
                       
                    } catch{
                       [string]$errorMessage = $Error[0].Exception
                       if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureDataPath: $errorMessage"
                       }
                    }
                }           
            TestScript = { 

                $pass = $true

                $Root = "C:\SQLStartup"

                if($(test-path -path $root) -eq $true) {
                    $ACL = Get-Acl $Root
                                   
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'CREATOR OWNER'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'NT AUTHORITY\SYSTEM'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'BUILTIN\Administrators'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'BUILTIN\Users'}}).FileSystemRights -ne 'ReadAndExecute'){
                        $pass= $false
                    }                      

                } else {
                    $pass = $false
                }

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureDataPath $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureDataPath $pass"
                }

             return $pass
            }
            DependsOn = "[File]StartupPath"
        }

        File SQLDataPath {
            Type = 'Directory'
            DestinationPath = $DataPath
            Ensure = "Present"
            DependsOn = "[Script]ConfigureStartupPath"
        }
        Script ConfigureDataPath{
            GetScript = {
                @{
                }
            }
            SetScript = {
                   
                    try { 
 
                        $Root = $($using:DataPath)

                        if($(test-path -path $root) -eq $true) {
                        
                            $ACL = Get-Acl $Root
 
                            $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"

                            $propagation = [system.security.accesscontrol.PropagationFlags]"None" 

                            $acl.SetAccessRuleProtection($True, $False)

                            #Adding the Rule

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\MSSQLSERVER", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\SQLSERVERAGENT", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                                                        
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("CREATOR OWNER", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                                                        
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "ReadAndExecute", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)


                            #Setting the Change
                            Set-Acl $Root $acl
                      }                         
                       
                    } catch{
                       [string]$errorMessage = $Error[0].Exception
                       if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureDataPath: $errorMessage"
                       }
                    }
                }           
            TestScript = { 

                $pass = $true

                $Root = $($using:DataPath)

                if($(test-path -path $root) -eq $true) {
                    $ACL = Get-Acl $Root
                
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'NT SERVICE\MSSQLSERVER'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    }
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -ne 'NT SERVICE\SQLSERVERAGENT'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'CREATOR OWNER'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'NT AUTHORITY\SYSTEM'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'BUILTIN\Administrators'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'BUILTIN\Users'}}).FileSystemRights -ne 'ReadAndExecute'){
                        $pass= $false
                    }                      

                } else {
                    $pass = $false
                }

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureDataPath $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureDataPath $pass"
                }

             return $pass
            }
            DependsOn = "[File]SQLDataPath"
        }
       
        File SQLLogPath {
            Type = 'Directory'
            DestinationPath = $LogPath
            Ensure = "Present"
        }
        Script ConfigureLogPath{
            GetScript = {
                @{
                }
            }
            SetScript = {
                   
                    try { 
 
                        $Root = $($using:logPath)

                        if($(test-path -path $root) -eq $true) {
                        
                            $ACL = Get-Acl $Root
 
                            $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"

                            $propagation = [system.security.accesscontrol.PropagationFlags]"None" 

                            $acl.SetAccessRuleProtection($True, $False)

                            #Adding the Rule

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\MSSQLSERVER", "FullControl", $inherit, $propagation, "Allow")   
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\SQLSERVERAGENT", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                                                        
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("CREATOR OWNER", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                            
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "ReadAndExecute", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                            #Setting the Change
                            Set-Acl $Root $acl
                      }                         
                       
                    } catch{
                       [string]$errorMessage = $Error[0].Exception
                       if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureLogPath: $errorMessage"
                       }
                    }
                }
            TestScript = { 

                $pass = $true

                $Root = $($using:LogPath)

               if($(test-path -path $root) -eq $true) {
                    $ACL = Get-Acl $Root
                
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'NT SERVICE\MSSQLSERVER'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    }
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -ne 'NT SERVICE\SQLSERVERAGENT'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'CREATOR OWNER'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'NT AUTHORITY\SYSTEM'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'BUILTIN\Administrators'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'BUILTIN\Users'}}).FileSystemRights -ne 'ReadAndExecute'){
                        $pass= $false
                    } 

                } else {
                    $pass = $false
                }
                
                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureLogPath $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureLogPath $pass"
                }

             return $pass
            }
            DependsOn = "[File]SQLLogPath"
        }

        File SQLTempdbPath {
            Type = 'Directory'
            DestinationPath = $TempDBPath
            Ensure = "Present"
        }
        Script ConfigureTempdbPath{
            GetScript = {
                @{
                }
            }
            SetScript = {
                   
                    try { 
 
                        $Root = $($using:TempdbPath)

                        if($(test-path -path $root) -eq $true) {
                        
                            $ACL = Get-Acl $Root
 
                            $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"

                            $propagation = [system.security.accesscontrol.PropagationFlags]"None" 

                            $acl.SetAccessRuleProtection($True, $False)

                            #Adding the Rule

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\MSSQLSERVER", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\SQLSERVERAGENT", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                                                        
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("CREATOR OWNER", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                            
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "ReadAndExecute", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            #Setting the Change
                            Set-Acl $Root $acl
                      }                         
                       
                    } catch{
                       [string]$errorMessage = $Error[0].Exception
                       if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureTempdbPath: $errorMessage"
                       }
                    }
                }
            TestScript = { 

                $pass = $true

                $Root = $($using:TempdbPath)

               if($(test-path -path $root) -eq $true) {
                    $ACL = Get-Acl $Root
                
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'NT SERVICE\MSSQLSERVER'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    }
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -ne 'NT SERVICE\SQLSERVERAGENT'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'CREATOR OWNER'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'NT AUTHORITY\SYSTEM'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'BUILTIN\Administrators'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    }
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'BUILTIN\Users'}}).FileSystemRights -ne 'ReadAndExecute'){
                        $pass= $false
                    } 
                     
                } else {
                    $pass = $false
                }
                
                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureTempdbPath $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureTempdbPath $pass"
                }

             return $pass
            }
            DependsOn = "[File]SQLTempdbPath"
        }

        File SQLBackupPath {
            Type = 'Directory'
            DestinationPath = $BackupPath
            Ensure = "Present"
        }
        Script ConfigurebacakupPath{
            GetScript = {
                @{
                }
            }
            SetScript = {
                   
                    try { 
 
                        $Root = $($using:BackupPath)

                        if($(test-path -path $root) -eq $true) {
                        
                            $ACL = Get-Acl $Root
 
                            $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"

                            $propagation = [system.security.accesscontrol.PropagationFlags]"None" 

                            $acl.SetAccessRuleProtection($True, $False)

                            #Adding the Rule


                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\MSSQLSERVER", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\SQLSERVERAGENT", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                                                        
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("CREATOR OWNER", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                            
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
    
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "ReadAndExecute", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            #Setting the Change
                            Set-Acl $Root $acl
                      }                         
                       
                    } catch{
                       [string]$errorMessage = $Error[0].Exception
                       if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigurebacakupPath: $errorMessage"
                       }
                    }
                }
            TestScript = { 

                $pass = $true

                $Root = $($using:BackupPath)

               if($(test-path -path $root) -eq $true) {
                    $ACL = Get-Acl $Root
                
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'NT SERVICE\MSSQLSERVER'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    }
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -ne 'NT SERVICE\SQLSERVERAGENT'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'CREATOR OWNER'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'NT AUTHORITY\SYSTEM'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'BUILTIN\Administrators'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    }
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'BUILTIN\Users'}}).FileSystemRights -ne 'ReadAndExecute'){
                        $pass= $false
                    } 
                     
                } else {
                    $pass = $false
                }
                
                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigurebacakupPath $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigurebacakupPath $pass"
                }

             return $pass
            }
            DependsOn = "[File]SQLBackupPath"
        }

        File SQLErrorPath {
            Type = 'Directory'
            DestinationPath = $ErrorPath
            Ensure = "Present"
        }
        Script ConfigureErrorPath{
            GetScript = {
                @{
                }
            }
            SetScript = {
                   
                    try { 
 
                        $Root = $($using:ErrorPath)

                        if($(test-path -path $root) -eq $true) {
                        
                            $ACL = Get-Acl $Root
 
                            $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"

                            $propagation = [system.security.accesscontrol.PropagationFlags]"None" 

                            $acl.SetAccessRuleProtection($True, $False)

                            #Adding the Rule

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\MSSQLSERVER", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT SERVICE\SQLSERVERAGENT", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                                                        
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("CREATOR OWNER", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)
                                                        
                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "ReadAndExecute", $inherit, $propagation, "Allow")
                            $acl.AddAccessRule($accessrule)

                            #Setting the Change
                            Set-Acl $Root $acl
                      }                         
                       
                    } catch{
                       [string]$errorMessage = $Error[0].Exception
                       if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureErrorPath: $errorMessage"
                       }
                    }
            }           
            TestScript = { 

                $pass = $true

                $Root = $($using:ErrorPath)

               if($(test-path -path $root) -eq $true) {
                    $ACL = Get-Acl $Root
                
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'NT SERVICE\MSSQLSERVER'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    }
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -ne 'NT SERVICE\SQLSERVERAGENT'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'CREATOR OWNER'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'NT AUTHORITY\SYSTEM'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'BUILTIN\Administrators'}}).FileSystemRights -ne 'FullControl'){
                        $pass= $false
                    } 
                    if($($ACL | %{ $_.access | ?{$_.IdentityReference -eq 'BUILTIN\Users'}}).FileSystemRights -ne 'ReadAndExecute'){
                        $pass= $false
                    } 
                } else {
                    $pass = $false
                }
                
                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureErrorPath $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureErrorPath $pass"
                }

             return $pass
            }
            DependsOn = "[File]SQLErrorPath"
        }
                      
        Script ConfigureServerLoginMode{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
   
                if($sqlInstances -ne $null){

                    try {  

                        ############################################                     
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
 
                        $srvConn.connect();

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn
                        $srv.Settings.LoginMode = [Microsoft.SqlServer.Management.SMO.ServerLoginMode]::Integrated
                        $srv.Alter()
                       
                    } catch {
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureServerLoginMode: $errorMessage"
                        }
                    }
                }
            }
            TestScript = { 
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $pass = $false

                if($sqlInstances -ne $null){

                    try {
                        ############################################
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
 
                        $srvConn.connect();
                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn
            
                        if($srv.Settings.LoginMode -eq "Integrated") {$pass =  $true} else {$pass =  $false}
                
                    }catch {$pass = $false}
                }else{$pass=$true}

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureServerLoginMode $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureServerLoginMode $pass"
                }
                
              
              return $pass
            }
            DependsOn = "[Script]ConfigureErrorPath"

        }

        Script ConfigureMaxDop{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                    try {

                        ############################################         
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                        
                        $srvConn.connect();

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn
                             
                        ############################################
                        # Set Max D.O.P.:  n=num of procs
                        ############################################
                       
                        $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                        $coreCount = ($cpu.NumberOfCores | Measure-Object -Sum).Sum
                  
                        if($($coreCount) -eq 1) { $maxDop=1 }
                        if($($coreCount) -ge 2 -and $($coreCount) -le 7) { $maxDop=2 }
                        if($($coreCount) -ge 8 -and $($coreCount) -le 16) { $maxDop=4 }
                        if($($coreCount) -gt 16) { $maxDop=8 }
                                          
                        $srv.configuration.MaxDegreeOfParallelism.ConfigValue =$maxDop
                        $srv.configuration.Alter();
                                               
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureMaxDop: $errorMessage"
                        } 
                    }
                }
            }
            TestScript = { 

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){

                    try {

                        ############################################
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srvConn.connect();

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        ############################################
                        # Test Max D.O.P.:  n=num of procs
                        ############################################
                        $pass=$false

                        $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                        $coreCount = ($cpu.NumberOfCores | Measure-Object -Sum).Sum
                   
                        if($($coreCount) -eq 1) { $maxDop=1 }
                        if($($coreCount) -ge 2 -and $($coreCount) -le 7) { $maxDop=2 }
                        if($($coreCount) -ge 8 -and $($coreCount) -le 16) { $maxDop=4 }
                        if($($coreCount) -gt 16) { $maxDop=8 }
                
                        if($srv.configuration.MaxDegreeOfParallelism.ConfigValue -eq $maxDop) { $pass= $true} else { $pass= $false}
                        
                    } catch{ $pass= $false}

                } else { $pass= $false}

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureMaxDop $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureMaxDop $pass"
                }
             return $pass
            }
            DependsOn = "[Script]ConfigureServerLoginMode"
        }

        Script ConfigureDefaultLocations{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
    
                if($sqlInstances -ne $null){
                   
                    try {
                        ############################################      
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srvConn.connect();

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        ###########################################
                        #  Set the backup location to $disks.SQLServer.backupPath
                        ############################################
                        $BackupDir = $($using:backupPath)
                       
                        $srv.BackupDirectory = $BackupDir
                        $srv.Alter()

                        ###########################################
                        #  Set the backup compression to true
                        ###########################################
                        $srv.Configuration.DefaultBackupCompression.ConfigValue = $true
                        $srv.Configuration.Alter()

                        ###########################################
                        #  Set the data location to $disks.SQLServer.backupPath
                        ############################################
                        $DefaultFileDir = $($using:DataPath)
                        
                        $srv.defaultfile = $DefaultFileDir
                        $srv.Alter()

                        ###########################################
                        #  Set the backup location to $disks.SQLServer.backupPath
                        ############################################
                        $DefaultLog = $($using:LogPath)
                        
                        $srv.DefaultLog = $DefaultLog
                        $srv.Alter()                 
                                               
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureDefaultLocations: $errorMessage"
                        }
                    }
                }
            }
            TestScript = { 

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                    ############################################
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                    ############################################

                    $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                    
                        $srvConn.connect();

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                    $pass=$true

                    ###########################################
                    #  Set the backup location to $disks.SQLServer.backupPath
                    ############################################
                    $BackupDir = $($using:backupPath)
               
                    if($srv.BackupDirectory -ne $BackupDir) {
                        $pass = $false
                    }

                    ###########################################
                    #  Set the data location to $disks.SQLServer.DataPath
                    ############################################
                    $DefaultFileDir = $($using:DataPath+"\")
                
                    if($srv.defaultfile -ne $DefaultFileDir){
                        $pass = $false
                    }

                    ###########################################
                    #  Set the backup location to $disks.SQLServer.LogPath
                    ############################################
                    $DefaultLog = $($using:LogPath+"\")
               
                    if($srv.DefaultLog -ne $DefaultLog) {
                        $pass = $false
                    }

                } else {$pass=$false}

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureDefaultLocations $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureDefaultLocations $pass"
                }

             return $pass
            }
            DependsOn = "[Script]ConfigureMaxDop"
        }

        Script ConfigureMaxMemory{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                   
                    try { 
                        ############################################ 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                        
                        $srvConn.connect();

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        ############################################
                        # Set Max Server MemorySQL
                        ############################################

                        $PhysicalRAM = (Get-WMIObject -class Win32_PhysicalMemory -ComputerName:$env:COMPUTERNAME |Measure-Object -Property capacity -Sum | % {[Math]::Round(($_.sum / 1GB),2)})
                      
                       if($PhysicalRAM -eq 7) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 4096 
                        }
                        if($PhysicalRAM -eq 8) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 4096
                        }
                         if($PhysicalRAM -eq 14) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 10240 
                        }
                        if($PhysicalRAM -eq 16) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 12288 
                        }
                        if($PhysicalRAM -eq 24) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 19456   
                        }
                         if($PhysicalRAM -eq 28) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 22528 
                        }
                        if($PhysicalRAM -eq 32) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 25600
                        }
                        if($PhysicalRAM -eq 48) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 38912
                        }
                        if($PhysicalRAM -eq 56) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 45056
                        }

                        if($PhysicalRAM -eq 64) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 52224
                        }
                        if($PhysicalRAM -eq 72) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 38912
                        }
                        if($PhysicalRAM -eq 96) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 77824
                        }
                         if($PhysicalRAM -eq 112) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 91136 
                        }
                        if($PhysicalRAM -eq 128) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 104448
                        }
                         if($PhysicalRAM -eq 140) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 114688 
                        }
                         if($PhysicalRAM -eq 224) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 196608 
                        }
                        if($PhysicalRAM -eq 256) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 229376
                        }
                         if($PhysicalRAM -eq 448) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 425984 
                        }
                        if($PhysicalRAM -eq 512) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 491520
                        }
                        if($PhysicalRAM -eq 768) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 753664
                        }
                        if($PhysicalRAM -eq 1024) 
                        {
                        $srv.configuration.MaxServerMemory.ConfigValue = 1015808
                        }
                        $srv.configuration.Alter(); 
                                                
                       
                    } catch{
                       [string]$errorMessage = $Error[0].Exception
                       if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureMaxMemory: $errorMessage"
                       }
                    }
                }
            }
            TestScript = { 

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
   
                if($sqlInstances -ne $null){

                    ############################################
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                    ############################################

                    $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                
                    $srvConn.connect();

                    $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                    $PhysicalRAM = (Get-WMIObject -class Win32_PhysicalMemory -ComputerName:$env:COMPUTERNAME |Measure-Object -Property capacity -Sum | % {[Math]::Round(($_.sum / 1GB),2)})
                           
                       if($PhysicalRAM -eq 7) 
                        {
                            $srvRAM = 4096
                        }
                        if($PhysicalRAM -eq 8) 
                        {
                            $srvRAM = 10240
                        }
                        if($PhysicalRAM -eq 14) 
                        {
                            $srvRAM = 4096
                        }
                        if($PhysicalRAM -eq 16) 
                        {
                            $srvRAM = 12288 
                        }
                        if($PhysicalRAM -eq 24) 
                        {
                            $srvRAM = 19456   
                        }
                        if($PhysicalRAM -eq 28) 
                        {
                            $srvRAM = 22528
                        }
                        if($PhysicalRAM -eq 32) 
                        {
                            $srvRAM = 25600
                        }
                        if($PhysicalRAM -eq 48) 
                        {
                            $srvRAM = 38912
                        }
                        if($PhysicalRAM -eq 56) 
                        {
                            $srvRAM = 45056
                        }
                        if($PhysicalRAM -eq 64) 
                        {
                            $srvRAM = 52224
                        }
                        if($PhysicalRAM -eq 72) 
                        {
                            $srvRAM = 38912
                        }
                        if($PhysicalRAM -eq 96) 
                        {
                            $srvRAM = 77824
                        }
                        if($PhysicalRAM -eq 112) 
                        {
                            $srvRAM = 91136
                        }
                        if($PhysicalRAM -eq 128) 
                        {
                            $srvRAM = 104448
                        }
                        if($PhysicalRAM -eq 140) 
                        {
                            $srvRAM = 114688
                        }
                        if($PhysicalRAM -eq 224) 
                        {
                            $srvRAM = 196608
                        }
                        if($PhysicalRAM -eq 256) 
                        {
                            $srvRAM = 229376
                        }
                        if($PhysicalRAM -eq 448) 
                        {
                            $srvRAM = 425984
                        }
                        if($PhysicalRAM -eq 512) 
                        {
                            $srvRAM = 491520
                        }
                        if($PhysicalRAM -eq 768) 
                        {
                            $srvRAM = 753664
                        }
                        if($PhysicalRAM -eq 1024) 
                        {
                            $srvRAM = 1015808
                        }
                       
                        if($srv.configuration.MaxServerMemory.ConfigValue -eq $srvRAM -or $PhysicalRAM -le 8 ) {
                            $pass=$true
                        }else {
                            $pass=$false
                        }
                }else {$pass=$false}

               if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureMaxMemory $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureMaxMemory $pass"
                }

             return $pass
            }
            DependsOn = "[Script]ConfigureDefaultLocations"
        }

        Script ConfigureSQLAgent{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
   
                if($sqlInstances -ne $null){
                   
                    try {   
                      
                        ############################################
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                        
                        $srvConn.connect();

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn 
                                              
                            $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "SQLServerAgent*" -and $_.PathName -match "SQLAGENT.exe" } 
                            if($sqlInstances.State -eq 'Stopped'){
                                net start SQLSERVERAGENT
                            }

                            $db = New-Object Microsoft.SqlServer.Management.Smo.Database
                            $db = $srv.Databases.Item("msdb")
                            # Select SQLAgent 
                            $SQLAgent = $db.parent.JobServer ;
                     
                            # Show settings
                            $CurrentSettings = $SQLAgent | select @{n="SQLInstance";e={$db.parent.Name}},MaximumHistoryRows, MaximumJobHistoryRows ;
                            #$CurrentSettings | ft -AutoSize ;
                            $TargetMaximumHistoryRows = 100000;
                            $TargetMaximumJobHistoryRows = 1000 ;

                            $SQLAgent.MaximumHistoryRows = $TargetMaximumHistoryRows ;
                            $SQLAgent.MaximumJobHistoryRows = $TargetMaximumJobHistoryRows ; 
                            $db.Parent.JobServer.SqlServerRestart=1
                            $db.Parent.JobServer.SqlAgentRestart=1
                            $SQLAgent.Alter();
                     
                            # ensuring we have the latest information
                            $SQLAgent.Refresh();
                            #$SQLAgent | select @{n="SQLInstance";e={$db.parent.Name}},MaximumHistoryRows, MaximumJobHistoryRows ;
                            $db.Parent.ConnectionContext.Disconnect();

                            CD HKLM:\
                            $Registry_Key ="HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SQLSERVERAGENT\"
                            Set-ItemProperty -Path $Registry_Key -Name Start  -Value 2 
                            CD C:\

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureSQLAgent: $errorMessage"
                        }
                    }
                }
            }
            TestScript = { 
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
   
                if($sqlInstances -ne $null){

                    ############################################
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                    ############################################

                    $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                               
                    $srvConn.connect();

                    $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                     $db = New-Object Microsoft.SqlServer.Management.Smo.Database
                     $db = $srv.Databases.Item("msdb")
                     $SQLAgent = $db.parent.JobServer ;

                     $pass=$true

                      if($SQLAgent.MaximumHistoryRows -ne $TargetMaximumHistoryRows){$pass=$false}
                      if($SQLAgent.MaximumJobHistoryRows -ne $TargetMaximumJobHistoryRows){$pass=$false}
                      if($db.Parent.JobServer.SqlServerRestart -ne 1) {$pass=$false} 
                      if($db.Parent.JobServer.SqlAgentRestart -ne 1) {$pass=$false}

                      $db.Parent.ConnectionContext.Disconnect();
                
                }else {$pass=$false}

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureSQLAgent $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureSQLAgent $pass"
                }

             return $pass
            }
            DependsOn = "[Script]ConfigureMaxMemory"
        }  
       
        Script MoveMasterFiles{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                   
                    try { 

                        ################################################################
	                    # Data.
                        ################################################################                     
                        $DataPath = $($using:dataPath)
                        $logPath = $($using:logPath)
                        $ErrorPath = $($using:ErrorPath)
                	    $flagsToAdd = "-T1118"

                        if($(Test-Path -Path $dataPath -ErrorAction SilentlyContinue) -eq $true) {
                        ################################################################
	                    # Alter DB...
                        ################################################################
        
                           $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                        if($sqlInstances -ne $null -and $sqlInstances.State -eq 'Running'){
	                        $q = "ALTER DATABASE [master] MODIFY FILE (NAME = master, FILENAME = '$($DataPath)\master.mdf')"
		                    Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue

                            $q = "ALTER DATABASE [master] MODIFY FILE (NAME = mastlog, FILENAME = '$($logPath)\mastlog.ldf')"
	                        Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue
                        }

                        ################################################################

                        ################################################################
                        #Change the startup parameters 
                        ################################################################
                        $hklmRootNode = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server" 
                            $props = Get-ItemProperty "$hklmRootNode\Instance Names\SQL" 
                            $instances = $props.psobject.properties | ?{$_.Value -like 'MSSQL*'} | select Value 

                            $instances | %{ $inst = $_.Value;}

                            $regKey = "$hklmRootNode\$inst\MSSQLServer\Parameters" 
                            $props = Get-ItemProperty $regKey 
                            $params = $props.psobject.properties | ?{$_.Name -like 'SQLArg*'} | select Name, Value 
                            $flagset=$false

                            $c=0
                            foreach ($param in $params) { 
                                if($param.Value -match '-d') {
                                    $param.value = "-d$datapath\master.mdf"
                                } elseif($param.Value -match '-l') {
                                    $param.value = "-l$logpath\mastlog.ldf"
                                } elseif($param.Value -match '-e') {
                                     $param.value = "-e$errorpath\ERRORLOG"
                                } elseif($param.Value -match '-T') {
                                     $flagset=$true
                                } 
                                Set-ItemProperty -Path $regKey -Name $param.Name -Value $param.value 

                                $c+=1
                             }
                             if(!$flagset) {
                                $newRegProp = "SQLArg"+($c) 
                                Set-ItemProperty -Path $regKey -Name $newRegProp -Value $flagsToAdd 
                             }
                               
                             $q = "EXEC msdb.dbo.sp_set_sqlagent_properties @errorlog_file=N'" +$ErrorPath + "\SQLAGENT.OUT'"
                             Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue
                             
                            ################################################################

                            ################################################################
                            # Stop SQL, move the files, start SQL 
                            ################################################################
                            #Stop
                            $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                            if($sqlInstances.State = 'Running') {
                            "$(Get-Date -Format g) Stopping SQL Server."
                                Stop-Service -displayname "SQL Server (MSSQLSERVER)" -Force
                            }
                            
                             $readylog = $(test-path -Path $("$($logPath)\mastlog.ldf"))
                             $readyData = $(test-path -Path $("$($DataPath)\master.mdf"))

                                  #Move
                              if(!$readyData) {
                                 Get-ChildItem -Path "C:\Program Files\Microsoft SQL Server\" -Recurse | Where-Object {$_.name -eq 'master.mdf'} | %{Move-Item -Path $_.FullName -Destination $datapath -force }
                              }
                              if(!$readyLog) {
                                 Get-ChildItem -Path "C:\Program Files\Microsoft SQL Server\" -Recurse | Where-Object {$_.name -eq 'mastlog.ldf'} | %{Move-Item -Path $_.FullName -Destination $logPath -force }
                              }
                               
                            #Start
                            $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                            if($sqlInstances.State = 'Stopped') {                            
                            "$(Get-Date -Format g) Starting SQL Server."
                                Start-Service -displayname "SQL Server (MSSQLSERVER)" 
                            }
                       }                                                     
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "MoveMasterFiles: $errorMessage"
                        } else {$errorMessage}
                    }
                }
               
                
            }
            TestScript = { 
            
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){

                    $DataPath = $($using:dataPath)
                    $logPath = $($using:logPath)
                    $ErrorPath = $($using:ErrorPath)

                    $readylog = $(test-path -Path $("$($logPath)\mastlog.ldf"))
                    $readyData = $(test-path -Path $("$($DataPath)\master.mdf"))
                    
                     $hklmRootNode = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server" 
                        $props = Get-ItemProperty "$hklmRootNode\Instance Names\SQL" 
                        $instances = $props.psobject.properties | ?{$_.Value -like 'MSSQL*'} | select Value 

                        $instances | %{ $inst = $_.Value;}

                        $regKey = "$hklmRootNode\$inst\MSSQLServer\Parameters" 
                        $props = Get-ItemProperty $regKey 
                        $params = $props.psobject.properties | ?{$_.Name -like 'SQLArg*'} | select Name, Value 

                        $c=0
                        foreach ($param in $params) { 
                            if($param.Value -eq "-d$datapath\master.mdf") {
                                $ReadyMastermdf = $true
                            } elseif($param.Value -eq "-l$logpath\mastlog.ldf") {
                                $ReadyMasterldf = $true 
                            } elseif($param.Value -eq "-e$errorpath\ERRORLOG") {
                                    $ReadyErrorLog = $true 
                            } 
                        }
                    if($readyLog -and $readyData -and $readyMastermdf -and $readymasterldf -and $readyErrorlog){return $true} else {return $false}
                
                }

                if($pass) {
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "MoveMasterFiles $pass"
                }else {
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "MoveMasterFiles $pass"
                }
             return $pass
            }
            DependsOn = "[Script]ConfigureSQLAgent"
        }

        Script MoveModelFiles{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                   
                    try { 
                     
                        $DataPath = $($using:dataPath)
                        $logPath = $($using:logPath)

                        if($(Test-Path -Path $dataPath -ErrorAction SilentlyContinue) -eq $true) {
                            ################################################################
	                        # Move tempdb.mdf...
                            ################################################################
	                        $q = "ALTER DATABASE [model] MODIFY FILE (NAME = modeldev, FILENAME = '$($DataPath)\model.mdf')"
				            Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue

                            $q = "ALTER DATABASE [model] MODIFY FILE (NAME = modellog, FILENAME = '$($logPath)\modellog.ldf')"
	                        Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue

                            #Stop
                            $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                            if($sqlInstances.State = 'Running') {
                            "$(Get-Date -Format g) Stopping SQL Server."
                                Stop-Service -displayname "SQL Server (MSSQLSERVER)" -Force
                            }
                               
                                $readylog = $(test-path -Path $("$($logPath)\modellog.ldf"))
                                $readyData = $(test-path -Path $("$($DataPath)\model.mdf"))

                                #Move
                                if(!$readyData) {
                                    Get-ChildItem -Path "C:\Program Files\Microsoft SQL Server\" -Recurse | Where-Object {$_.name -eq 'model.mdf'} | %{Move-Item -Path $_.FullName -Destination $datapath -force}
                                }
                                if(!$readylog) {
                                    Get-ChildItem -Path "C:\Program Files\Microsoft SQL Server\" -Recurse | Where-Object {$_.name -eq 'modellog.ldf'} | %{Move-Item -Path $_.FullName -Destination $logPath -force}
                                }
                                    
                            #Start
                            $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                            if($sqlInstances.State = 'Stopped') {                            
                            "$(Get-Date -Format g) Starting SQL Server."
                                Start-Service -displayname "SQL Server (MSSQLSERVER)" 
                            }
                          }
                                                                             
                        } catch{
                            [string]$errorMessage = $Error[0].Exception
                            if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                                Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "MoveModelFiles: $errorMessage"
                            } else {$errorMessage}
                        }
                }
                
            }
            TestScript = { 
            
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){

                    $DataPath = $($using:dataPath)
                    $logPath = $($using:logPath)

                    $readylog = $(test-path -Path $("$($logPath)\modellog.ldf"))
                    $readyData = $(test-path -Path $("$($DataPath)\model.mdf"))
                    
                    if($readyLog -and $readyData){return $true} else {return $false}
                }

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "MoveModelFiles $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "MoveModelFiles $pass"
                }

             return $pass
            }
            DependsOn = "[Script]MoveMasterFiles"
        }

        Script MoveMSDBFiles{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                   
                    try { 
                     
                        $DataPath = $($using:dataPath)
                        $logPath = $($using:logPath)

                        if($(Test-Path -Path $dataPath -ErrorAction SilentlyContinue) -eq $true) {
                            ################################################################
	                        # Move tempdb.mdf...
                            ################################################################
	                        $q = "ALTER DATABASE [MSDB] MODIFY FILE (NAME = MSDBData, FILENAME = '$($DataPath)\MSDBData.mdf')"
				            Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue

                            $q = "ALTER DATABASE [MSDB] MODIFY FILE (NAME = MSDBlog, FILENAME = '$($logPath)\MSDBlog.ldf')"
	                        Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue


                            #Stop
                            $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                            if($sqlInstances.State = 'Running') {
                            "$(Get-Date -Format g) Stopping SQL Server."
                                Stop-Service -displayname "SQL Server (MSSQLSERVER)" -Force
                            }
                                
                               $readylog = $(test-path -Path $("$($logPath)\MSDBlog.ldf"))
                               $readyData = $(test-path -Path $("$($DataPath)\MSDBData.mdf"))
                                                               
                                #Move
                                if(!$readyData) {
                                    Get-ChildItem -Path "C:\Program Files\Microsoft SQL Server\" -Recurse | Where-Object {$_.name -eq 'MSDBData.mdf'} | %{Move-Item -Path $_.FullName -Destination $datapath -force}
                                 }
                                if(!$readylog) {
                                    Get-ChildItem -Path "C:\Program Files\Microsoft SQL Server\" -Recurse | Where-Object {$_.name -eq 'MSDBlog.ldf'} | %{Move-Item -Path $_.FullName -Destination $logPath -force}
                                }
                                                           
                                    
                            #Start
                            $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                            if($sqlInstances.State = 'Stopped') {                            
                            "$(Get-Date -Format g) Starting SQL Server."
                                Start-Service -displayname "SQL Server (MSSQLSERVER)" 
                            }
                          }
                                             
                        } catch{
                            [string]$errorMessage = $Error[0].Exception
                            if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                                Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "MoveMSDBFiles: $errorMessage"
                            } else {$errorMessage}
                        }
                }
                
            }
            TestScript = { 
            
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){

                    $DataPath = $($using:dataPath)
                    $logPath = $($using:logPath)

                    $readylog = $(test-path -Path $("$($logPath)\MSDBlog.ldf"))
                    $readyData = $(test-path -Path $("$($DataPath)\MSDBData.mdf"))
                    
                    if($readyLog -and $readyData){return $true} else {return $false}
                }

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "MoveMSDBFiles $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "MoveMSDBFiles $pass"
                }

             return $pass
            }
            DependsOn = "[Script]MoveModelFiles"
        }
                
        Script ConfigureModelDataFile{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                   
                    try { 
                        ############################################ 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        $DatabaseName="Model"

                        $MyDatabase = $srv.Databases[$DatabaseName]
                        $MyDatabase.RecoveryModel = "Simple"                                            
                        $MyDatabase.Alter()

                        $DBFG = $MyDatabase.FileGroups;
                        foreach ($DBF in $DBFG.Files) {
                           if((50*1024) -ne $dbf.Size -or (5*1024) -ne $dbf.Growth) {
                               $DBF.MaxSize = -1
                               $dbf.Growth = (5*1024)
                               $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                               $dbf.Size = (50*1024)
                               $dbf.Alter()

                           } else {"$($DBF.Name) Size to 50MB, Filegrowth to 5MB"}
                                                      

                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureModelDataFile: $errorMessage"
                        }
                    }
                }
            }
            TestScript = { 
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                           
                if($sqlInstances -ne $null){

                    ############################################
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                    ############################################

                    $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                
                     $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                    $DatabaseName="Model"

                    $MyDatabase = $srv.Databases[$DatabaseName]
                                                                      
                    $DBFG = $MyDatabase.FileGroups;
                    $pass=$true
                    foreach ($DBF in $DBFG.Files) {
                        if((20*1024) -ne $dbf.Size) {
                            $pass= $false
                        } 
                        if((5*1024) -ne $dbf.Growth) {
                            $pass= $false
                        } 
                    }
                } else {$pass=$false}

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureModelDataFile $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureModelDataFile $pass"
                }

               return $pass
            }
            DependsOn = "[Script]MoveMSDBFiles"
        }

        Script ConfigureModelLogFile{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                   
                    try { 
                        
                        ############################################
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        $DatabaseName="Model"

                        $MyDatabase = $srv.Databases[$DatabaseName]
                                                                      
                        foreach ($DBF in $MyDatabase.LogFiles) {
                            

                                $DBF.MaxSize = -1
                                $dbf.Growth = (5*1024)
                                $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                                $dbf.Size = (20*1024)
                                $dbf.Alter()

                          
                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureModelLogFile: $errorMessage"
                        }
                    }
                }
            }
            TestScript = { 
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                           
                if($sqlInstances -ne $null){

                    ############################################
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                    ############################################

                    $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                
                     $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                    $DatabaseName="Model"

                    $MyDatabase = $srv.Databases[$DatabaseName]
                    $pass=$true

                    foreach ($DBF in $MyDatabase.LogFiles) {
                        if((50*1024) -ne $dbf.Size) {
                            $pass= $false
                        } 
                        if((5*1024) -ne $dbf.Growth) {
                            $pass= $false
                        } 
                    }
                } else {$pass=$false}

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureModelLogFile $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureModelLogFile $pass"
                }

               return $pass
            }
            DependsOn = "[Script]ConfigureModelDataFile"
        }
         
        Script ConfigureMSDBDataFile{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                   
                    try {
                     
                        ############################################     
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        $DatabaseName="MSDB"

                        $MyDatabase = $srv.Databases[$DatabaseName]
                                                                      
                        $DBFG = $MyDatabase.FileGroups;
                        foreach ($DBF in $DBFG.Files) {
                           if((50*1024) -ne $dbf.Size) {
                                $DBF.MaxSize = -1
                                 $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                                $dbf.Size = (50*1024)
                                $dbf.Growth = (5*1024)
                                $dbf.Alter()

                           } else {"$($DBF.Name) Size to 50MB,Filegrowth to 5MB, unlimited growth"}
                          
                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureMSDBDataFile: $errorMessage"
                        } else {$errorMessage}
                    }
                }
            }
            TestScript = { 
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){

                    ############################################
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                    ############################################

                    $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                
                     $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                    $DatabaseName="MSDB"

                    $MyDatabase = $srv.Databases[$DatabaseName]
                                                                      
                    $DBFG = $MyDatabase.FileGroups;
                    $pass=$true

                    foreach ($DBF in $DBFG.Files) {
                        if((50*1024) -ne $dbf.Size) {
                            $pass= $false
                        } 
                        if((5*1024) -ne $dbf.Growth) {
                            $pass= $false
                        } 
                    }
                    } else {$pass=$false}

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureMSDBDataFile $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureMSDBDataFile $pass"
                }

               return $pass
            }
            DependsOn = "[Script]ConfigureModelLogFile"
        }

        Script ConfigureMSDBLogFile{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                   
                    try {

                        ############################################      
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        $DatabaseName="MSDB"

                        $MyDatabase = $srv.Databases[$DatabaseName]
       
                        foreach ($DBF in $MyDatabase.LogFiles) {
                                                       
                                $DBF.MaxSize = -1
                                $dbf.Growth = (5*1024)
                                $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                                $dbf.Size = (20*1024)
                                $dbf.Alter()
                                                         
                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                       if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureMSDBLogFile: $errorMessage"
                        } else {$errorMessage}
                    }
                }
            }
            TestScript = { 
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){

                    ############################################
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                    ############################################

                    $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                
                    $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                    $DatabaseName="MSDB"

                    $MyDatabase = $srv.Databases[$DatabaseName]
                    $pass=$true

                    foreach ($DBF in $MyDatabase.LogFiles) {
                        if((20*1024) -ne $dbf.Size) {
                            $pass= $false
                        } 
                        if((5*1024) -ne $dbf.Growth) {
                            $pass= $false
                        } 
                        if(-1 -ne $dbf.maxsize) {
                            $pass= $false
                        } 
                    }

                 }else {$pass=$false}
                 
                 Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureMSDBLogFile $pass"

               return $pass
            }
            DependsOn = "[Script]ConfigureMSDBDataFile"
        }
        
        Script ConfigureAuditing{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                    try{
                        INVOKE-sqlcmd  -Database master -Query "Exec [master].[sys].[xp_instance_regwrite] N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'NumErrorLogs', REG_DWORD, 30"
                    }catch{
                       [string]$errorMessage = $Error[0].Exception
                       if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureAuditing: $errorMessage"
                        } else {$errorMessage}
                    }
                }
            }
            TestScript = { 

               $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
               $pass = $false

                if($sqlInstances -ne $null){
                    try{
                        $retval=INVOKE-sqlcmd  -Database master -Query "Exec [master].[sys].[xp_instance_regread] N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'NumErrorLogs'"
                        if($retval.Data -eq 30) {$pass=$true} else {$pass=$false}
                    }catch{
                    [string]$errorMessage = $Error[0].Exception
		            
                    }

                }
            
                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureAuditing $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureAuditing $pass"
                }

             return $pass 
            }
            DependsOn = "[Script]ConfigureMSDBLogFile"
        }

        Script ConfigureBuiltInAdmins{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                    try {                            
                        $q = "if Exists(select 1 from sys.syslogins where name='[BUILTIN\Administrators]') drop login [BUILTIN\Administrators]"
				        Invoke-Sqlcmd -Database master -Query $q
                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureBuiltInAdmins: $errorMessage"
                        } else {$errorMessage}
                    }
                }
            }
            TestScript = { 
                try{
                    $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                    if($sqlInstances -ne $null){

                        $pass=$false
                        $q = "select count(*) as Instances from sys.syslogins where name='[BUILTIN\Administrators]'"
				        Invoke-Sqlcmd -Database master -Query $q            
                        if(($q.Instances) -eq 0) {$pass=$true}else{$pass=$false} 
                     
                     }else{$pass=$false}
                  
                }catch{$pass=$false}
            
                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureBuiltInAdmins $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureBuiltInAdmins $pass"
                }

             return $pass
            }
            DependsOn = "[Script]ConfigureAuditing"
        }
        
        Script MoveTempdbFiles{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                   
                    try { 
                     
                        $TempDrive=$($using:TempDbPath).split("\")[0] 
                        $TempPath = $($using:TempDbPath)

                        $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                        $TempDBSpaceAvailGB = $FreeSpaceGB - 50
	                    $TempDBSpaceAvailMB = $TempDBSpaceAvailGB * 1024

                        $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                        $fileCount = ($cpu.NumberOfCores | Measure-Object -Sum).Sum
                        if($fileCount -gt 8)
                        {
                            $fileCount = 8
                        } 

                        $maxFileGrowthSizeMB = $TempDBSpaceAvailMB / $fileCount 
                        $maxFileGrowthSizeMB = [math]::truncate($maxFileGrowthSizeMB)
	                    $fileSize     = '1000'
                        $fileGrowthMB = '50' 

                            ################################################################
	                        # Move tempdb.mdf...
                            ################################################################
	                        $q = "ALTER DATABASE [tempdb] MODIFY FILE (NAME = tempdev, FILENAME = '$($TempPath)\tempdb.mdf')"
				            Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue

                            $q = "ALTER DATABASE [tempdb] MODIFY FILE (NAME = templog, FILENAME = '$($TempPath)\templog.ldf')"
	                        Invoke-Sqlcmd -Database master -Query $q  -QueryTimeout 10000 -ErrorAction SilentlyContinue

                            "$(Get-Date -Format g) Restarting SQL Server."
                                    $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "SQLServerAgent*" -and $_.PathName -match "SQLAGENT.exe" } 
                                    if($sqlInstances.State -eq 'Running'){
                                    net stop sqlserveragent
                                    }
                                    $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                                    if($sqlInstances.state -eq 'Running'){
                                    net stop mssqlserver
                                    }
                                    start-sleep 30
                                    $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "SQLServerAgent*" -and $_.PathName -match "SQLAGENT.exe" } 
                                    if($sqlInstances.State -eq 'Stopped'){
                                    net start sqlserveragent
                                    }
                                    $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                                    if($sqlInstances.state -eq 'Stopped'){
                                    net start mssqlserver
                                    }
                                Start-Sleep 30
                                               
                            } catch{
                                [string]$errorMessage = $Error[0].Exception
                                if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "MoveTempdbFiles: $errorMessage"
                                } else {$errorMessage}
                            }
                    }
                
            }
            TestScript = { 
            
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                    
                    $TempDrive=$($using:TempDbPath).split("\")[0] 
                    $TempPath = $($using:TempDbPath)
                    
                    $readylog = $(test-path -Path $("$($TempPath)\templog.ldf"))
                    $readyData = $(test-path -Path $("$($TempPath)\tempdb.mdf"))
                    
                    if($readyLog -and $readyData){return $true} else {return $false}
                }

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "MoveTempdbFiles $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "MoveTempdbFiles $pass"
                }

             return $pass
            }
            DependsOn = "[Script]ConfigureBuiltInAdmins"
        }

        Script AddTempdbFiles{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                $ret = $false

                if($sqlInstances -ne $null){
                   
                    try { 
                     
                        $TempDrive=$($using:TempDbPath).split("\")[0] 
                        $TempPath = $($using:TempDbPath)

                        $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                        $TempDBSpaceAvailGB = $FreeSpaceGB - 50
	                    $TempDBSpaceAvailMB = $TempDBSpaceAvailGB * 1024

                        $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                        $fileCount = ($cpu.NumberOfCores | Measure-Object -Sum).Sum
            
                        #maximum of 8 to start, the additional ones to be added by the server Owners
                        if($fileCount -gt 8){ $fileCount = 8 }

                        $maxFileGrowthSizeMB = $TempDBSpaceAvailMB / $fileCount 
                        $maxFileGrowthSizeMB = [math]::truncate($maxFileGrowthSizeMB)
	                    $fileSize     = '1000'
                        $fileGrowthMB = '50' 

                            ################################################################
	                        # Move tempdb.mdf...
                            ################################################################                       
	                        "$(Get-Date -Format g) Creating remaining data files..."

                            for ($i = 2; $i -le $fileCount; $i++) {

                                $msg="Create tempdev$($i)"
                                           
                                try{
                                    
                                        $q = "IF NOT EXISTS(SELECT 1 FROM tempdb.dbo.sysfiles WHERE name = 'tempdev$($i)') Begin ALTER DATABASE [tempdb] ADD FILE ( NAME = tempdev$($i), SIZE = $($fileSize)MB, MAXSIZE = 'unlimited', FILEGROWTH = $($fileGrowthMB)MB, FILENAME = '$($TempPath)\tempdb$($i).mdf') END "; 
		                                Invoke-Sqlcmd -Database master -Query $q -QueryTimeout 10000 -ErrorAction SilentlyContinue
                                    
                                    }catch{
                                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message $errorMessage
                                        }else {$errorMessage}
                                    }
                                                                                               
                            Restart-Service -displayname "SQL Server (MSSQLSERVER)" -Force

		                        	                        
                        }

                          

                                               
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "AddTempdbFiles: $errorMessage"
                        } else {$errorMessage}
                   }
                }
            }
            TestScript = { 
            
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                    
                    $TempDrive=$($using:TempDbPath).split("\")[0] 
                    $TempPath = $($using:TempDbPath)
                    
                    $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                    $fileCount = ($cpu.NumberOfCores | Measure-Object -Sum).Sum
                        if($fileCount -gt 8)
                        {
                            $fileCount = 8
                        }

                    $pass=$true
                    for ($i = 2; $i -le $fileCount; $i++) {

                        $readylog = $(test-path -Path $("$($TempPath)\tempdb$($i).mdf"))
                        if(!$readylog) {$pass=$false}            

                    }
                }

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "AddTempdbFiles $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "AddTempdbFiles $pass"
                }

             return $pass
            }
            DependsOn = "[Script]MoveTempdbFiles"
        }

        Script ConfigureTempDataFile{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                   
                    try {
                     
                        ############################################     
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        $DatabaseName="tempdb"
                        $tempDrive = $(split-path $($using:tempdbpath) -Qualifier)  
                        $TempPath = $($using:TempDbPath)

                        $MyDatabase = $srv.Databases[$DatabaseName]
                        $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                        $TempDBSpaceAvailGB = $FreeSpaceGB - 50
	                    $TempDBSpaceAvailMB = $TempDBSpaceAvailGB * 1024
                       
                        $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                        $fileCount =($cpu.NumberOfCores | Measure-Object -Sum).Sum

                        if($fileCount -gt 8){ $fileCount = 8 }
                       
                        $fileSize     = $(1024*1000)
                        $fileGrowthMB = $(1024*50)
                        if($FreeSpaceGB -ge  10 -and $FreeSpaceGB -lt 50 ){
                            $fileSize     = $(1024*500)
                            $fileGrowthMB = $(1024*50)
                        }elseif($FreeSpaceGB -ge  50  ){
                            $fileSize     = $(1024*1000)
                            $fileGrowthMB = $(1024*100)
                        }

                        $maxFileGrowthSizeMB = $TempDBSpaceAvailMB / $fileCount 
                        $maxFileGrowthSizeMB = [math]::truncate($maxFileGrowthSizeMB)
                                                                           
                        $DBFG = $MyDatabase.FileGroups;
                        foreach ($DBF in $DBFG.Files) {
                          
                               $DBF.MaxSize = -1
                               $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                               $dbf.Size = $($fileSize)
                               $dbf.Growth = "$fileGrowthMB"
                               $dbf.Alter()                        
                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureTempDataFile: $errorMessage"
                        }else {$errorMessage}
                    }
                }
            }
            TestScript = { 
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){

                    ############################################
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                    ############################################

                    $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                
                    $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                    $DatabaseName="tempdb"
                   
                    $tempDrive = $(split-path $($using:tempdbpath) -Qualifier)  
                    $TempPath = $($using:TempDbPath)

                    $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                    $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                    $fileCount = ($cpu.NumberOfCores | Measure-Object -Sum).Sum
                     if($fileCount -gt 8)
                        {
                            $fileCount = 8
                        }

                    $maxFileGrowthSizeMB = $TempDBSpaceAvailMB / $fileCount 
                    $maxFileGrowthSizeMB = [math]::truncate($maxFileGrowthSizeMB)

                    if($fileCount -gt 8){ $fileCount = 8 }
                       
                    if($FreeSpaceGB -ge  10 -and $FreeSpaceGB -lt 50 ){
                        $fileSize     = $(1024*500)
                        $fileGrowthMB = $(1024*50)
                    }elseif($FreeSpaceGB -ge  50  ){
                        $fileSize     = $(1024*1000)
                        $fileGrowthMB = $(1024*100)
                    }

                    $MyDatabase = $srv.Databases[$DatabaseName]
                                                                      
                    $DBFG = $MyDatabase.FileGroups;
                    $pass=$true

                    foreach ($DBF in $DBFG.Files) {
                        if(($fileSize) -ne $dbf.Size) {
                            $pass= $false
                        } 
                        if(($fileGrowthMB) -ne $dbf.Growth) {
                            $pass= $false
                        } 
                         if(($maxFileGrowthSizeMB) -ne $dbf.Maxsize) {
                            $pass= $false
                        } 
                    }
                    } else {$pass=$false}

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureTempDataFile $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureTempDataFile $pass"
                }

               return $pass
            }
            DependsOn = "[Script]AddTempdbFiles"
        }

        Script ConfigureTempLogFile{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                   
                    try {

                        ############################################      
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        $DatabaseName="tempdb"
                        $tempDrive = $(split-path $($using:tempdbpath) -Qualifier)  
                        $TempPath = $($using:TempDbPath)
                    
                        
                        $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                        $TempDBSpaceAvailGB = $FreeSpaceGB - 50
	                    $TempDBSpaceAvailMB = $TempDBSpaceAvailGB * 1024
                        $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                        $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                        $fileCount = ($cpu.NumberOfCores | Measure-Object -Sum).Sum
                        if($fileCount -gt 8)
                        {
                            $fileCount = 8
                        } 

                        $DatafileSize     = $(1024*1000)
                        $fileGrowthMB = $(1024*50)
                        if($FreeSpaceGB -ge  10 -and $FreeSpaceGB -lt 50 ){
                            $DatafileSize = $(1024*500)
                            $fileGrowthMB = $(1024*50)
                        }elseif($FreeSpaceGB -ge  50  ){
                            $DatafileSize = $(1024*1000)
                            $fileGrowthMB = $(1024*100)
                        }

                        if($fileCount -gt 8){ $fileCount = 8 }
                        $LogfileSize     = $(.25 * $($fileCount * $DatafileSize))

                        $maxFileGrowthSizeMB = $TempDBSpaceAvailMB / $fileCount 
                        $maxFileGrowthSizeMB = [math]::truncate($maxFileGrowthSizeMB)

                        $MyDatabase = $srv.Databases[$DatabaseName]
          
                        foreach ($DBF in $MyDatabase.LogFiles) {
                          
                               $DBF.MaxSize = -1
                               $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                               $dbf.Size = ($LogfileSize)
                               $dbf.Growth = $fileGrowthMB
                               $dbf.Alter()

                               "$($DBF.Name) Size is $($dbf.Size) MB,Growth is $($dbf.Growth) MB, MaxSize is $($dbf.MaxSize) MB"

                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureTempLogFile: $errorMessage"
                        } else {$errorMessage}
                    }
                }
            }
            TestScript = { 
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){

                    ############################################
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                    ############################################

                    $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                    
                    $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                    $DatabaseName="tempdb"
                    $TempDrive = $(split-path $($using:tempdbpath) -Qualifier)    

                        $fileSize     = $(1024*1000)
                        $fileGrowthMB = $(1024*50)
                        $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                        $TempDBSpaceAvailGB = $FreeSpaceGB - 50
	                    $TempDBSpaceAvailMB = $TempDBSpaceAvailGB * 1024
                        $FreeSpaceGB = (Get-WmiObject -Class win32_volume -Filter "DriveLetter = '$TempDrive'").FreeSpace / 1024 / 1024 / 1024
                        $cpu =  Get-WmiObject -class win32_processor -Property 'numberofcores'
                        $fileCount = ($cpu.NumberOfCores | Measure-Object -Sum).Sum
                        if($fileCount -gt 8)
                        {
                            $fileCount = 8
                        } 

                        if($fileCount -gt 8){ $fileCount = 8 }
                       
                        if($FreeSpaceGB -ge  10 -and $FreeSpaceGB -lt 50 ){
                            $fileSize     = $(1024*500)
                            $fileGrowthMB = $(1024*50)
                        }elseif($FreeSpaceGB -ge  50  ){
                            $fileSize     = $(1024*1000)
                            $fileGrowthMB = $(1024*100)
                        }

                        $maxFileGrowthSizeMB = $TempDBSpaceAvailMB / $fileCount 
                        $maxFileGrowthSizeMB = [math]::truncate($maxFileGrowthSizeMB)

                    $MyDatabase = $srv.Databases[$DatabaseName]
                                                                      
                    $DBFG = $MyDatabase.Logs;
                    $pass=$true

                    foreach ($DBF in $MyDatabase.LogFiles) {
                        if(($fileSize) -ne $dbf.Size) {
                            $pass= $false
                        } 
                        if(($fileGrowthMB) -ne $dbf.Growth) {
                            $pass= $false
                        } 
                         if((-1) -ne $dbf.Maxsize) {
                            $pass= $false
                        }  
                    }

                 }else {$pass=$false}
                 
                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureTempLogFile $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureTempLogFile $pass"
                }

               return $pass
            }
            DependsOn = "[Script]ConfigureTempDataFile"
        }
          
        Script ConfigureMasterDataFile{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                   
                    try {  
                        ############################################
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        $DatabaseName="Master"

                        $MyDatabase = $srv.Databases[$DatabaseName]
                                                                      
                        $DBFG = $MyDatabase.FileGroups;
                        foreach ($DBF in $DBFG.Files) {
                           if((50*1024) -ne $dbf.Size) {

                               $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                               $dbf.Size = (50*1024)
                               $dbf.Alter()

                           } else {"$($DBF.Name) Size to 50MB"}
                           
                           if((5*1024) -ne $dbf.Growth) {

                               $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                               $dbf.Growth = (5*1024)
                               $dbf.Alter()

                           } else {"$($DBF.Name) Filegrowth to 5MB"}

                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureMasterDataFile: $errorMessage"
                        }
                    }
                }
            }
            TestScript = { 
            
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 

                if($sqlInstances -ne $null){
                     
                    ############################################
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                     ############################################

                    $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                
                     $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                    $DatabaseName="Master"

                    $MyDatabase = $srv.Databases[$DatabaseName]
                                                                      
                    $DBFG = $MyDatabase.FileGroups;
                    $pass=$true
                    foreach ($DBF in $DBFG.Files) {
                        if((50*1024) -ne $dbf.Size) {
                            $pass= $false
                        } 
                        if((5*1024) -ne $dbf.Growth) {
                            $pass= $false
                        } 
                    }

                }else {$pass=$false}

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureMasterDataFile $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureMasterDataFile $pass"
                }

               return $pass
            }
            DependsOn = "[Script]ConfigureSQLAgent"
        }

        Script ConfigureMasterLogFile{
            GetScript = {
                @{
                }
            }
            SetScript = {

                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                
                if($sqlInstances -ne $null){
                   
                    try {    
                      
                        ############################################
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                        $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                        ############################################

                        $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername

                        $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                        $DatabaseName="Master"

                        $MyDatabase = $srv.Databases[$DatabaseName]
                      
                        foreach ($DBF in $MyDatabase.LogFiles) {
                           if((50*1024) -ne $dbf.Size) {
                                $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                               $dbf.Size = (20*1024)
                               $dbf.Alter()

                           } else {"$($DBF.Name) Size to 50MB"}
                           
                           if((5*1024) -ne $dbf.Growth) {
                               $DBF.GrowthType = [Microsoft.SqlServer.Management.Smo.FileGrowthType]::KB
                               $dbf.Growth = (5*1024)
                               $dbf.Alter()

                           } else {"$($DBF.Name) Filegrowth to 5MB"}

                        }

                       
                    } catch{
                        [string]$errorMessage = $Error[0].Exception
                        if([string]::IsNullOrEmpty($errorMessage) -ne $true) {
                            Write-EventLog -LogName Application -source AzureArmTemplates -eventID 3001 -entrytype Error -message "ConfigureMasterLogFile: $errorMessage"
                        }
                    }
                }
            }
            TestScript = { 
                $sqlInstances = gwmi win32_service -computerName localhost -ErrorAction SilentlyContinue | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } 
                           
                if($sqlInstances -ne $null){
                     
                    ############################################
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") 
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO")
                    $null=[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended")
                    ############################################

                    $srvConn = New-Object Microsoft.SqlServer.Management.Common.ServerConnection $env:computername
                
                     $srv = New-Object Microsoft.SqlServer.Management.Smo.Server $srvConn

                    $DatabaseName="Master"

                    $MyDatabase = $srv.Databases[$DatabaseName]
                    $pass=$true

                    foreach ($DBF in $MyDatabase.LogFiles) {
                        if((20*1024) -ne $dbf.Size) {
                            $pass= $false
                        } 
                        if((5*1024) -ne $dbf.Growth) {
                            $pass= $false
                        } 
                    }
                } else {$pass=$false}

                if($Pass){
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1000 -entrytype Information -message "ConfigureMasterLogFile $pass"
                }else{
                    Write-EventLog -LogName Application -source AzureArmTemplates -eventID 1001 -entrytype Warning -message "ConfigureMasterLogFile $pass"
                }

               return $pass
            }
            DependsOn = "[Script]ConfigureMasterDataFile"
        }

        Script ConfigureStartupJob {
            GetScript = {
                @{
                }
            }
            SetScript = {
                if($(test-path -path C:\SQLStartup) -eq $true) {
               
                    $WebClient = New-Object System.Net.WebClient
                    $WebClient.DownloadFile($($Using:baseURL) + "scripts/SQL-Startup.ps1","C:\SQLStartup\SQL-Startup.ps1")

                    if($(test-path -path C:\SQLStartup\SQL-Startup.ps1) -eq $true) {
                        C:\SQLStartup\SQL-Startup.ps1 $($using:TempDBPath)
                    }
                }
            }
            TestScript = { 
                $pass=$false
                if($(test-path -path "C:\SQLStartup\SQL-Startup.ps1") -eq $true) {

                    if ((Get-ScheduledTask -TaskPath '\' | Where-Object { $_.TaskName -eq 'SqlTempdriveAndStartup'; }) -eq $null) {
                        $pass=$false
                    }else {
                        $pass=$true
                    }

                } else {
                    $pass=$false
                }

                return $Pass
            }
            DependsOn = "[Script]ConfigureMasterLogFile"
        }

}

}
# SIG # Begin signature block
# MIIkRQYJKoZIhvcNAQcCoIIkNjCCJDICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCiTxf4JiouqpZ8
# yhsk4abDvMEm6oJ4gOjWWDjEXHNkZqCCDZIwggYQMIID+KADAgECAhMzAAAAZEeE
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
# SIb3DQEJBDEiBCDNzIy2kAKKlmXt8jZDRiZC7ugyEweQ7BDT0VAPy1fY2jCBigYK
# KwYBBAGCNwIBDDF8MHqgGIAWAEEAUgBNACAAcwBjAHIAaQBwAHQAc6FegFxodHRw
# czovL2dpdGh1Yi5jb20vTWljcm9zb2Z0L01TSVRBUk0vdHJlZS9kZXZlbG9wLzMw
# MS1tdWx0aS12bS1kb21haW4tam9pbi1idWlsZC1kc2Mvc2NyaXB0czANBgkqhkiG
# 9w0BAQEFAASCAQAVhDLExSP+Vy0U+sY9AuQ5IPs3qVXWkViA+m1mrIzSfUfScZAf
# qGN27u7M1g+KpMzx3R2gC+yE0zkFW6hDq/NFGv7I2AwXk+mmcbBgEGCuF1MU+rX7
# EAf88JrcaQcDdtd/ssdrVLcjHrCKkLwqnP/Ef8Do1b8B6V6CHlvh59FD0k+Cg0L3
# P6yVITNyRt9pj3AoKtYYAxNGiIjYkxoWmjy4lrpx+htkZgyydkpwyxeT4K6GV9HU
# FHZc06AQjb1DujaQBqhJiBmn0gZMd+qj+s6ukpzVdTOHdBL6YpC+5ul+lGy/GUX7
# IkbNijDZKBtUwENCXHpJIqh3g+CITVFrPlIMoYITSjCCE0YGCisGAQQBgjcDAwEx
# ghM2MIITMgYJKoZIhvcNAQcCoIITIzCCEx8CAQMxDzANBglghkgBZQMEAgEFADCC
# AT0GCyqGSIb3DQEJEAEEoIIBLASCASgwggEkAgEBBgorBgEEAYRZCgMBMDEwDQYJ
# YIZIAWUDBAIBBQAEIHm8ougJ7eKvD8Ir96DiPf79G55w8PULx/3IIcAHYzJoAgZX
# vIMR4UkYEzIwMTYwODMwMDI1MDQ0LjMwNFowBwIBAYACAfSggbmkgbYwgbMxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIx
# JzAlBgNVBAsTHm5DaXBoZXIgRFNFIEVTTjpDMEY0LTMwODYtREVGODElMCMGA1UE
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
# 01+P3nSISRIwggTaMIIDwqADAgECAhMzAAAAlr/ytCHAd3UkAAAAAACWMA0GCSqG
# SIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTE2MDQy
# NzE3MDYxN1oXDTE3MDcyNzE3MDYxN1owgbMxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIxJzAlBgNVBAsTHm5DaXBoZXIg
# RFNFIEVTTjpDMEY0LTMwODYtREVGODElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ0y
# MLS8iyZFouvssJCJhu4iIx0gusRfKVF7DWXu7wgOO9477m+PTOzSXnV9566lvsLf
# vgQm7t7B383R71dVwEqcWpugW0aIj7URDPHiH/g9/aNYIDgDywTeKCkyQh2G5J/u
# fM7RQXhwraJHfzjvk2l8jBljcoiz4YlQPJ0JTvBjUfKSCcflDhtL07mVB4MUpa+9
# NuwH8C52KrTc+T0iwyMwxLoXgfZasopTXlRWj5Nbz9/rGN8cPcpEiH9FAdQBVGDU
# 3xkWdis/lcxTtrJV/Da+GVLrRC/Nly5yk7lik30WcA6Ndgei3YNaKKcPXRiQJdgj
# YMh7ALehdDfzty0tf/0CAwEAAaOCARswggEXMB0GA1UdDgQWBBSdGDcZIbm19sxj
# 3raOFolLMOX9XjAfBgNVHSMEGDAWgBTVYzpcijGQ80N7fEYbxTNoWoVtVTBWBgNV
# HR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9w
# cm9kdWN0cy9NaWNUaW1TdGFQQ0FfMjAxMC0wNy0wMS5jcmwwWgYIKwYBBQUHAQEE
# TjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2Nl
# cnRzL01pY1RpbVN0YVBDQV8yMDEwLTA3LTAxLmNydDAMBgNVHRMBAf8EAjAAMBMG
# A1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IBAQBQdKGemJkwFnJb
# j2WSZpoRoAj01e9ubPNIlqXP3oFUkuCQS/Hsf5ZCZkYJJlcNqOjgu4UJTzCgRNs4
# OxsUlfdwha2jLNcovgVtl9R0BntG6JXN9RMftNii2Y4lN/5+TwKLplQBN+2HCyqw
# uyeLBjekQKVEQZ57EK+SP4BUDzBb5DqwtC3E/haFY0tSAFgNubv56tiOIt7FSxiT
# ZCBaes15EKC5qB7CydMLENBFHMMcQPFB+iECYTyzbWLodGRhSSd7/bGuTSvWYr02
# PC18lPwl4wpC74QteYfIWAbvfqxgm4ODFosCsAcudB7xsCp6MnBM7VwmvAiGODAk
# q1s84WGuoYIDdjCCAl4CAQEwgeOhgbmkgbYwgbMxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIxJzAlBgNVBAsTHm5DaXBo
# ZXIgRFNFIEVTTjpDMEY0LTMwODYtREVGODElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZaIlCgEBMAkGBSsOAwIaBQADFQDkasCTMEE2e4WWCwtc
# Zcgdi8C9nqCBwjCBv6SBvDCBuTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBOVFMgRVNO
# OjU3RjYtQzFFMC01NTRDMSswKQYDVQQDEyJNaWNyb3NvZnQgVGltZSBTb3VyY2Ug
# TWFzdGVyIENsb2NrMA0GCSqGSIb3DQEBBQUAAgUA229FOTAiGA8yMDE2MDgyOTIz
# MzUyMVoYDzIwMTYwODMwMjMzNTIxWjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDb
# b0U5AgEAMAcCAQACAgpJMAcCAQACAhe+MAoCBQDbcJa5AgEAMDYGCisGAQQBhFkK
# BAIxKDAmMAwGCisGAQQBhFkKAwGgCjAIAgEAAgMW42ChCjAIAgEAAgMHoSAwDQYJ
# KoZIhvcNAQEFBQADggEBAF0UWzLKc/zabtd9Uo2oCvug++P6zN5Gyoaq/bPXIYf7
# H/+9Oiogt5cvDvZO1Nc+YZEn9e9TaDctVP4XazXkLUEinwCNx+7btLfrDhdvGw/0
# GWMd96HX5Zq3J3pP6SZdEM8HAODlJF+PShMxjx3d0K+74FZi2rx5aea1CAkfkKhK
# v3w7fV/u+rp/5YsJLHXt6GRAlk+MSACGSD5bvDyNLf1Ysc2K71TnKc8Fvtata61Y
# aLEDOJmhdHxfrorIdGbags70aShPsyoTE2AHC3CsAay5qQmkbgX1XW15peLMywe1
# Uy1V67uDBpmLBBFhMKPA4rg3oepSJ02JF+zdzRkjqfcxggL1MIIC8QIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAJa/8rQhwHd1JAAAAAAA
# ljANBglghkgBZQMEAgEFAKCCATIwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCC9JGQ+3jXIsi9koG/MH1Z8Z0ebPNGDCq2MRy2CakCc
# 0jCB4gYLKoZIhvcNAQkQAgwxgdIwgc8wgcwwgbEEFORqwJMwQTZ7hZYLC1xlyB2L
# wL2eMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAACW
# v/K0IcB3dSQAAAAAAJYwFgQU5KCcVmW+1ST/ElYeo79Gge+2IkUwDQYJKoZIhvcN
# AQELBQAEggEAG6D5AyhsEwA6r8FZFniW54PvybTbA7skcYv/t6EeL45DS51qkRv1
# svQ4bFkxoejZO28T+DpxpMbyeS5c90/TZwRLnW1NxgTr0i0Jfle7gZGDcj4ZqB2g
# 9r82d5fnNkLSuTK61OlrIUbk44Jch2KaiiCRZzKFTf7nv4ty9//9GrlXchBsDWPq
# 30zkNcBb2YD57bziDJQBQhVGNVq1cPUeMG39g/Jf4gWAMrHAqNtYSIoiu9H84OPS
# t9kokg7u6mTX44LbrHbqGvVGh6eI0YA4cIFWG7u8SJYW1bpZoOXHk44Y3uICYCZg
# 8szcVSKl7zXIcQBroS0+g4CMRfoM6T6lPA==
# SIG # End signature block
