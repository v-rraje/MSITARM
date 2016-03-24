
$Global:VMConfiguration={


    #Get-NetConnectionProfile -InterfaceAlias Ethernet | Set-NetConnectionProfile -NetworkCategory Private

    netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=yes
    netsh advfirewall firewall set rule group="Remote Desktop" new enable=yes
    netsh advfirewall firewall set rule group="Remote Event Log Management" new enable=yes
    netsh advfirewall firewall set rule group="Windows Management Instrumentation (WMI)" new enable=yes
    netsh advfirewall firewall set rule group="Remote Volume Management" new enable=yes
    netsh advfirewall firewall set rule group="Remote Scheduled Tasks Management" new enable=yes
    netsh advfirewall firewall set rule group="Remote Service Management" new enable=yes
    netsh advfirewall firewall set rule group="Windows Firewall Remote Management" new enable=yes
    netsh advfirewall firewall set rule group="Windows Remote Management" new enable=yes

    ## added this to clear NLA required for RDP if issue hits
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
  
  ## so these get added if not present after any reboot
    schtasks /Create /RU "NT AUTHORITY\SYSTEM" /F /SC "OnStart" /delay "0001:00" /TN "ITCU-BuildAdminGroup" /TR "cmd.exe /c net localgroup administrators /add redmond\cu_vmbuilder_build"
    schtasks /Create /RU "NT AUTHORITY\SYSTEM" /F /SC "OnStart" /delay "0001:00" /TN "ITCU-BuildITGAdmin" /TR "cmd.exe /c net localgroup administrators /add redmond\ITG-Admin"
    schtasks /Create /RU "NT AUTHORITY\SYSTEM" /F /SC "OnStart" /delay "0001:00" /TN "ITCU-BuildITGGDCTools" /TR "cmd.exe /c net localgroup administrators /add redmond\ITG-GDCTools"
    schtasks /Create /RU "NT AUTHORITY\SYSTEM" /F /SC "OnStart" /delay "0001:00" /TN "ITCU-RegisterDNS" /TR "cmd.exe /c IPConfig.exe /registerdns"
    
IPConfig.exe /registerdns

}