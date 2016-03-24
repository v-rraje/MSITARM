
    $Global:WebPlatformInstaller = {

    $arguments = "/quiet /norestart"

   
     $url = "http://download.microsoft.com/download/C/F/F/CFF3A0B8-99D4-41A2-AE1A-496C08BEB904/WebPlatformInstaller_amd64_en-US.msi"
     $file = "$env:TEMP\WebPlatformInstaller_amd64_en-US.msi"
 
     Invoke-WebRequest $url -OutFile $file
   
        start-sleep -Seconds 60

     Write-output "Installing $File....."
        $process = Start-Process -FilePath $file -ArgumentList $arguments -Wait -PassThru
        if ($process.ExitCode -eq 0){
           Write-output -f green "$WebPlatformInstaller_amd64_en-US.msi has been successfully installed"
        }
        else {
           Write-output -f red "installer exit code  $($process.ExitCode) for file  $($msifile)"
        }


    
}



