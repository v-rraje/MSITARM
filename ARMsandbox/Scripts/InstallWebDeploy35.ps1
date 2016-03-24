
$Global:InstallWebDeploy35 = {

    $process = Start-Process -FilePath "C:\Program Files\Microsoft\Web Platform Installer\WebpiCmd-x64.exe" -ArgumentList "/install /Products:WDeploy /AcceptEULA" -Wait -PassThru

        if ($process.ExitCode -eq 0){
           Write-output -f green "$WebPlatformInstaller_amd64_en-US.msi has been successfully installed"
        }
        else {
           Write-output -f red "installer exit code  $($process.ExitCode) for file  $($msifile)"
        }
     

}