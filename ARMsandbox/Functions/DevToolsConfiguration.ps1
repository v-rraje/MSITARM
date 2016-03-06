$configurationData = @{
    AllNodes = @( 
        @{
            NodeName = 'localhost'
            WebPiSourcePath = Join-Path $PSScriptRoot WebPi
            WebPiCmdPath = "$env:ProgramFiles\Microsoft\Web Platform Installer\WebPiCmd-x64.exe"
        }
    );
}

Configuration DevToolsConfiguration
{
    Node $AllNodes.NodeName
    {    
        Package WebPi_Installation
        {
            Ensure = "Present"
            Name = "Microsoft Web Platform Installer 5.0"
            Path = Join-Path $($Node.WebPiSourcePath) wpilauncher.exe
            ProductId = '4D84C195-86F0-4B34-8FDE-4A17EB41306A'
            Arguments = ''
        }

        Package WebDeploy_Installation
        {
            Ensure = "Present"
            Name = "Microsoft Web Deploy 3.5"
            Path = $Node.WebPiCmdPath
            ProductId = ''
            Arguments = "/install /products:WDeploy /AcceptEula"
            DependsOn = @("[Package]WebPi_Installation")
        }

        Package AzureSDK_2_3_Installation
        {
            Ensure = "Present"
            Name = "Windows Azure Libraries for .NET – v2.3"
            Path = $Node.WebPiCmdPath
            ProductId = ''
            Arguments = "/install /products:WindowsAzureSDK_2_3 /AcceptEula"
            DependsOn = @("[Package]WebDeploy_Installation")
        }
    }
}
