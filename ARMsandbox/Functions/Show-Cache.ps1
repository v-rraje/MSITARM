  Function Show-Cache(){

        $variable = Get-Variable -Name localCreds -Scope Global -ErrorAction SilentlyContinue
        if(!$variable) {$global:localCreds=$null}
        Write-host -f blue "     localcreds=$($localCreds.UserName)"

        $variable = Get-Variable -Name DomainCreds -Scope Global -ErrorAction SilentlyContinue
        if(!$variable) {$global:DomainCreds=$null}
		Write-host -f blue "     DomainCreds=$($DomainCreds.UserName)"

        $variable = Get-Variable -Name vmNamePart -Scope Global -ErrorAction SilentlyContinue      
        if(!$variable) {$global:vmNamePart=$null}
        Write-host -f blue "     vmNamePart=$($vmNamePart)"

        $variable = Get-Variable -Name Diagnosticsstorage -Scope Global -ErrorAction SilentlyContinue
       if(!$variable) {$global:DiagnosticsStorage=$null}
       Write-host -f blue "     StorageAccountName=$($Diagnosticsstorage)"

        $variable = Get-Variable -Name numberOfInstances -Scope Global -ErrorAction SilentlyContinue
        if(!$variable) {$global:numberOfInstances=$null}
        Write-host -f blue "     numberOfInstances=$($numberOfInstances)"

}