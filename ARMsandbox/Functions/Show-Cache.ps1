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

        $variable = Get-Variable -Name AdditionalAdmins -Scope Global -ErrorAction SilentlyContinue
       if(!$variable) {$global:AdditionalAdmins=$null}
       Write-host -f blue "     AdditionalAdmins=$($AdditionalAdmins)"

        $variable = Get-Variable -Name numberOfInstances -Scope Global -ErrorAction SilentlyContinue
        if(!$variable) {$global:numberOfInstances=$null}
        Write-host -f blue "     numberOfInstances=$($numberOfInstances)"

        $variable = Get-Variable -Name imagePublisher -Scope Global -ErrorAction SilentlyContinue
        if(!$variable) {$global:imagePublisher=$imagePublisher}
        Write-host -f blue "     imagePublisher=$($imagePublisher)"

        $variable = Get-Variable -Name imageOffer -Scope Global -ErrorAction SilentlyContinue
        if(!$variable) {$global:imageOffer=$null}
        Write-host -f blue "     imageOffer=$($imageOffer)"

        $variable = Get-Variable -Name sku -Scope Global -ErrorAction SilentlyContinue
        if(!$variable) {$global:sku=$null}
        Write-host -f blue "     SKU=$($sku)"

}