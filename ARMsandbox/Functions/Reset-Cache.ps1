function Reset-Cache(){
     
     $variable = Get-Variable -Name vmNamePart -Scope Global -ErrorAction SilentlyContinue
     if($variable) {$global:vmNamePart=$null}

     $variable = Get-Variable -Name numberOfInstances -Scope Global -ErrorAction SilentlyContinue
     if($variable) {$global:numberOfInstances=$null}

     $variable = Get-Variable -Name AdditionalAdmins -Scope Global -ErrorAction SilentlyContinue
     if($variable) {$global:AdditionalAdmins=$null}

     $variable = Get-Variable -Name DomainCreds -Scope Global -ErrorAction SilentlyContinue
     if($variable) {$global:DomainCreds=$null}
     
     $variable = Get-Variable -Name LocalCreds -Scope Global -ErrorAction SilentlyContinue
     if($variable) {$global:LocalCreds=$null}

     $variable = Get-Variable -Name imagePublisher -Scope Global -ErrorAction SilentlyContinue
     if($variable) {$global:imagePublisher=$null}

     $variable = Get-Variable -Name imageOffer -Scope Global -ErrorAction SilentlyContinue
     if($variable) {$global:imageOffer=$null}

      $variable = Get-Variable -Name sku -Scope Global -ErrorAction SilentlyContinue
     if($variable) {$global:sku=$null}

     show-cache
}
