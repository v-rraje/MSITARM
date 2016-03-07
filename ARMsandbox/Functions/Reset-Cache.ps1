function Reset-Cache(){
     
     $variable = Get-Variable -Name vmNamePart -Scope Global -ErrorAction SilentlyContinue
     if($variable) {$global:vmNamePart=$null}

     $variable = Get-Variable -Name numberOfInstances -Scope Global -ErrorAction SilentlyContinue
     if($variable) {$global:numberOfInstances=$null}

     $variable = Get-Variable -Name Diagnosticsstorage -Scope Global -ErrorAction SilentlyContinue
     if($variable) {$global:Diagnosticsstorage=$null}

     $variable = Get-Variable -Name DomainCreds -Scope Global -ErrorAction SilentlyContinue
     if($variable) {$global:DomainCreds=$null}
     
     $variable = Get-Variable -Name LocalCreds -Scope Global -ErrorAction SilentlyContinue
     if($variable) {$global:LocalCreds=$null}

      $variable = Get-Variable -Name sku -Scope Global -ErrorAction SilentlyContinue
     if($variable) {$global:sku=$null}

     show-cache
}
