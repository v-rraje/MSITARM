function Remove-CachedData(){
     
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

     show-cache
}
set-alias Reset-Cache Remove-CachedData