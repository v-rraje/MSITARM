function Remove-CachedData(){
     
     $variable = Get-Variable -Name vmNamePart -Scope Global -ErrorAction SilentlyContinue
     if($variable) {$global:vmNamePart=$null}

     $variable = Get-Variable -Name DiagStore -Scope Global -ErrorAction SilentlyContinue
     if($variable) {$global:DiagStore=$null}

    $Global:DomainCreds=$null
    $Global:LocalCreds=$null
}