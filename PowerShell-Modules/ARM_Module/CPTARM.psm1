#get this modules path
$Root =(Get-Location).Path

#load the library of Scripts
gci "$Root\Scripts" -recurse -filter *.ps1 | % { . $_.FullName }
Export-ModuleMember -Function "*"

#load the library of functions
gci "$Root\Functions" -recurse -filter *.ps1 | % { . $_.FullName }
Export-ModuleMember -Function "*"




