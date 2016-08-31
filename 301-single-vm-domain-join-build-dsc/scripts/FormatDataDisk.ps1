# Name: FormatDataDisks
#
configuration FormatDataDisks 
{ 
      param (
         $Disks
    ) 

    #$DiskArray = $Disks | convertfrom-Json $disks
   
    node localhost
    {
       
        Script FormatVolumnes
        {
            GetScript = {
              get-disk
              Get-Partition
            }
            SetScript = {
               try {
                
                #format the ones requested
                foreach($disk in $using:Disks.values) {

                $diskArray = get-disk 
                $partArray = Get-Partition

                    $thisExists =$partArray  | Where-Object {$_.DriveLetter -eq $($disk.DiskName)} | Select -First 1
        
                    if($thisExists -eq $null) {
                                 
                        $DiskExists =  $diskArray  | ? {$($_.Size/1GB) -eq $($disk.Disksize)} | ?{$_.Number -notin $partarray.DiskNumber} | Sort-Object DiskNumber | select -First 1
            
                        try {
                            if($DiskExists) {      
                            
                                if($DiskExists.PartitionStyle -eq 'Raw') {
                                        $DiskExists |  Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -DriveLetter $($disk.DiskName) -UseMaximumSize | Format-Volume -NewFileSystemLabel $($disk.DiskLabel) -FileSystem NTFS -AllocationUnitSize 65536 -Confirm:$false     
                                    } else {
                                        $DiskExists |  New-Partition -DriveLetter $($disk.DiskName) -UseMaximumSize | Format-Volume -NewFileSystemLabel $($disk.DiskLabel) -FileSystem NTFS -AllocationUnitSize 65536 -Confirm:$false    
                                    } 
                          
                            } else {
                                write-verbose "No Drive avail"
                            }
                        } catch {
                                write-verbose  "`t[FAIL] $VM Setting Drive $($Disk.DiskName) Failed.`n"
                        
                        }

                    } else {
                        Write-verbose "`t[PASS] $VM Drive $($Disk.DiskName) exists.`n"
                    }
                }

                #format the remaining using next available drive letter
                get-disk | ? {$_.PartitionStyle -eq 'Raw'} | %{ Initialize-Disk -PartitionStyle GPT -Number $_.number -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS -AllocationUnitSize 65536 -Confirm:$false  }   

               } catch {}
            }
            TestScript = {
                 $diskArray = get-disk | ? {$_.PartitionStyle -eq 'RAW'}
                 $partArray = Get-Partition

                 $vols =@()
                 $disks | ? {
                    $d=$_
                    $v =  $($partArray  | Where-Object {$_.DriveLetter -eq $($d.DiskName)} | Select -First 1)
                    if(!$v){
                        $vols+=$d
                    }
                 }

            if($vols) {return $true} else {return $false}
            }    
            
        }

      }

    }


# SIG # Begin signature block
# MIIkAwYJKoZIhvcNAQcCoIIj9DCCI/ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBYlpGMtHbDAwQU
# J7JYQSBeIO9bQLLT0gZ/9QZEhGenk6CCDZIwggYQMIID+KADAgECAhMzAAAAZEeE
# lIbbQRk4AAAAAABkMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMTUxMDI4MjAzMTQ2WhcNMTcwMTI4MjAzMTQ2WjCBgzEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjENMAsGA1UECxMETU9Q
# UjEeMBwGA1UEAxMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAky7a2OY+mNkbD2RfTahYTRQ793qE/DwRMTrvicJK
# LUGlSF3dEp7vq2YoNNV9KlV7TE2K8sDxstNSFYu2swi4i1AL3X/7agmg3GcExPHf
# vHUYIEC+eCyZVt3u9S7dPkL5Wh8wrgEUirCCtVGg4m1l/vcYCo0wbU06p8XzNi3u
# XyygkgCxHEziy/f/JCV/14/A3ZduzrIXtsccRKckyn6B5uYxuRbZXT7RaO6+zUjQ
# hiyu3A4hwcCKw+4bk1kT9sY7gHIYiFP7q78wPqB3vVKIv3rY6LCTraEbjNR+phBQ
# EL7hyBxk+ocu+8RHZhbAhHs2r1+6hURsAg8t4LAOG6I+JQIDAQABo4IBfzCCAXsw
# HwYDVR0lBBgwFgYIKwYBBQUHAwMGCisGAQQBgjdMCAEwHQYDVR0OBBYEFFhWcQTw
# vbsz9YNozOeARvdXr9IiMFEGA1UdEQRKMEikRjBEMQ0wCwYDVQQLEwRNT1BSMTMw
# MQYDVQQFEyozMTY0Mis0OWU4YzNmMy0yMzU5LTQ3ZjYtYTNiZS02YzhjNDc1MWM0
# YjYwHwYDVR0jBBgwFoAUSG5k5VAF04KqFzc3IrVtqMp1ApUwVAYDVR0fBE0wSzBJ
# oEegRYZDaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljQ29k
# U2lnUENBMjAxMV8yMDExLTA3LTA4LmNybDBhBggrBgEFBQcBAQRVMFMwUQYIKwYB
# BQUHMAKGRWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWlj
# Q29kU2lnUENBMjAxMV8yMDExLTA3LTA4LmNydDAMBgNVHRMBAf8EAjAAMA0GCSqG
# SIb3DQEBCwUAA4ICAQCI4gxkQx3dXK6MO4UktZ1A1r1mrFtXNdn06DrARZkQTdu0
# kOTLdlGBCfCzk0309RLkvUgnFKpvLddrg9TGp3n80yUbRsp2AogyrlBU+gP5ggHF
# i7NjGEpj5bH+FDsMw9PygLg8JelgsvBVudw1SgUt625nY7w1vrwk+cDd58TvAyJQ
# FAW1zJ+0ySgB9lu2vwg0NKetOyL7dxe3KoRLaztUcqXoYW5CkI+Mv3m8HOeqlhyf
# FTYxPB5YXyQJPKQJYh8zC9b90JXLT7raM7mQ94ygDuFmlaiZ+QSUR3XVupdEngrm
# ZgUB5jX13M+Pl2Vv7PPFU3xlo3Uhj1wtupNC81epoxGhJ0tRuLdEajD/dCZ0xIni
# esRXCKSC4HCL3BMnSwVXtIoj/QFymFYwD5+sAZuvRSgkKyD1rDA7MPcEI2i/Bh5O
# MAo9App4sR0Gp049oSkXNhvRi/au7QG6NJBTSBbNBGJG8Qp+5QThKoQUk8mj0ugr
# 4yWRsA9JTbmqVw7u9suB5OKYBMUN4hL/yI+aFVsE/KJInvnxSzXJ1YHka45ADYMK
# AMl+fLdIqm3nx6rIN0RkoDAbvTAAXGehUCsIod049A1T3IJyUJXt3OsTd3WabhIB
# XICYfxMg10naaWcyUePgW3+VwP0XLKu4O1+8ZeGyaDSi33GnzmmyYacX3BTqMDCC
# B3owggVioAMCAQICCmEOkNIAAAAAAAMwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29m
# dCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDExMB4XDTExMDcwODIwNTkw
# OVoXDTI2MDcwODIxMDkwOVowfjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEoMCYGA1UEAxMfTWljcm9zb2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAx
# MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKvw+nIQHC6t2G6qghBN
# NLrytlghn0IbKmvpWlCquAY4GgRJun/DDB7dN2vGEtgL8DjCmQawyDnVARQxQtOJ
# DXlkh36UYCRsr55JnOloXtLfm1OyCizDr9mpK656Ca/XllnKYBoF6WZ26DJSJhIv
# 56sIUM+zRLdd2MQuA3WraPPLbfM6XKEW9Ea64DhkrG5kNXimoGMPLdNAk/jj3gcN
# 1Vx5pUkp5w2+oBN3vpQ97/vjK1oQH01WKKJ6cuASOrdJXtjt7UORg9l7snuGG9k+
# sYxd6IlPhBryoS9Z5JA7La4zWMW3Pv4y07MDPbGyr5I4ftKdgCz1TlaRITUlwzlu
# ZH9TupwPrRkjhMv0ugOGjfdf8NBSv4yUh7zAIXQlXxgotswnKDglmDlKNs98sZKu
# HCOnqWbsYR9q4ShJnV+I4iVd0yFLPlLEtVc/JAPw0XpbL9Uj43BdD1FGd7P4AOG8
# rAKCX9vAFbO9G9RVS+c5oQ/pI0m8GLhEfEXkwcNyeuBy5yTfv0aZxe/CHFfbg43s
# TUkwp6uO3+xbn6/83bBm4sGXgXvt1u1L50kppxMopqd9Z4DmimJ4X7IvhNdXnFy/
# dygo8e1twyiPLI9AN0/B4YVEicQJTMXUpUMvdJX3bvh4IFgsE11glZo+TzOE2rCI
# F96eTvSWsLxGoGyY0uDWiIwLAgMBAAGjggHtMIIB6TAQBgkrBgEEAYI3FQEEAwIB
# ADAdBgNVHQ4EFgQUSG5k5VAF04KqFzc3IrVtqMp1ApUwGQYJKwYBBAGCNxQCBAwe
# CgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0j
# BBgwFoAUci06AjGQQ7kUBU7h6qfHMdEjiTQwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0
# cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2Vy
# QXV0MjAxMV8yMDExXzAzXzIyLmNybDBeBggrBgEFBQcBAQRSMFAwTgYIKwYBBQUH
# MAKGQmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2Vy
# QXV0MjAxMV8yMDExXzAzXzIyLmNydDCBnwYDVR0gBIGXMIGUMIGRBgkrBgEEAYI3
# LgMwgYMwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lv
# cHMvZG9jcy9wcmltYXJ5Y3BzLmh0bTBABggrBgEFBQcCAjA0HjIgHQBMAGUAZwBh
# AGwAXwBwAG8AbABpAGMAeQBfAHMAdABhAHQAZQBtAGUAbgB0AC4gHTANBgkqhkiG
# 9w0BAQsFAAOCAgEAZ/KGpZjgVHkaLtPYdGcimwuWEeFjkplCln3SeQyQwWVfLiw+
# +MNy0W2D/r4/6ArKO79HqaPzadtjvyI1pZddZYSQfYtGUFXYDJJ80hpLHPM8QotS
# 0LD9a+M+By4pm+Y9G6XUtR13lDni6WTJRD14eiPzE32mkHSDjfTLJgJGKsKKELuk
# qQUMm+1o+mgulaAqPyprWEljHwlpblqYluSD9MCP80Yr3vw70L01724lruWvJ+3Q
# 3fMOr5kol5hNDj0L8giJ1h/DMhji8MUtzluetEk5CsYKwsatruWy2dsViFFFWDgy
# cScaf7H0J/jeLDogaZiyWYlobm+nt3TDQAUGpgEqKD6CPxNNZgvAs0314Y9/HG8V
# fUWnduVAKmWjw11SYobDHWM2l4bf2vP48hahmifhzaWX0O5dY0HjWwechz4GdwbR
# BrF1HxS+YWG18NzGGwS+30HHDiju3mUv7Jf2oVyW2ADWoUa9WfOXpQlLSBCZgB/Q
# ACnFsZulP0V3HjXG0qKin3p6IvpIlR+r+0cjgPWe+L9rt0uX4ut1eBrs6jeZeRhL
# /9azI2h15q/6/IvrC4DqaTuv/DDtBEyO3991bWORPdGdVk5Pv4BXIqF4ETIheu9B
# CrE/+6jMpF3BoYibV3FWTkhFwELJm3ZbCoBIa/15n8G9bW1qyVJzEw16UM0xghXH
# MIIVwwIBATCBlTB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExAhMzAAAA
# ZEeElIbbQRk4AAAAAABkMA0GCWCGSAFlAwQCAQUAoIG4MBkGCSqGSIb3DQEJAzEM
# BgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqG
# SIb3DQEJBDEiBCCdaiYyejr0I/ClmAmFrjsiBNVKMzNDcyLJZb0Dzi2u7TBMBgor
# BgEEAYI3AgEMMT4wPKASgBAATQBTAEkAVAAgAEEAUgBNoSaAJGh0dHBzOi8vZ2l0
# aHViLmNvbS9taWNyb3NvZnQvbXNpdGFybTANBgkqhkiG9w0BAQEFAASCAQAY31Lo
# J6CGIx0VRSHGxrUPnk0Ma9cDyv1TS7cgtrmhBrnF+doIRpcby/+lxjBO0xQVnzxy
# k+jXKub6+cxI0r+TRUDu2ihJY1Cm1Tym1PnFxjhpYH2qf2wCuRUoaAw0A3iRiGHD
# /OUyUNjz0Yo0aeA1npsNQvptdOqdYJ4StmoNKxri7E7ChhFs7XJtoe/UxP5Kk6TS
# ld64d2o9w67QhG3QrhANm68eyCI2hnnHg3EJzbRn9ciZ3j8mLp7sKli2HPKY7vd1
# UjDzIkwwlAPfviSxj9bksEzOV5XIVp/qlAyfK1vst/ACEAHpIIo22WJUS/rT01IA
# k4PXVT3RizuMLgYRoYITRzCCE0MGCisGAQQBgjcDAwExghMzMIITLwYJKoZIhvcN
# AQcCoIITIDCCExwCAQMxDzANBglghkgBZQMEAgEFADCCAToGCyqGSIb3DQEJEAEE
# oIIBKQSCASUwggEhAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIMFd
# qW2PHHSqGq0/iXn835gL68QfV8FzVklxgpusYuYEAgZXvINfU+4YEzIwMTYwODMx
# MjEzNjQwLjA3OFowBIACAfSggbmkgbYwgbMxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIxJzAlBgNVBAsTHm5DaXBoZXIg
# RFNFIEVTTjoxNDhDLUM0QjktMjA2NjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCDs0wggZxMIIEWaADAgECAgphCYEqAAAAAAACMA0GCSqG
# SIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkg
# MjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0yNTA3MDEyMTQ2NTVaMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
# AQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWlCgCChfvtfGhLLF/Fw+Vhwna3PmYr
# W/AVUycEMR9BGxqVHc4JE458YTBZsTBED/FgiIRUQwzXTbg4CLNC3ZOs1nMwVyaC
# o0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeRX4FUsc+TTJLBxKZd0WETbijGGvmG
# gLvfYfxGwScdJGcSchohiq9LZIlQYrFd/XcfPfBXday9ikJNQFHRD5wGPmd/9WbA
# A5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogINeh4HLDpmc085y9Euqf03GS9pAHB
# IAmTeM38vMDJRF1eFpwBBU8iTQIDAQABo4IB5jCCAeIwEAYJKwYBBAGCNxUBBAMC
# AQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8RhvFM2hahW1VMBkGCSsGAQQBgjcUAgQM
# HgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1Ud
# IwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0
# dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0Nl
# ckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKG
# Pmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0
# XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSABAf8EgZUwgZIwgY8GCSsGAQQBgjcuAzCB
# gTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL1BLSS9kb2Nz
# L0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0HjIgHQBMAGUAZwBhAGwAXwBQ
# AG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0AC4gHTANBgkqhkiG9w0BAQsF
# AAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Ehb7Prpsz1Mb7PBeKp/vpXbRkws8LFZslq
# 3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7uVOMzPRgEop2zEBAQZvcXBf/XPleFzWY
# JFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqRUgCvOA8X9S95gWXZqbVr5MfO9sp6AG9L
# MEQkIjzP7QOllo9ZKby2/QThcJ8ySif9Va8v/rbljjO7Yl+a21dA6fHOmWaQjP9q
# Yn/dxUoLkSbiOewZSnFjnXshbcOco6I8+n99lmqQeKZt0uGc+R38ONiU9MalCpaG
# pL2eGq4EQoO4tYCbIjggtSXlZOz39L9+Y1klD3ouOVd2onGqBooPiRa6YacRy5rY
# DkeagMXQzafQ732D8OE7cQnfXXSYIghh2rBQHm+98eEA3+cxB6STOvdlR3jo+KhI
# q/fecn5ha293qYHLpwmsObvsxsvYgrRyzR30uIUBHoD7G4kqVDmyW9rIDVWZeodz
# OwjmmC3qjeAzLhIp9cAvVCch98isTtoouLGp25ayp0Kiyc8ZQU3ghvkqmqMRZjDT
# u3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx16HSxVXjad5XwdHeMMD9zOZN+w2/XU/p
# nR4ZOC+8z1gFLu8NoFA12u8JJxzVs341Hgi62jbb01+P3nSISRIwggTaMIIDwqAD
# AgECAhMzAAAAiUn1DOTxi5SzAAAAAACJMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTE2MDMzMDE5MjQyNloXDTE3MDYzMDE5
# MjQyNlowgbMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xDTAL
# BgNVBAsTBE1PUFIxJzAlBgNVBAsTHm5DaXBoZXIgRFNFIEVTTjoxNDhDLUM0Qjkt
# MjA2NjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCASIw
# DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL5+QbX38cc1ITtOV04eOCBc9arc
# VScOsR9CN6d6fYab/E62CW095yggfRoZGhvLk2IboLEuJkUDfKerHhf7UIeAFfMB
# 42oB6Fatbth+kGc+9YrcutqjjoMxjtlCrZziESdJPhI/WWyWrSF+mSeSubHjdGY0
# JCCg+xlNctABsrbhuAdqT61hyh3g3jCaPjuHXGvgATVMvbJhDb7QPQ4cPFBScZFb
# IhV6FKgWr5WQVCGDofLSqIh+itty0vNjyDe/PEQBoJEspx6q+agDg3yyqvf2kP/C
# KZKkyQ8UhQkuTTJt1ZfFZoXEjoHqoXdM3LvvoYQq/lIR6v+hTfF5/Unj8EMCAwEA
# AaOCARswggEXMB0GA1UdDgQWBBTVwPpBFF2X1055Ctmbh6S/V/5TsDAfBgNVHSME
# GDAWgBTVYzpcijGQ80N7fEYbxTNoWoVtVTBWBgNVHR8ETzBNMEugSaBHhkVodHRw
# Oi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNUaW1TdGFQ
# Q0FfMjAxMC0wNy0wMS5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1RpbVN0YVBDQV8y
# MDEwLTA3LTAxLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4IBAQCjUyzo/BB549H8Oyjz0xe+uhkJxPvVC5rWY85m
# EmU+lJgOxG6AQO7sF2VQ3Z4MFwcQnMcAFKofyFj6AN+drRjwr2F30VxhxeYDOxaW
# VLbQY9YVl3sTtt23DKA03c5bCkMGK3wHc/oWB7PSkGDhyTGrPMWZjD7IMAQGc8G+
# rgN82ijxCmHTnAhlpNO1v0YV3CWLjLm7IVNx/2dy+tTMpitHpnPaf17UWuF0xccs
# TgEAvd3rehLEdnylm/eoYRyvk2bjc1Jkj7h/agu6Q8HFY3vnGLQx+8/i1iD94j6T
# ZINkbWx0D+glDTFt4ei7p9C30Wpon3dq4fqOUOfuzf/FOWWvoYIDdjCCAl4CAQEw
# geOhgbmkgbYwgbMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# DTALBgNVBAsTBE1PUFIxJzAlBgNVBAsTHm5DaXBoZXIgRFNFIEVTTjoxNDhDLUM0
# QjktMjA2NjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIl
# CgEBMAkGBSsOAwIaBQADFQCGWJJE6T6Be+eg2QB44EL7fKLK6KCBwjCBv6SBvDCB
# uTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjENMAsGA1UECxME
# TU9QUjEnMCUGA1UECxMebkNpcGhlciBOVFMgRVNOOjRERTktMEM1RS0zRTA5MSsw
# KQYDVQQDEyJNaWNyb3NvZnQgVGltZSBTb3VyY2UgTWFzdGVyIENsb2NrMA0GCSqG
# SIb3DQEBBQUAAgUA23GK8jAiGA8yMDE2MDgzMTE2NTcyMloYDzIwMTYwOTAxMTY1
# NzIyWjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDbcYryAgEAMAcCAQACAgDEMAcC
# AQACAhvzMAoCBQDbctxyAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkK
# AwGgCjAIAgEAAgMHoSChCjAIAgEAAgMHoSAwDQYJKoZIhvcNAQEFBQADggEBACVA
# 0nIkrgcCubR5L9bj8g/GSmuixewywzVgt6zcFJi4Rhb2fnh90UifRDeULK0QRs6d
# d2umzI7VuMqyMI7UWTS1bwZ5o3aNediLOLrF8dz619inKpGIVGtyqnUjD48minZF
# r1ZAOKjJdD/3JvUnzIaZ78ksoRpG4zzbHr9JNFB1azKBEIVIFamNtbgdYzMk5MRz
# U09hsBLc1raXCBxf6vCCCR732kUaJnw0M1R5uruvD6Nk3BxhZsMyCVlVdlkL6crf
# 50OAMIUZi4FPX8mO3qWt54VbosBqzZKQpf+d8KIr0JivESUZwsfSeIOsdnnZR/U2
# VXkbHqngXqlvxYGwIpkxggL1MIIC8QIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMAITMwAAAIlJ9Qzk8YuUswAAAAAAiTANBglghkgBZQMEAgEFAKCC
# ATIwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCBW
# DjKZn7gBPQIPJtemY/xosvA1jkvutlTqkT/fg1yWsjCB4gYLKoZIhvcNAQkQAgwx
# gdIwgc8wgcwwgbEEFIZYkkTpPoF756DZAHjgQvt8osroMIGYMIGApH4wfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAACJSfUM5PGLlLMAAAAAAIkwFgQU
# 9FsFMJMcDJeKNnuFOp4Vyem+gkwwDQYJKoZIhvcNAQELBQAEggEAFRXq1M9Pp8Bm
# hCYcBI3IZVYRgsLmko+9jJCrwwLK9uhXP8XzfPGmmztIiiCuShZlHqPhGdePpFRI
# iBpxYCy96IEIoBhIlTAtUY2p8cfwLkwDJ2OxmUq4CVKdli5VTmfNhmU9p7Dn7Xql
# x6srpiCj4hOj6gnKMtOQAfeVQGRBhrtQW2KOcE4FViEccY0EccZNWZxI0HmOPan/
# 8o5BGplOH2ZEqk2rqfeCKPFF7yHQjizLw/1ojYnhplJzby276G0IX80+jGawf42m
# 7YwzhI8vs8UkR8zvc3GM5bXGO8jIVUI8793Gk/Kyv0PB7XqXAK6LQD1/Nead+5cV
# uPmOllUv3A==
# SIG # End signature block
