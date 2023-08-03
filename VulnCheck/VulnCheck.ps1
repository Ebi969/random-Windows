$env:COMPUTERNAME

# IE All Fixes Reg Key
$regName = 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX\iexplore.exe'
$regValue = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX' -Name iexplore.exe -EA SilentlyContinue | Select -ExpandProperty iexplore.exe
$shouldBe = "1"
if($regValue -eq $shouldBe){
    $regName = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX\iexplore.exe'
    $regValue = Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX' -Name iexplore.exe -EA SilentlyContinue | Select -ExpandProperty iexplore.exe
    $shouldBe = "1"
    if($regValue -eq $shouldBe){    
        $regName = 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING\iexplore.exe'
        $regValue = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING' -Name iexplore.exe -EA SilentlyContinue | Select -ExpandProperty iexplore.exe
        $shouldBe = "1"
        if($regValue -eq $shouldBe){
            $regName = 'HKLM:\SOFTWARE\Microsoft\InternetEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING\iexplore.exe'
            $regValue = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\InternetEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING' -Name iexplore.exe -EA SilentlyContinue | Select -ExpandProperty iexplore.exe
            $shouldBe = "1"
            if($regValue -eq $shouldBe){
                $cleared = $true
            }else{
                $cleared = $false
                $errorWith = $regName
            }
        }else{
            $cleared = $false
            $errorWith = $regName
        }            
    }else{
        $cleared = $false
        $errorWith = $regName
    }    
}else{
    $cleared = $false
    $errorWith = $regName
}

if($cleared){
    $cleared
}else{
    $cleared
    $errorWith
    $regValue
    $shouldBe
}

#KB3009008 Reg Key
$regName = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client\DisabledByDefault'
$regValue = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Name DisabledByDefault -EA SilentlyContinue | Select -ExpandProperty DisabledByDefault
$shouldBe = "1"

if($regValue -eq $shouldBe){
    $regName = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server\Enabled'
    $regValue = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name Enabled -EA SilentlyContinue | Select -ExpandProperty Enabled
    $shouldBe = "0"
    if($regValue -eq $shouldBe){
        $cleared = $true
    }else{
        $cleared = $false
        $errorWith = $regName
    }
}else{
    $cleard = $false
    $errorWith = $regName
}

if($cleared){
    $cleared
}else{
    $cleared
    $errorWith
    $regValue
    $shouldBe
}

#ZombieLoad_Fallout
$regName = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\FeatureSettingsOverride'
$regValue = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name FeatureSettingsOverride -EA SilentlyContinue | Select -ExpandProperty FeatureSettingsOverride
$shouldBe = "72"
if($regValue -eq $shouldBe){
    $regName = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\FeatureSettingsOverrideMask'
    $regValue = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name FeatureSettingsOverrideMask -EA SilentlyContinue | Select -ExpandProperty FeatureSettingsOverrideMask
    $shouldBe = "3"
    if($regValue -eq $shouldBe){
        $regName = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\MinVmVersionForCpuBasedMitigations'
        $regValue = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization' -Name MinVmVersionForCpuBasedMitigations -EA SilentlyContinue | Select -ExpandProperty MinVmVersionForCpuBasedMitigations
        $shouldBe = "1.0"
        if($regValue -eq $shouldBe){
            $cleared = $true
        }else{
            $cleared = $false
            $errorWith = $regName
        }
    }else{
        $cleared  = $false
        $errorWith = $regName
    }
}else{
    $cleared = $false
    $errorWith = $regName
}

if($cleared){
    $cleared
}else{
    $cleared
    $errorWith
    $regValue
    $shouldBe
}

#KB4022715 Reg Key
$regName = 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX\iexplore.exe'
$regValue = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX' -Name iexplore.exe -EA SilentlyContinue | Select -ExpandProperty iexplore.exe
$shouldBe = "1"
if($regValue -eq $shouldBe){
   $regName = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX\iexplore.exe'
    $regValue = Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX' -Name iexplore.exe -EA SilentlyContinue | Select -ExpandProperty iexplore.exe
    $shouldBe = "1"
    if($regValue -eq $shouldBe){
        $cleared = $true
    }
}else{
    $cleared = $false
    $errorWith = $regName
}

if($cleared){
    $cleared
}else{
    $cleared
    $errorWith
    $regValue
    $shouldBe
}

# MS15-124 Reg Key
$regName = 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING\iexplore.exe'
$regValue = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING' -Name iexplore.exe -EA SilentlyContinue | Select -ExpandProperty iexplore.exe
$shouldBe = "1"
if($regValue -eq $shouldBe){
    $cleared = $true
}else{
    $cleared = $false    
    $errorWith = $regName
}

if($cleared){
    $cleared
}else{
    $cleared
    $errorWith
    $regValue
    $shouldBe
}


#KB4091664
Try{
    $test = Get-HotFix -Id KB4091664 -EA Stop
    $installed = "KB4091664 is Installed"
}catch{
    $installed = "KB4091664 is Not Installed"    
}
    $installed
    $installed = $null

#KB4346087
Try{
    $test = Get-HotFix -Id KB4346087 -EA Stop
    $installed = "KB4346087 is Installed"
}catch{
    $installed = "KB4346087 is Not Installed"
}
    $installed
    $installed = $null