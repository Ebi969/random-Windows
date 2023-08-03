
$serverName = "SRV030323"

# getting the date and time into a usable format (used in the names of the files)
$timestamp=Get-Date -Format s | foreach {$_ -replace "-", ""} | foreach {$_ -replace "T", "_"} | foreach {$_ -replace ":",""} 

# getting the path that is used to write the output files to
$path = "D:\UserData\Ibraaheem\Scripts\Server Checks"

# setting up the prefix for the final output files
$fileprefix=$path + "\" + $serverName + "_" + $timestamp
$outPut = $fileprefix + "_config.txt"

$cred = Get-Credential


if(Test-Path $path\Compliance.html){
    Remove-Item $path\Compliance.html
}

if(Test-Path $outPut){
    Remove-Item $outPut
}

Function get-Info{
$ou = Get-ADComputer -Identity $serverName -Properties CanonicalName |select -ExpandProperty CanonicalName
Write-host "OU: $ou"

"OU: $ou" | Out-File -FilePath $outPut -Append

#can be done remotely
$installedPrograms = Get-WmiObject Win32_product -ComputerName $serverName | Select Name, Vendor, Version | Sort-Object -Property Name | Format-Table –AutoSize
$installedPrograms
$installedPrograms | Out-File -FilePath $outPut -Append

$nlaValue = (Get-WMIObject -Class "Win32_TSGeneralSetting" -NameSpace root\cimv2\terminalservices -ComputerName $serverName -Filter "TerminalName='RDP-tcp'").UserAuthenticationRequired
if($nlaValue -eq "1"){
    $nlaEnabled = "True"
}else{
    $nlaEnabled = "False"
}

"NLA Enabled: $nlaEnabled" | Out-File -FilePath $outPut -Append
Write-Host "NLA Enabled: $nlaEnabled`n"


$FireWallRules = Invoke-Command -ComputerName $serverName -Credential $cred -ScriptBlock{(New-object -ComObject HNetCfg.FWPolicy2).rules}

$specificFirewall = $FireWallRules | Where-Object {$_.Name -eq 'File and Printer Sharing (Echo Request - ICMPv4-In)' -or $_.Name -eq 'Remote Service Management (RPC-EPMAp)' `
                    -or $_.Name -eq 'Remote Service Management (RPC)' -or $_.Name -eq 'Remote Service Management (NP-In)' -or $_.Name -eq 'Windows Management Instrumentation (DCOM-In)' `
                    -or $_.Name -eq 'Windows Management Instrumentation (WMI-In)'} | Select-Object -Property Name, Enabled | Out-File -FilePath $outPut -Append

$specificFirewall

$adminGroups = Invoke-Command -ComputerName $serverName -Credential $cred -ScriptBlock{Get-LocalGroupMember -Group "Administrators" | Select -ExpandProperty Name}
Write-Host "`nAdmin Groups:"
$adminGroups

"Admin Groups:" | Out-File -FilePath $outPut -Append
$adminGroups | Out-File -FilePath $outPut -Append

#toCSS($ou, $installedPrograms, $nlaEnabled, $FireWallRules, $adminGroups)

}

Function toCSS{
Param(
    $ou,
    $installedPrograms,
    $nlaEnabled,
    $FireWallRules,
    $adminGroups
)

$HTMLReport = "$path\Compliance.html"
$ReportTitle = $serverName

$specificFirewall = $FireWallRules | Where-Object {$_.Name -eq 'File and Printer Sharing (Echo Request - ICMPv4-In)' -or $_.Name -eq 'Remote Service Management (RPC-EPMAp)' `
                    -or $_.Name -eq 'Remote Service Management (RPC)' -or $_.Name -eq 'Remote Service Management (NP-In)' -or $_.Name -eq 'Windows Management Instrumentation (DCOM-In)' `
                    -or $_.Name -eq 'Windows Management Instrumentation (WMI-In)'} | Select-Object -Property Name, Enabled


$belowTable = "
    <p> $ou </p>
"

$aboveTable = "

 <h1 id='Test'>$ReportTitle</h1>
 `n
 <h5>Updated: on $(Get-Date)</h5> 

"

$specificFirewall | ConvertTo-Html -Title $ReportTitle
$installedPrograms | ConvertTo-Html -Title $ReportTitle
$adminGroups | ConvertTo-Html -Title $ReportTitle

# Write Content to Report.
    Add-Content $HTMLReport $aboveTable
    Add-Content $HTMLReport $belowTable
    Add-Content $HTMLReport $installedPrograms
    Add-Content $HTMLReport $specificFirewall
    Add-Content $HTMLReport $adminGroups

# Call the results or open the file.
    Invoke-Item $HTMLReport
}

get-Info