$path = "D:\UserData\Ibraaheem\Scripts\Set-DNS"
$ServerList = Get-Content $path\ServerList.txt

if(Test-Path $path\report.csv){
    Remove-Item $path\report.csv
}

foreach($Server in $ServerList){

    try{

        $DNSservers = "10.11.21.121", "10.11.21.23"
        $DNSSuffixes = "mud.internal.co.za", "sanlam.co.za"

        $networkConfig = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $Server -filter "ipenabled = 'true'" -ErrorAction Stop
        $networkConfig.SetDNSServerSearchOrder($DNSservers)
        #$networkConfig.SetDnsDomain("dnsdc.mud.internal.co.za")
        $networkConfig.SetDynamicDNSRegistration($true,$false)
        Invoke-Wmimethod -Class win32_networkadapterconfiguration -ComputerName $Server -Name setDNSSuffixSearchOrder -ArgumentList @($DNSSuffixes),$null -ErrorAction Stop
        #ipconfig /registerdns
        Write-Host -ForegroundColor Green "$Server completed successfully"
        $msg = "Completed Successfully"

    }catch{

        Write-Host -ForegroundColor Yellow "$Server ran into a problem"
        $msg = "Ran into a problem"
    }

    $out = New-Object PSObject

    $out | Add-Member -MemberType NoteProperty -Name "Server Name" -Value $Server
    $out | Add-Member -MemberType NoteProperty -Name "Comment" -Value $msg

    $out | Export-Csv $path\report.csv -Append -NoTypeInformation
}