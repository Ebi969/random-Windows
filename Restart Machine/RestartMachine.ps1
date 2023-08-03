$Server = "SRV005475"
$creds = Get-Credential
$lastbootuptime = Get-CimInstance -ClassName Win32_OperatingSystem | Select Lastbootuptime

<#
if(($lastbootuptime.Lastbootuptime) -gt (Get-Date).AddMinutes(-5)){
#Less than 5 minutes ago   
}else{
#More than 5 minutes ago
}
#>

Restart-Computer $Server -Credential $creds -Force

$testRDP = New-Object System.Net.Sockets.TCPClient -ArgumentList $Server,3389
While($testRDP.Connected){
    "Can RDP"
    $testRDP = New-Object System.Net.Sockets.TCPClient -ArgumentList $Server,3389
}
While(!($testRDP.Connected)){
    "Can't RDP"
    $testRDP = New-Object System.Net.Sockets.TCPClient -ArgumentList $Server,3389
}

Write-Host "Online"

<#
While(!(Test-Connection $Server -Count 1)){

    Write-Host "Reboot in Progress"    
    sleep -Seconds 2
}

Write-Host "Online"
#>