$cred = Get-Credential

$Server = "SRV003606"

Restart-Computer $Server -Credential $cred -Force

Start-Sleep -Seconds 10

While(!(Test-Connection $Server)){

    Write-Host "Offline"

}

Write-Host "Online"