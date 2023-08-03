
$path = "D:\UserData\Ibraaheem\Scripts\VulnCheck"
$serverList = Get-Content $path\serverlist.txt
#$serverList = "SRV007998"
#$cred = Get-Credential

foreach($server in $serverList){
    Invoke-Command -FilePath $path\VulnCheck.ps1 -ComputerName $server -Credential $cred
}