$serverName = Read-Host "Please input Server Name"

while($serverName -ne $null){
Get-CimInstance -ClassName Win32_LogicalDisk -CimSession $serverName.Replace(" ", "") -ErrorAction Stop | Where {$_.DriveType -eq 3} | select @{n="Server" ; e={$_.PSComputername}}, @{n="Drive"; e={$_.DeviceID}}, @{n="VolumeName"; e={$_.volumeName}}, @{n="Size(GB)" ; e={[Math]::Round($_.Size/1024/1024/1024, 2)}}, @{n="FreeSpace(GB)" ; e={[Math]::Round($_.FreeSpace/1024/1024/1024, 2)}} | ft -AutoSize | Out-Default
$serverName = $null
$serverName = Read-Host "Please input Server Name"
}