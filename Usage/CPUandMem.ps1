$cpuUsage = Get-WmiObject -Class Win32_Processor| Measure-Object -property LoadPercentage -Average | Select -ExpandProperty Average
$memInfo = Get-WmiObject -Class Win32_OperatingSystem

$totMem = [Math]::Round(((($memInfo.TotalVisibleMemorySize)/1024)/1024),2)
$memFreeBytes = [Math]::Round(((($memInfo.FreePhysicalMemory)/1024)/1024),2)
$memFreePerc = [Math]::Round((($memFreeBytes/$totMem)*100),2)
$memUsageBytes = [Math]::Round(($totMem - $memFreeBytes),2)
$memUsagePerc = [Math]::Round((($memUsageBytes/$totMem)*100),2)

$cpuUsage + "%"
$memFreeBytes + "GB"
$memFreePerc + "%"
$totMem + "GB"
$memUsageBytes + "GB"
$memUsagePerc + "%"