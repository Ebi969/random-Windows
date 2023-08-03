$objHost = "SRV005879"

$objHostMem = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $objHost
$objHostCpu = Get-CimInstance -ClassName Win32_Processor -ComputerName $objHost

$memory = [math]::Round($objHostMem.TotalVisibleMemorySize/1024/1024,2)
$cpu = $objHostCpu.NumberOfLogicalProcessors

$output = [pscustomobject] @{
    "Server" = $objHost
    "Memory(GB)" = $memory
    "CpuCount" = $cpu
}

$output