$path="D:\UserData\Ibraaheem\Scripts\Total cores and mem" 
$Servers = get-content "$path\Serverlist.txt"

If(Test-Path $path\TotalCoreMem.csv){
    Remove-Item $path\TotalCoreMem.csv
}


foreach($server in $Servers){

        $logicalProcessors = Get-WmiObject -Class Win32_ComputerSystem  -computer $server | select -ExpandProperty NumberOfLogicalProcessors
        $physicalMemory = [Math]::Round((Get-WmiObject -Class Win32_ComputerSystem  -computer $server).TotalPhysicalMemory/1MB)
    
        $out = New-Object PSObject

        $out | Add-Member -MemberType NoteProperty -Name "Server Name" -Value $server
        $out | Add-Member -MemberType NoteProperty -Name "Number of Logical Processors" -Value $logicalProcessors
        $out | Add-Member -MemberType NoteProperty -Name "Total Physical Memory" -Value $physicalMemory

        $out | Export-Csv $path\TotalCoreMem.csv -NoTypeInformation -Append
    
}

