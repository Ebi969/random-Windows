$inputPath = "C:\Users\DA003089\Desktop\Vuln"
$outputPath = "\\SRV005879\Reports\Vulnerabilities\Owner Reboots"
$serverSheet = Import-Excel -Path "$inputPath\*Nov.xlsx" -WorksheetName "List"

$timestamp=Get-Date -Format s | foreach {$_ -replace "-", ""} | foreach {$_ -replace "T", "_"} | foreach {$_ -replace ":",""} 

$fileprefix = $outputPath + "\" + $timestamp
$outPutName = $fileprefix + "_rebootCheck.xlsx"

if(Test-Path $outputPath\$outPutName){
    Remove-Item $outputPath\$outPutName
}

foreach($row in $serverSheet){
        
        $ServerName = $row.'Server Name'
        $ServerName

        try{
            $bootTime = Get-WmiObject Win32_OperatingSystem -ComputerName $ServerName -ErrorAction Stop | Select -ExpandProperty LastBootUpTime
            $dateBooted = [System.Management.ManagementDateTimeConverter]::ToDateTime($bootTime)
        }catch{
            $dateBooted = "Error connecting to server"
        }    

        $row | Add-Member -MemberType NoteProperty -Name "Last Rebooted" -Value $dateBooted

        $row | Export-Excel -Path $outPutName -Append -FreezeTopRowFirstColumn -BoldTopRow -AutoFilter -AutoSize
        
}