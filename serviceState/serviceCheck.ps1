$path = "D:\UserData\Ibraaheem\Scripts\serviceState"
$servers = Get-Content "$path\serverlist.txt"

foreach($server in $servers){
$collect = @()
    $hostCheck = $server.Replace(" ", "")
    "Busy with " + $hostCheck
    Get-EventLog -LogName System -ComputerName $hostCheck -EntryType Information -Source "Service Control Manager" -After ((Get-Date).AddDays(-10)) | Where {$_.message -like "*admin*"} | foreach{
        $collect += $_ 
    }

    if(!($collect)){
       $noResults = [pscustomobject] @{
            Comment = "No results found for " + $hostCheck
       } | Export-Excel -Path $path\serviceCheck.xlsx -WorksheetName $hostCheck -Append -BoldTopRow -AutoFilter -FreezeTopRow
    }else{
        $collect | Export-Excel -Path $path\serviceCheck.xlsx -WorksheetName $hostCheck -Append -BoldTopRow -AutoFilter -FreezeTopRow
    }
}