$serverListPath = "D:\UserData\Ibraaheem\Scripts\Remove Defender"
$Serverlist = Get-Content $serverListPath\ServerList.txt

$outPutPath = "$serverListPath\statusCheck.xlsx"

foreach($serverName in $Serverlist){

$server = $serverName.replace(" ", "")
$path = "\\$server\C$\Windows\System32"

    if(Test-Path $path\MpSigStub.exe){
    
        try{
            Remove-Item $path\MpSigStub.exe -Force -ErrorAction stop        
        
            $msg = "MpSigStub Removed From System32"
            
                Write-Host "`n#################################################################################"
                Write-Host -ForegroundColor Green "MpSigStub Removed Successfully from path: $path"
                Write-Host "#################################################################################"

        }catch{
            $msg = "error occured"
            Write-Host "`n#################################################################################"
            Write-Host -ForegroundColor Red "No Access to $path"
            Write-Host "#################################################################################"
        }

    }else{

        $msg = "path cannot be found"
    
        Write-Host "`n###########################################################################"
        Write-Host -ForegroundColor Yellow "$path - path cannot be found"
        Write-Host "###########################################################################"
    }

    $outPut = [pscustomobject] @{
        "Server" = $server
        "Status" = $msg
    } 

    $allOutput += $outPut
    
}

$allOutput | Export-Excel -path $outPutPath -Append -BoldTopRow