$account = "bcxmso"
$servers = Get-Content .\servers.txt

Function Remove_Local_Account{

$msg = "Attempting in Local Account"

$msg | Out-File -FilePath .\results.txt -Append

    foreach ($server in $servers){
        try{
            $adminGroup = [ADSI]"WinNT://$server"
            $adminGroup.delete("User", $account)
            "$server`tSuccess"
            "$server`tSuccess" | Out-File -FilePath .\results.txt -Append
        }catch{
            "$server`t" + $_.Exception.Message.ToString().Split(":")[1].Replace("`n","")
            "$server`t" + $_.Exception.Message.ToString().Split(":")[1].Replace("`n","") | Out-File -FilePath .\results.txt -Append
        }
    }
}

Function Remove_From_AdminGroup{

$msg = "Attempting in Admin Group"

$msg | Out-File -FilePath .\results.txt -Append

    foreach ($server in $servers){
        try{
            $adminGroup = [ADSI]"WinNT://$server/Administrator"
            $adminGroup.remove("WinNT://$server/$account")
            "$server`tSuccess"
            "$server`tSuccess" | Out-File -FilePath .\results.txt -Append
        }catch{
            "$server`t" + $_.Exception.Message.ToString().Split(":")[1].Replace("`n","")
            "$server`t" + $_.Exception.Message.ToString().Split(":")[1].Replace("`n","") | Out-File -FilePath .\results.txt -Append
        }
    }
}