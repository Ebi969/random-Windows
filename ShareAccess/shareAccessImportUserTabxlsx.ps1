$importData = Import-Excel -Path "C:\Users\DA003089\Desktop\SoftwareFolderUsers2490.xlsx" -WorksheetName "Users"

foreach($line in $importData){
    
    $userID = $line.Users

    Try{
        $userName = Get-ADUser -Identity $userID -Properties DisplayName -ErrorAction Stop | select -ExpandProperty DisplayName
    }catch{        
        $userName = "User not Found in AD"
    }

    $outObject = [pscustomobject] @{

        UserID = $userID
        UserName = $userName

    } | Export-Excel -Path "D:\UserData\Ibraaheem\Scripts\ShareAccess\SRV002490ShareAccess.xlsx" -WorksheetName "SoftwareShare" -Append

}