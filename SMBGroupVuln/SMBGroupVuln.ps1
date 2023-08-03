$serverList = Get-content "D:\UserData\Ibraaheem\Scripts\SMBGroupVuln\ServerList.txt"
$outputPath = "D:\UserData\Ibraaheem\Scripts\SMBGroupVuln"
foreach($serverIN in $serverList){
$server = $serverIN.replace(" ", "")
    $server
    Try{
        $groupList = Get-ADComputer -Identity $server -ErrorAction Stop | Get-AdPrincipalGroupMembership | Select -ExpandProperty Name
        $inSMB = $null

        if($groupList -match "CG-SPFBEL01A-SMB_Signing_Vulnerability"){
            $inSMB = $true
        }else{
            $inSMB = $false
        }
            $output = [pscustomobject] @{
                "Server" = $server
                "AllGroups" = $groupList -join ", "
                "inSMBGroup" = $inSMB
            }
        $output | Export-Excel -path $outputPath\SMBGroup.xlsx -WorksheetName "SMBInfoList" -Append -AutoFilter 
    }catch{
        $comment = "Not in AD"
            $output = [pscustomobject] @{
                "Server" = $server
                "Comment" = $comment
            }        
        $output | Export-Excel -path $outputPath\SMBGroup.xlsx -WorksheetName "NotInAD" -Append -AutoFilter 
    }
}