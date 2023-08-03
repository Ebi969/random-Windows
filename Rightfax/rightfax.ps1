$users = Get-Content "D:\UserData\Ibraaheem\Scripts\Rightfax\userList.txt"
#$users = @("G985965")


function createRightFax{
    foreach($userid in $users){
        $email = $null
        $email = Get-ADUser -Identity $userid -Properties EmailAddress | Select -ExpandProperty EmailAddress

        $output = "Right-Fax: account has been created successfully (" + $userid + " - " + $email + ") routing code - " + $routingCode + " Cost - "

        $output
    }
}

function removeRightFax{

    foreach($userid in $users){
    
        $name = Get-ADUser -Identity $userid -Properties DisplayName | Select -ExpandProperty DisplayName

        $output = "Right-Fax: User (" + $userid + " - " + $name + ") has been removed successfully."

        $output
    }
}