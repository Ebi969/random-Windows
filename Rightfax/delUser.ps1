$importData = Import-Excel -Path "D:\UserData\Ibraaheem\Scripts\Rightfax\Removal List.xlsx"

<#
$user = "G984006"
\\SRV004542\D$\Rightfax\AdminUtils\chguser.exe -fsrv004542 -ladministrator -osnl@efm -x -u"$user"
#>

foreach($user in $importData."User ID"){

    $userNoSpaces = $user.Replace(" ","")

    \\SRV004542\D$\Rightfax\AdminUtils\chguser.exe -fsrv004542 -ladministrator -osnl@efm -x -u"$userNoSpaces"

}
