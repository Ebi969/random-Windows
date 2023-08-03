$outputPath = "D:\UserData\Ibraaheem\Scripts\UserLoggedOnWhere\loggedOnServers.csv"

Function Get-Username {
$Global:Username = Read-Host "Enter username you want to search for"
if ($Username -eq $null){
	Write-Host "Username cannot be blank, please re-enter username!!!!!"
	Get-Username}
$UserCheck = Get-ADUser -Identity $Username
if ($UserCheck -eq $null){
	Write-Host "Invalid username, please verify this is the logon id for the account"
	Get-Username}
}

get-username

$computerObjects = Get-ADComputer -Filter * | where {$_.Enabled -eq $true} 
foreach ($comp in $computerObjects){
	$server = $comp.Name
	$ping = new-object System.Net.NetworkInformation.Ping
  	$Reply = $null
  	$Reply = $ping.send($server)
  	if($Reply.status -like 'Success'){

		$proc = gwmi win32_process -computer $server -Filter "Name = 'explorer.exe'"

		ForEach ($p in $proc) {
	    	$temp = ($p.GetOwner()).User
	  		if ($temp -eq $Username){
                $Username + " is logged on $server"
			    $exportThis = [pscustomobject] @{
                    "Username" = $Username
                    "loggedOnHere" = $server
                }
                $exportThis | Export-CSV -Path $outputPath -Append
		    }
        }
    }
}
