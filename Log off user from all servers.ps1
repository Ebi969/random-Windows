#The username to check against each server
$Username = "User.Name"

#Output file
	$csvOutput = 'd:\nasser\whereisloggedon.csv'
		#Deletes the output file if it exists
			If (Test-Path $csvOutput){
				Remove-Item $csvOutput
			}
		#Add the first line to the CSV file
		Add-Content -Path $csvOutput -Value "Hostname,SessionID"

#Get all Servers' names in the Domain that are not enabled.
$serverList=(Get-ADComputer -Filter ('(OperatingSystem -Like "*SERVER*") -AND (Enabled -Eq "True")') | select-object Name).Name

#Start a foreach cycle which will go through each Server in the ServerList
foreach ($Server in $serverList)
	{
		#Ping the Server
		$ping = Test-Connection $Server -Count 1 -EA Silentlycontinue

		#If Ping is successfull then keep going
		if($ping)
		{
			#Get server session ID if $username is logged on - cmd /c is needed for the 2>NUL to avoid quser to write "No User exists for *" when nobody is logged on a server.
			$sessionID = ((cmd /c quser /server:$server "2>NUL"| ? { $_ -match $username }) -split ' +')[2]
			
			#If sessionsID exists, write it to console and to the output file but exclude any live RDP connection or console (ie: rdp-tcp#1)
				If ($sessionID -AND $sessionID -NotLike "*rdp*" -AND $sessionID -ne "console")
				{
					#Write to console
					Write-Host "$($Username) is logged on $($Server) with ID: $($sessionID). The script will attempt to logoff the user."
					#Log off the user
					logoff $SessionID /server:$Server
					#Write into $csvOutput
						Add-Content -Path $csvOutput -Value "$($Server),$($sessionID)"
				}
		}
	}