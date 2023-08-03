# =====================================================================
# setting up some variables that are utilised throughout the script run
# =====================================================================
# getting the name of the server that the script is running on (used in the names of the files)
$computer=$env:computername

# getting the date and time into a usable format (used in the names of the files)
$timestamp=Get-Date -Format s | foreach {$_ -replace "-", ""} | foreach {$_ -replace "T", "_"} | foreach {$_ -replace ":",""} 

# getting the path that the script was run from, this is used to write the output files to the same directory
$currentpath = "C:\Users\DA003089\Desktop\Scripts\Compliance Check"

# setting up the prefix for the final output files
$fileprefix=$currentpath + "\" + $computer + "_" + $timestamp 

# defining the names of the final output files to be utilised
$scriptversionfile=$fileprefix + "_ScriptVersion.txt"
$versionfile=$fileprefix + "_Version.txt"
$regfile=$fileprefix + "_RegTest.txt"
$regfilecsv=$fileprefix + "_RegTest.csv"
$advauditpolicyfile=$fileprefix + "_AdvAuditPolicy.txt"
$seceditfile=$fileprefix + "_SecEdit.txt"
$userrightsfile=$fileprefix + "_UserRights.txt"
$auditpolfile=$fileprefix + "_AuditPolicy.txt"


"[Registry Settings]" | Out-File $regfile -Append

	$theregkey="HKLM\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name LimitBlankPasswordUse -EA SilentlyContinue).LimitBlankPasswordUse
	$theregkey + ":" + $regkey  | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Control\Lsa\AuditBaseObjects"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name AuditBaseObjects -EA SilentlyContinue).AuditBaseObjects
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Control\Lsa\FullPrivilegeAuditing"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name FullPrivilegeAuditing -EA SilentlyContinue).FullPrivilegeAuditing
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name SCENoApplyLegacyAuditPolicy -EA SilentlyContinue).SCENoApplyLegacyAuditPolicy
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name CrashOnAuditFail -EA SilentlyContinue).CrashOnAuditFail
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\UndockWithoutLogon"	
	$regkey=(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name UndockWithoutLogon -EA SilentlyContinue).UndockWithoutLogon
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AllocateDASD -EA SilentlyContinue).AllocateDASD
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers"	
	$regkey=(Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" -Name AddPrinterDrivers -EA SilentlyContinue).AddPrinterDrivers
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateCDRoms"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AllocateCDRoms -EA SilentlyContinue).AllocateCDRoms
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateFloppies"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AllocateFloppies -EA SilentlyContinue).AllocateFloppies
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters -Name RequireSignOrSeal -EA SilentlyContinue).RequireSignOrSeal
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters -Name SealSecureChannel -EA SilentlyContinue).SealSecureChannel
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters -Name SignSecureChannel -EA SilentlyContinue).SignSecureChannel
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters -Name DisablePasswordChange -EA SilentlyContinue).DisablePasswordChange
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters -Name MaximumPasswordAge -EA SilentlyContinue).MaximumPasswordAge
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters -Name RequireStrongKey -EA SilentlyContinue).RequireStrongKey
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName"	
	$regkey=(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name DontDisplayLastUserName -EA SilentlyContinue).DontDisplayLastUserName
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD"	
	$regkey=(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableCAD -EA SilentlyContinue).DisableCAD 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name CachedLogonsCount -EA SilentlyContinue).CachedLogonsCount 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name PasswordExpiryWarning -EA SilentlyContinue).PasswordExpiryWarning 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name ForceUnlockLogon -EA SilentlyContinue).ForceUnlockLogon 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name ScRemoveOption -EA SilentlyContinue).ScRemoveOption 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters -Name RequireSecuritySignature -EA SilentlyContinue).RequireSecuritySignature 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters -Name EnableSecuritySignature -EA SilentlyContinue).EnableSecuritySignature 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters -Name EnablePlainTextPassword -EA SilentlyContinue).EnablePlainTextPassword 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters -Name AutoDisconnect -EA SilentlyContinue).AutoDisconnect 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters -Name RequireSecuritySignature -EA SilentlyContinue).RequireSecuritySignature 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters -Name EnableSecuritySignature -EA SilentlyContinue).EnableSecuritySignature 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters -Name EnableForcedLogOff -EA SilentlyContinue).EnableForcedLogOff 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -EA SilentlyContinue).AutoAdminLogon 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Control\CrashControl\AutoReboot"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Control\CrashControl -Name AutoReboot -EA SilentlyContinue).AutoReboot 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\AutoShareServer"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters -Name AutoShareServer -EA SilentlyContinue).AutoShareServer 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting"
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters -Name DisableIPSourceRouting -EA SilentlyContinue).DisableIPSourceRouting 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters -Name DisableIPSourceRouting -EA SilentlyContinue).DisableIPSourceRouting 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters -Name EnableICMPRedirect -EA SilentlyContinue).EnableICMPRedirect 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\Lanmanserver\Parameters\Hidden"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\Lanmanserver\Parameters -Name Hidden -EA SilentlyContinue).Hidden 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters -Name KeepAliveTime -EA SilentlyContinue).KeepAliveTime 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\IPSEC\NoDefaultExempt"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\IPSEC -Name NoDefaultExempt -EA SilentlyContinue).NoDefaultExempt 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\Netbt\Parameters -Name NoNameReleaseOnDemand -EA SilentlyContinue).NoNameReleaseOnDemand 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Control\FileSystem\NtfsDisable8dot3NameCreation"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Control\FileSystem -Name NtfsDisable8dot3NameCreation -EA SilentlyContinue).NtfsDisable8dot3NameCreation 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\PerformRouterDiscovery"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters -Name PerformRouterDiscovery -EA SilentlyContinue).PerformRouterDiscovery 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode"	
	$regkey=(Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Session Manager" -Name SafeDllSearchMode -EA SilentlyContinue).SafeDllSearchMode 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScreenSaverGracePeriod"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name ScreenSaverGracePeriod -EA SilentlyContinue).ScreenSaverGracePeriod 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters\TcpMaxDataRetransmissions"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters -Name TcpMaxDataRetransmissions -EA SilentlyContinue).TcpMaxDataRetransmissions 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxDataRetransmissions"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters -Name TcpMaxDataRetransmissions -EA SilentlyContinue).TcpMaxDataRetransmissions 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Control\Lsa\RestrictAnonymous"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name RestrictAnonymous -EA SilentlyContinue).RestrictAnonymous 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name RestrictAnonymousSAM -EA SilentlyContinue).RestrictAnonymousSAM 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Control\Lsa\DisableDomainCreds"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name DisableDomainCreds -EA SilentlyContinue).DisableDomainCreds 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name EveryoneIncludesAnonymous -EA SilentlyContinue).EveryoneIncludesAnonymous 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters -Name NullSessionShares -EA SilentlyContinue).NullSessionShares 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Control\Lsa\ForceGuest"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name ForceGuest -EA SilentlyContinue).ForceGuest 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Control\Lsa\NoLMHash"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name NoLMHash -EA SilentlyContinue).NoLMHash 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name LmCompatibilityLevel -EA SilentlyContinue).LmCompatibilityLevel 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\LDAP -Name LDAPClientIntegrity -EA SilentlyContinue).LDAPClientIntegrity 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0 -Name NTLMMinClientSec -EA SilentlyContinue).NTLMMinClientSec 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" -Name SecurityLevel -EA SilentlyContinue).SecurityLevel 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SetCommand"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" -Name SetCommand -EA SilentlyContinue).SetCommand 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon"	
	$regkey=(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ShutdownWithoutLogon -EA SilentlyContinue).ShutdownWithoutLogon 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\ClearPageFileAtShutdown"	
	$regkey=(Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -Name ClearPageFileAtShutdown -EA SilentlyContinue).ClearPageFileAtShutdown 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\Cryptography\ForceKeyProtection"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\Cryptography -Name ForceKeyProtection -EA SilentlyContinue).ForceKeyProtection 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy -Name Enabled -EA SilentlyContinue).Enabled 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive"	
	$regkey=(Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Session Manager\Kernel" -Name ObCaseInsensitive -EA SilentlyContinue).ObCaseInsensitive 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Control\Session Manager\ProtectionMode"	
	$regkey=(Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Session Manager" -Name ProtectionMode -EA SilentlyContinue).ProtectionMode 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Control\Session Manager\SubSystems\optional"	
	$regkey=(Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Session Manager\SubSystems" -Name optional -EA SilentlyContinue).optional 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\AuthenticodeEnabled"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers -Name AuthenticodeEnabled -EA SilentlyContinue).AuthenticodeEnabled 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken"	
	$regkey=(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name FilterAdministratorToken -EA SilentlyContinue).FilterAdministratorToken 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle"	
	$regkey=(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableUIADesktopToggle -EA SilentlyContinue).EnableUIADesktopToggle 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin"	
	$regkey=(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -EA SilentlyContinue).ConsentPromptBehaviorAdmin 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser"	
	$regkey=(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorUser -EA SilentlyContinue).ConsentPromptBehaviorUser 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection"	
	$regkey=(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableInstallerDetection -EA SilentlyContinue).EnableInstallerDetection 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures"	
	$regkey=(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ValidateAdminCodeSignatures -EA SilentlyContinue).ValidateAdminCodeSignatures 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths"	
	$regkey=(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableSecureUIAPaths -EA SilentlyContinue).EnableSecureUIAPaths 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA"	
	$regkey=(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -EA SilentlyContinue).EnableLUA 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop"	
	$regkey=(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name PromptOnSecureDesktop -EA SilentlyContinue).PromptOnSecureDesktop 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization"	
	$regkey=(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableVirtualization -EA SilentlyContinue).EnableVirtualization 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun"	
	$regkey=(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoDriveTypeAutoRun -EA SilentlyContinue).NoDriveTypeAutoRun 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun"	
	$regkey=(Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoDriveTypeAutoRun -EA SilentlyContinue).NoDriveTypeAutoRun 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators"	
	$regkey=(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI -Name EnumerateAdministrators -EA SilentlyContinue).EnumerateAdministrators 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions\NoUpdateCheck"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions" -Name NoUpdateCheck -EA SilentlyContinue).NoUpdateCheck
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ProxySettingsPerUser"
	$regkey=(Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxySettingsPerUser -EA SilentlyContinue).ProxySettingsPerUser 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Security_HKLM_only"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name Security_HKLM_only -EA SilentlyContinue).Security_HKLM_only 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\Conferencing\NoRDS"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\Conferencing -Name NoRDS -EA SilentlyContinue).NoRDS 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name fPromptForPassword -EA SilentlyContinue).fPromptForPassword 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\Windows NT\Reliability\ShutdownReasonOn"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Reliability" -Name ShutdownReasonOn -EA SilentlyContinue).ShutdownReasonOn 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\Windows NT\Reliability\ShutdownReasonUI"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Reliability" -Name ShutdownReasonUI -EA SilentlyContinue).ShutdownReasonUI
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name fDisableCdm -EA SilentlyContinue).fDisableCdm 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name DisablePasswordSaving -EA SilentlyContinue).DisablePasswordSaving 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name MinEncryptionLevel -EA SilentlyContinue).MinEncryptionLevel 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -EA SilentlyContinue).AlwaysInstallElevated 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name NoBackgroundPolicy -EA SilentlyContinue).NoBackgroundPolicy 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name NoGPOListChanges -EA SilentlyContinue).NoGPOListChanges 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name DisableWebPnPDownload -EA SilentlyContinue).DisableWebPnPDownload 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoWebServices"	
	$regkey=(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoWebServices -EA SilentlyContinue).NoWebServices 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name DisableHTTPPrinting -EA SilentlyContinue).DisableHTTPPrinting 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\SearchCompanion\DisableContentFileUpdates"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\SearchCompanion -Name DisableContentFileUpdates -EA SilentlyContinue).DisableContentFileUpdates 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoPublishingWizard"	
	$regkey=(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoPublishingWizard -EA SilentlyContinue).NoPublishingWizard 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\Messenger\Client\CEIP"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\Messenger\Client -Name CEIP -EA SilentlyContinue).CEIP 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\SQMClient\Windows\CEIPEnable"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\SQMClient\Windows -Name CEIPEnable -EA SilentlyContinue).CEIPEnable 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\Windows\DriverSearching\DontSearchWindowsUpdate"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\DriverSearching -Name DontSearchWindowsUpdate -EA SilentlyContinue).DontSearchWindowsUpdate 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisableLocalMachineRun"	
	$regkey=(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name DisableLocalMachineRun -EA SilentlyContinue).DisableLocalMachineRun 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisableLocalMachineRunOnce"	
	$regkey=(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name DisableLocalMachineRunOnce -EA SilentlyContinue).DisableLocalMachineRunOnce 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp"	
	$regkey=(Get-ItemProperty "HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services" -Name fAllowToGetHelp -EA SilentlyContinue).fAllowToGetHelp 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicited"	
	$regkey=(Get-ItemProperty "HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services" -Name fAllowUnsolicited -EA SilentlyContinue).fAllowUnsolicited 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc" -Name RestrictRemoteClients -EA SilentlyContinue).RestrictRemoteClients 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop\ScreenSaveActive"	
	$regkey=(Get-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name ScreenSaveActive -EA SilentlyContinue).ScreenSaveActive 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop\SCRNSAVE.EXE"	
	$regkey=(Get-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "SCRNSAVE.EXE" -EA SilentlyContinue)."SCRNSAVE.EXE"
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop\ScreenSaveTimeOut"	
	$regkey=(Get-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name ScreenSaveTimeOut -EA SilentlyContinue).ScreenSaveTimeOut 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Windows\CurrentVersion\Policies\System" -Name InactivityTimeoutSecs -EA SilentlyContinue).InactivityTimeoutSecs 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append	
	$theregkey="HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\EnableDeadGWDetect"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters -Name EnableDeadGWDetect -EA SilentlyContinue).EnableDeadGWDetect
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\SynAttackProtect"
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters -Name SynAttackProtect -EA SilentlyContinue).SynAttackProtect 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxConnectResponseRetransmissions"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters -Name TcpMaxConnectResponseRetransmissions -EA SilentlyContinue).TcpMaxConnectResponseRetransmissions 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxPortsExhausted"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters -Name TcpMaxPortsExhausted -EA SilentlyContinue).TcpMaxPortsExhausted 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Driver Signing\Policy"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Microsoft\Driver Signing" -Name Policy -EA SilentlyContinue).Policy 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Control\Lsa\NoDefaultAdminOwner"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name NoDefaultAdminOwner -EA SilentlyContinue).NoDefaultAdminOwner 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\RasMan\Parameters\DisableSavePassword"
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\RasMan\Parameters -Name DisableSavePassword -EA SilentlyContinue).DisableSavePassword 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\EnablePMTUDiscovery"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters -Name EnablePMTUDiscovery -EA SilentlyContinue).EnablePMTUDiscovery 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions\NoSplash"
	$regkey=(Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions" -Name NoSplash -EA SilentlyContinue).NoSplash
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoMSAppLogo5ChannelNotify"
	$regkey=(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoMSAppLogo5ChannelNotify -EA SilentlyContinue).NoMSAppLogo5ChannelNotify
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnableSecureCredentialPrompting"
	$regkey=(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI -Name EnableSecureCredentialPrompting -EA SilentlyContinue).EnableSecureCredentialPrompting
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec"
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0 -Name NTLMMinServerSec -EA SilentlyContinue).NTLMMinServerSec
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\PolicyVersion"
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall -Name PolicyVersion -EA SilentlyContinue).PolicyVersion
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters -Name RestrictNullSessAccess -EA SilentlyContinue).RestrictNullSessAccess 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\Windows NT\Rpc\EnableAuthEpResolution"	
	$regkey=(Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc" -Name EnableAuthEpResolution -EA SilentlyContinue).EnableAuthEpResolution 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	
	# Remotely accessible registry paths and sub-paths registry settings
	" " | Out-File $regfile -Append
	"[Registry Paths]" | Out-File $regfile -Append	
	$theregkey="HKLM\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths -Name Machine -EA SilentlyContinue).Machine 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	" " | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths -Name Machine -EA SilentlyContinue).Machine 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
		
	# Event log registry settings
	" " | Out-File $regfile -Append
	"[Event log settings]" | Out-File $regfile -Append	
	$theregkey="HKLM\System\CurrentControlSet\Services\Eventlog\Security\WarningLevel"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\Eventlog\Security -Name WarningLevel -EA SilentlyContinue).WarningLevel 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\EventLog\System\Retention"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\EventLog\System -Name Retention -EA SilentlyContinue).Retention 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\EventLog\Application\Retention"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\EventLog\Application -Name Retention -EA SilentlyContinue).Retention 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\EventLog\Security\Retention"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\EventLog\Security -Name Retention -EA SilentlyContinue).Retention 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\EventLog\System\MaxSize"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\EventLog\System -Name MaxSize -EA SilentlyContinue).MaxSize 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\EventLog\Application\MaxSize"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\EventLog\Application -Name MaxSize -EA SilentlyContinue).MaxSize 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\System\CurrentControlSet\Services\EventLog\Security\MaxSize"	
	$regkey=(Get-ItemProperty HKLM:\System\CurrentControlSet\Services\EventLog\Security -Name MaxSize -EA SilentlyContinue).MaxSize 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append	
	
	# Windows firewall settings
	" " | Out-File $regfile -Append
	"[Firewall Settings]" | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableUnicastResponsesToMulticastBroadcast"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile -Name DisableUnicastResponsesToMulticastBroadcast -EA SilentlyContinue).DisableUnicastResponsesToMulticastBroadcast 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\AllowLocalIPsecPolicyMerge"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile -Name AllowLocalIPsecPolicyMerge -EA SilentlyContinue).AllowLocalIPsecPolicyMerge 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\AllowLocalPolicyMerge"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile -Name AllowLocalPolicyMerge -EA SilentlyContinue).AllowLocalPolicyMerge 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableNotifications"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile -Name DisableNotifications -EA SilentlyContinue).DisableNotifications 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile -Name EnableFirewall -EA SilentlyContinue).EnableFirewall 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultInboundAction"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile -Name DefaultInboundAction -EA SilentlyContinue).DefaultInboundAction 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile -Name DefaultOutboundAction -EA SilentlyContinue).DefaultOutboundAction 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\DisableUnicastResponsesToMulticastBroadcast"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile -Name DisableUnicastResponsesToMulticastBroadcast -EA SilentlyContinue).DisableUnicastResponsesToMulticastBroadcast 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\AllowLocalIPsecPolicyMerge"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile -Name AllowLocalIPsecPolicyMerge -EA SilentlyContinue).AllowLocalIPsecPolicyMerge 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\AllowLocalPolicyMerge"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile -Name AllowLocalPolicyMerge -EA SilentlyContinue).AllowLocalPolicyMerge 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\DisableNotifications"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile -Name DisableNotifications -EA SilentlyContinue).DisableNotifications 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\EnableFirewall"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile -Name EnableFirewall -EA SilentlyContinue).EnableFirewall 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultInboundAction"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile -Name DefaultInboundAction -EA SilentlyContinue).DefaultInboundAction 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultOutboundAction"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile -Name DefaultOutboundAction -EA SilentlyContinue).DefaultOutboundAction 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\DisableUnicastResponsesToMulticastBroadcast"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile -Name DisableUnicastResponsesToMulticastBroadcast -EA SilentlyContinue).DisableUnicastResponsesToMulticastBroadcast 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalIPsecPolicyMerge"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile -Name AllowLocalIPsecPolicyMerge -EA SilentlyContinue).AllowLocalIPsecPolicyMerge 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalPolicyMerge"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile -Name AllowLocalPolicyMerge -EA SilentlyContinue).AllowLocalPolicyMerge 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\DisableNotifications"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile -Name DisableNotifications -EA SilentlyContinue).DisableNotifications 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\EnableFirewall"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile -Name EnableFirewall -EA SilentlyContinue).EnableFirewall 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultInboundAction"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile -Name DefaultInboundAction -EA SilentlyContinue).DefaultInboundAction 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultOutboundAction"	
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile -Name DefaultOutboundAction -EA SilentlyContinue).DefaultOutboundAction 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogDroppedPackets"
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging -Name LogDroppedPackets -EA SilentlyContinue).LogDroppedPackets
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogSuccessfulConnections"
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging -Name LogSuccessfulConnections -EA SilentlyContinue).LogSuccessfulConnections
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFilePath"
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging -Name LogFilePath -EA SilentlyContinue).LogFilePath
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFileSize"
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging -Name LogFileSize -EA SilentlyContinue).LogFileSize
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogDroppedPackets"
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging -Name LogDroppedPackets -EA SilentlyContinue).LogDroppedPackets
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogSuccessfulConnections"
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging -Name LogSuccessfulConnections -EA SilentlyContinue).LogSuccessfulConnections
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogFilePath"
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging -Name LogFilePath -EA SilentlyContinue).LogFilePath
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogFileSize"
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging -Name LogFileSize -EA SilentlyContinue).LogFileSize
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogDroppedPackets"
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging -Name LogDroppedPackets -EA SilentlyContinue).LogDroppedPackets
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogSuccessfulConnections"
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging -Name LogSuccessfulConnections -EA SilentlyContinue).LogSuccessfulConnections
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFilePath"
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging -Name LogFilePath -EA SilentlyContinue).LogFilePath
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFileSize"
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging -Name LogFileSize -EA SilentlyContinue).LogFileSize
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\DoNotAllowExceptions"
	$regkey=(Get-ItemProperty HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile -Name DoNotAllowExceptions -EA SilentlyContinue).DoNotAllowExceptions
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	
	# Legal warning registry keys
	" " | Out-File $regfile -Append
	"[Legal warning]" | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText"	
	$regkey=(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name LegalNoticeText -EA SilentlyContinue).LegalNoticeText 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	$theregkey="HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption"	
	$regkey=(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name LegalNoticeCaption -EA SilentlyContinue).LegalNoticeCaption 	
	$theregkey + ":" + $regkey | Out-File $regfile -Append
	
	" " | Out-File $regfile -Append
	"===================================================================================================" | Out-File $regfile -Append








#Grab the text file
$textFile = Get-Content 'C:\Users\DA003089\Desktop\Scripts\Compliance Check\*RegTest.txt'

#Loop through each line and assign everything produced in the
$result = foreach ($line in $textFile) {
    
    if($line.contains("\")){
        #Split the line into an array using space as a delimiter
        $array = $line -Split ":"
        #Create a new object to return to $result and define the what each "column" would be assigned to
        New-Object -TypeName PSObject -Property @{"Registry"=$array[0]; "Value"=$array[1]}
    }
}

#Export the object to a CSV
$result | Export-CSV $regfilecsv -NoTypeInformation