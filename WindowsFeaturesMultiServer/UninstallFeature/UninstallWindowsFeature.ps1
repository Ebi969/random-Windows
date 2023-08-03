$exportPath = "D:\UserData\Ibraaheem\Scripts\WindowsFeaturesMultiServer\UninstallFeature"

$importList = Get-Content $exportPath\serverList.txt

$serverNames = @()
$serverNames = $importList.Replace(" ", "")

<# WindowsFeature Name #>
$featureName = "Windows-Defender-Features"

$multiRunspace = Invoke-Command -ComputerName $serverNames -ScriptBlock{
    Uninstall-WindowsFeature -Name $using:featureName
} | Export-Excel -Path $exportPath\Results.xlsx -AutoSize -Append