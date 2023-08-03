# Config File Path for multi features

#$ConfigurationFilepath = "D:\UserData\Ibraaheem\Scripts\WindowsFeaturesMultiServer\InstallFeature"
#-ConfigurationFilepath $using:ConfigurationFilepath
$exportPath = "D:\UserData\Ibraaheem\Scripts\WindowsFeaturesMultiServer\InstallFeature"
$serverNames = @("srv005474", "srv005475")

function Invoke-WindowsFeatureBatchDeployment {  
    param (  
        [parameter(mandatory)]  
        [string[]] $serverNames  
        #[parameter(mandatory)]  
        #[string] $ConfigurationFilepath  
    )  

    # Deploy the features on multiple computers simultaneously.  
    $jobs = @()  

    foreach($server in $serverNames) {  
        $jobs += start-Job -Command {  
            Install-WindowsFeature -Name "Windows-Defender-Features" -computerName $using:server 
        }   
    }  

    #$output = Receive-Job -Job $jobs -Wait | select-Object PSComputerName, Success, RestartNeeded, exitCode, FeatureResult 
    $output = Receive-Job -Job $jobs -Wait | Select *
    $output
    $output | Export-Excel -Path $exportPath\results.xlsx
} 

Invoke-WindowsFeatureBatchDeployment -serverNames $serverNames