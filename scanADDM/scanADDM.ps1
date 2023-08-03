$latestADDMextract = (Get-ChildItem -Path "\\srv003789\ADDMReports" | Sort CreationTime | Select -Last 1)
$importFile = "\\srv003789\ADDMReports\" + $latestADDMextract
$importData = Import-CSV $importFile

$importBDC = Import-Excel -Path "D:\UserData\Ibraaheem\Scripts\scanADDM\importList.xlsx" -WorksheetName "BDC"
$importCDC = Import-Excel -Path "D:\UserData\Ibraaheem\Scripts\scanADDM\importList.xlsx" -WorksheetName "CDC"

foreach($row in $importBDC){

    $vmName = $row.Name

    foreach($item in $importData){


        if($item.Name -like "*$vmName*"){

            if($item.serverdescription -like "*SQL*" -or $item.application -like "*SQL*"){

                $vmName
                $item.serverdescription
                $item.application

                $output = [pscustomobject] @{
                    Name = $vmName
                    NumCpu = $row.NumCpu
                    Mem = $row.Mem
                    Storage = $row.Storage
                    Description = $item.serverdescription
                    Application = $item.application
                } | Export-Excel -Path "D:\UserData\Ibraaheem\Scripts\scanADDM\export.xlsx" -WorksheetName "BDC" -Append -AutoFilter -BoldTopRow -AutoSize

            }<#else{
                    $output = [pscustomobject] @{
                    Name = $vmName
                    NumCpu = $row.NumCpu
                    Mem = $row.Mem
                    Storage = $row.Storage
                    Description = "Not SQL"
                    Application = "Not SQL"
                } | Export-Excel -Path "D:\UserData\Ibraaheem\Scripts\scanADDM\export.xlsx" -WorksheetName "CDC" -Append -AutoFilter -BoldTopRow -AutoSize
            }#>

        }

    }
}

foreach($row in $importCDC){

    $vmName = $row.Name

    foreach($item in $importData){


        if($item.Name -like "*$vmName*"){

            if($item.serverdescription -like "*SQL*" -or $item.application -like "*SQL*"){

                $vmName
                $item.serverdescription
                $item.application

                $output = [pscustomobject] @{
                    Name = $vmName
                    NumCpu = $row.NumCpu
                    Mem = $row.Mem
                    Storage = $row.Storage
                    Description = $item.serverdescription
                    Application = $item.application
                } | Export-Excel -Path "D:\UserData\Ibraaheem\Scripts\scanADDM\export.xlsx" -WorksheetName "CDC" -Append -AutoFilter -BoldTopRow -AutoSize

            }<#else{
                    $output = [pscustomobject] @{
                    Name = $vmName
                    NumCpu = $row.NumCpu
                    Mem = $row.Mem
                    Storage = $row.Storage
                    Description = "Not SQL"
                    Application = "Not SQL"
                } | Export-Excel -Path "D:\UserData\Ibraaheem\Scripts\scanADDM\export.xlsx" -WorksheetName "CDC" -Append -AutoFilter -BoldTopRow -AutoSize
            }#>

        }

    }
}