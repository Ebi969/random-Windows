$cred = Get-Credential
$usercode = $cred.UserName
$userName = Get-ADUser -Identity $usercode -Properties DisplayName | Select-Object -ExpandProperty DisplayName

$logPath ="C:\Users\DA003089\Desktop\Scripts\RestartLog"
$path = "C:\Users\DA003089\Desktop\Scripts\Restart Machine"
$Server = "SRV005010"

#remove pre and post health checks that were already compiled
if(Test-Path $path\PostHealthCheck_$server.Csv){
    Remove-Item $path\PostHealthCheck_$server.Csv
}

if(Test-Path $path\PreHealthCheck_$server.Csv){
    Remove-Item $path\PreHealthCheck_$server.Csv
}

Function doStuff{
 
    Write-Host "Reboot of $Server initiated" -ForegroundColor Yellow

    Try{

        #Start reboot using valid credentials
        #Restart-Computer -ComputerName $Server -Credential $cred -Force -ErrorAction Stop

    }catch{
        Write-Host "Access denied using account $usercode"
        exit
    }
    
        #ping server till server is offline
        While(Test-Connection -ComputerName $Server -Quiet){
            Write-Host "Server $Server shutting down" 
        }

        #ping server till server is back online
        While(!(Test-Connection -ComputerName $Server -Quiet)){
            Write-Host "Server $Server powering up"
            Start-Sleep -Seconds 5
        }

    #create log file to state who initiated the reboot
    $msg = "Reboot of $Server was initiated by $usercode - $userName`n"

    $msg | Out-File -FilePath $logPath\log.txt -Append
    
    $checkTime = "Post Check"

    #Sleep for 30 seconds for server to stabilize before doing a post health check
    Start-Sleep -Seconds 30

    healthCheck

}

Function createGraph{

    if($option -eq "Reboot Machine"){
        if($checkTime -eq "Post Check"){
            $checkMsg = "Post"
        }else{
            $checkMsg = "Pre"
        }
    }else{
        $checkMsg = ""
    }

    Write-Host "Generating $checkMsg health check Graph..." -ForegroundColor Green
        $cpuGraphName = $checkMsg + " Cpu Usage_"
        $memGraphName = $checkMsg + " Mem Usage_"
        $checkMsg = $checkMsg + "HealthCheck_"

        for($i = 0; $i -lt $CPUArray.Length; $i++){
            $out = New-Object PSobject

            $out | Add-Member -MemberType NoteProperty -Name "Server" -Value $Server
            $out | Add-Member -MemberType NoteProperty -Name "CPU %" -Value $CPUArray[$i]
            $out | Add-Member -MemberType NoteProperty -Name "Mem %" -Value $MemArray[$i]

            $out | Export-Csv $path\$checkMsg$server.Csv -NoTypeInformation -Append
        }

        [void][Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
        [void][Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms.DataVisualization')

        $MemChart = New-Object -TypeName System.Windows.Forms.DataVisualization.Charting.Chart
        $MemChart.Size = '1000,500'
 
        $MemChartArea = New-Object -TypeName System.Windows.Forms.DataVisualization.Charting.ChartArea
        $MemChartArea.AxisX.LabelStyle.Enabled = $true
        $MemChartArea.AxisX.LabelStyle.Angle = 90
        $MemChart.ChartAreas.Add($MemChartArea)
        $MemChart.Series.Add('Memory')
        $MemChartArea.AxisY.Title = 'Percentage %'
        $MemChartArea.AxisX.Title = 'Period'
        $MemChart.Series['Memory'].ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Line

        foreach($mem in $MemArray){
            $Value = $MemChart.Series['Memory'].Points.AddY("$mem")
        }

        $Title = New-Object -TypeName System.Windows.Forms.DataVisualization.Charting.Title
        $MemChart.Titles.Add($Title)
        $MemChart.Titles[0].Text = "Memory usage ($Server)"
 
        #Saving PNG file on desktop
        $MemChart.SaveImage("$path\$memGraphName$Server.png", "PNG")
###############################################################################################################################################################
        $cpuChart = New-Object -TypeName System.Windows.Forms.DataVisualization.Charting.Chart
        $cpuChart.Size = '1000,500'
 
        $cpuChartArea = New-Object -TypeName System.Windows.Forms.DataVisualization.Charting.ChartArea
        $cpuChartArea.AxisX.LabelStyle.Enabled = $true
        $cpuChartArea.AxisX.LabelStyle.Angle = 90
        $cpuChart.ChartAreas.Add($cpuChartArea)
        $cpuChart.Series.Add('CPU')
        $cpuChartArea.AxisY.Title = 'Percentage %'
        $cpuChartArea.AxisX.Title = 'Period'
        $cpuChart.Series['CPU'].ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Line

        foreach($cpu in $cpuArray){
            $Value = $cpuChart.Series['CPU'].Points.AddY("$cpu")
        }

        $Title = New-Object -TypeName System.Windows.Forms.DataVisualization.Charting.Title
        $cpuChart.Titles.Add($Title)
        $cpuChart.Titles[0].Text = "CPU usage ($Server)"
 
        #Saving PNG file on desktop
        $cpuChart.SaveImage("$path\$cpuGraphName$Server.png", "PNG")

    if($option -eq "Reboot Machine"){
        if($checkTime -ne "Post Check"){
            #doStuff
        }
    }
}

Function healthCheck{

Write-Host "Initiating Health Check..." -ForegroundColor Green

$count = 0

$Global:CPUArray = @()
$Global:MemArray = @()

    while($count -lt 25){
        try{
            # CPU utilization
            $CPU = (Get-WmiObject -ComputerName $Server -Class win32_processor -ErrorAction Stop | Measure-Object -Property LoadPercentage -Average | Select-Object Average).Average
  
            # Memory utilization
            $ComputerMemory = Get-WmiObject -ComputerName $Server -Class win32_operatingsystem -ErrorAction Stop
            $Memory = ((($ComputerMemory.TotalVisibleMemorySize - $ComputerMemory.FreePhysicalMemory)*100)/ $ComputerMemory.TotalVisibleMemorySize)
            $RoundMemory = [math]::Round($Memory, 2)
            
        }catch{
            Write-Host "Ooops, we ran into a problem" -ForegroundColor Red
        }
        
            $Global:CPUArray += $CPU
            $Global:MemArray += $RoundMemory
                        
            $count += 1

    }

Write-Host "Health Check Successful" -ForegroundColor Green
    
            createGraph

}

$Global:option = "Reboot Machine"
$Global:checkTime = $null
healthCheck

