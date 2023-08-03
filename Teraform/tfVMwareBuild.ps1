$buildData = Get-content -Raw -Path 'D:\UserData\Ibraaheem\Scripts\Teraform\Test.json' | ConvertFrom-Json
#$buildData = Get-content -Raw -Path 'D:\UserData\Ibraaheem\Scripts\Teraform\TestSuccess.json' | ConvertFrom-Json

Function DataChecks{
param(
    $vmData
)
    $vmData = $buildData
    $serverName = $vmData.requested.hostname
    $targetCluster = $vmData.data.cluster
    $targetEPG = $vmData.data.epg_string
    $template = $vmData.data.vm_template
    $vmfolder = $vmData.data.vmFolder
    $vCpu = $vmData.requested.vcpus
    $vMem = $vmData.requested.vram
    $osDatastore = ""
    $tier2status = $vmData.data.t2storage_ok
    $tier2disks = $vmData.data.t2storage_disks
    $tier2datastore = $vmData.data.t2_datastore
    $tier3status = $vmData.data.t3storage_ok
    $tier3disks = $vmData.data.t3storage_disks
    $tier3datastore = $vmData.data.t3_datastore

    if($tier2disks){
        $priDatastore = $tier2datastore
    }else{
        $priDatastore = $tier3datastore
    }


    $computeSpecs = [pscustomobject] @{
        ServerName = $serverName
        vmCluster = $targetCluster
        vmHost = ""
        Template = $template
        Folder = $vmfolder
        EPG = $targetEPG
        vcpu = $vCpu
        vmem = $vMem
    }

    $storageSpecs = [pscustomobject] @{
        osDatastore = $priDatastore
        tier2Datastore = $tier2datastore
        tier2Disks = $tier2disks
        tier3Datastore = $tier3datastore
        tier3Disks = $tier3disks
    }

    BuildVM -buildSpecs $computeSpecs -storageSpecs $storageSpecs

}

Function BuildVM{
param(

 $buildSpecs,
 $diskSpecs

)
    $buildSpecs = $computeSpecs
    $diskSpecs = $storageSpecs

    $vmName = $buildSpecs.ServerName
    $vmHost = (Get-Cluster $buildSpecs.vmCluster | Get-VMHost | Where{$_.Name -match "001"}) | Get-Random
    $vmTemplate = $buildSpecs.Template
    $vmFolder = $buildSpecs.Folder
    $vmEPG = $buildSpecs.EPG
    $vCPU = $buildSpecs.vcpu
    $vMem = $buildSpecs.vmem
    $vmOSDatastore = $diskSpecs.osDatastore
    $vmTier2Datastore = $diskSpecs.tier2Datastore
    $vmTier2Disks = $diskSpecs.tier2Disks
    $vmTier3Datastore = $diskSpecs.tier3Datastore
    $vmTier3Disks = $diskSpecs.tier3Disks

    $vm = New-VM -Name $vmName -VMHost $vmHost -Template $vmTemplate -Datastore $vmOSDatastore -Location $vmFolder

    $vm | Set-VM -MemoryGB $vMem -NumCpu $vCPU -CoresPerSocket $vCPU -Confirm:$false
    $vm | Get-NetworkAdapter | Set-NetworkAdapter -NetworkName $vmEPG -Confirm:$false

    foreach($t2Disk in $vmTier2Disks){
        $vm | New-HardDisk -Datastore $vmTier2Datastore -CapacityGB $t2Disk -StorageFormat Thick 
    }

    foreach($t3Disk in $vmTier3Disks){
        $vm | New-HardDisk -Datastore $vmTier3Datastore -CapacityGB $t3Disk -StorageFormat Thick 
    }

}

Function ErrorHandling{
param(
    $error
)



}