Get-Folder -Type VM -Name "VMware" | Get-VM | where { $_.Name -match "VRA"} | Get-VMGuest | % {

    $name = $_.VM
    $ip  = $_.IPaddress[0]

    $item = New-Object PSObject -Property @{
    
        NOME = $name 
        IP = $ip
    }
   $item
   
} | select NOME,IP

##Write-Host "$NOME"  -ForegroundColor DarkGreen


$ipgt = @("10.188.31.222","10.188.31.220","10.188.31.219","10.188.31.221","10.188.31.218","10.188.31.217")
function get-elastictb {
$iptb = @("10.189.24.205","10.189.16.210","10.189.24.201","10.189.16.208","10.189.24.203","10.189.16.207")

    foreach ( $servers in $iptb){

    #$ipgt = @("10.188.31.222","10.188.31.220","10.188.31.219","10.188.31.221","10.188.31.218","10.188.31.217")

        get-datacenter -name tambore | Get-VM | where { $_.Guest.IPAddress -match "$servers" } | Get-HardDisk | select Parent,CapacityGB
        
    }
}

function get-elasticgt {
$ipgt = @("10.188.31.222","10.188.31.220","10.188.31.219","10.188.31.221","10.188.31.218","10.188.31.217")

    foreach ( $servers in $ipgt){

    #$ipgt = @("10.188.31.222","10.188.31.220","10.188.31.219","10.188.31.221","10.188.31.218","10.188.31.217")

        get-datacenter -name Glete | Get-VM | where { $_.Guest.IPAddress -match "$servers" } | Get-HardDisk | select Parent,CapacityGB
        
    }
}

get-elastictb 

get-elasticgt | % {

    $csize = ($_.CapacityGB | measure -Property CapacityGB -Sum).Sum

    $name = $_.Parent

    $item = New-Object PSObeject -Property @{
    
        NOME = $name
        SIZE = $csize
    
    }
    $item
} | select NOME,SIZE


GTVMDPAPP73F1 --> OK
GTVMDPAPPD633 --> OK
GTVMDPAPPD85A --> OK
GTVMDPAPP4FA6 --> OK
GTVMDPAPP81DA --> OK
GTVMDPAPPE24B --> OK


TBVMDPAPP4AC5 --> OK
TBVMDPAPP815C --> OK
TBVMDPAPP6E7D --> OK
TBVMDPAPP3C0D --> OK
TBVMDPAPPC428 --> OK
TBVMDPAPP1A04 --> OK

$disksizetotal = (Get-VM -Name GTVMDPAPP73F1 | Get-HardDisk | select CapacityGB | measure -Property CapacityGB -Sum).Sum

$clucpu = ((Get-Cluster -Name TB-CLS-PRD-001 | Get-VMHost).NumCpu | measure -Sum).Sum

$cluvcpuvm = ((Get-Cluster -Name TB-CLS-PRD-001 | Get-VM | where { $_.Powerstate -eq "PoweredOn" }).NumCpu | measure -Sum).Sum

$cluratio = [math]::Round(($cluvcpuvm / $clucpu), 0)

$cred = Get-Credential


$vctb = tbvm
$vcservers = @()


function get-cdisovms {
$vcdccon = Get-Content -Path C:\Users\ednascimento\Documents\scripts\vm_with_cds.txt
    foreach ($VMs in $vcdccon){
        Get-VM -Name $VMs | Get-CDDrive | select @{L="VM";E={$_.parent}},IsoPath 
    }
}

function Connect-VCSPags {
$vcs = @("gtvmvcen001.pags","tbvmvcen001.pags")
$vcenConn = $global:DefaultVIServers
$username = 'dc.pags\ednascimento'
$userwelcome = $username.Split('\')[1]



    if ( $vcenConn.Count -eq 1) {
        Write-Host "You are connected to "$vcs.name"`n" -ForegroundColor Green
        sleep 3
    }else {
        write-host "You are disconnected to "$vcenConn.name"`n" -ForegroundColor Red
        sleep 1
        Write-Host "Connecting..." -ForegroundColor Yellow
        sleep 3
        #$auth = Get-Credential -Message "Welcome to PagCloud" -UserName "$username"
        $con = Get-VICredentialStoreItem
        foreach ( $vc in $vcs){
            if ($? -eq 1 ) {
                Write-Host ""
                Connect-VIServer -Server $vc -User $con.User[0] -Password $con.Password[0]
                Write-Host "Welcome - $userwelcome" -ForegroundColor DarkYellow
            } else {
                Write-Host ""
                Write-Host "Do you typing the password strong" -ForegroundColor DarkRed
            }
        }
        
    }        
}



function Get-CDISO {
$vtoiso = @("GTVMPOSWEB5058","TBVMPOSWEBDB25")

    foreach ($vm in $vtoiso) {
        Get-VM | where { $_.Name -match "$vm" } | Get-CDDrive  |select @{L="VM";E={$_.Parent}},@{L="ISO";E={(($_.IsoPath).split("/")[2])}}
    }
}



function Get-IPPagsHost {
    Get-Datacenter | Get-VMHost | Get-VMHostNetworkAdapter | % {
     
        $_ | select VMhost,Name,IP,PortGroupName | where { $_.Name -match "vmk0" } | sort -Property VMhost

    } | ft -HideTableHeaders
}

$allvms = Get-VM

foreach ( $vm in $allvms) {
     $name = ($vm | Get-View).Name
     $bottime = ($vm | Get-View).Summary.Runtime.BootTime
     Write-Host "$name | $bottime"
     
}

function Get-CapacityPAGS {
    
    $tbsite = "Tambore"
    $gtsite = "Glete"
   
    $TotalvCPUGt = ((Get-Datacenter -Name Glete | Get-VM).NumCpu | measure -Sum).Sum
    $TotalMemGt = ((Get-Datacenter -Name Glete | Get-VM).MemoryGB | measure -Sum).Sum
    $TotalvCPUTb = ((Get-Datacenter -Name Tambore | Get-VM).NumCpu | measure -Sum).Sum
    $TotalMemTb = [math]::Round((((Get-Datacenter -Name Tambore | Get-VM).MemoryGB | measure -Sum).Sum),0)

    Write-Host "O Total de vCPU no site  $gtsite é $TotalvCPUGt" -ForegroundColor Yellow
    Write-Host "O Total de vRAM no site  $gtsite é $TotalMemGt" -ForegroundColor Yellow
    Write-Host ""
    Write-Host ""
    Write-Host "O Total de vCPU no site $tbsite é $TotalvCPUTb" -ForegroundColor Yellow
    Write-Host "O Total de vRAM no site $tbsite é $TotalMemTb" -ForegroundColor Yellow
}


Get-Folder -Type VM -Name 'utah' | Get-VM | Get-NetworkAdapter | select @{L="Name";E={$_.Parent}},networkname | where { $_.Networkname -eq "VLAN-500-GERAL-GT"} | foreach { ($_.Name |Get-VMHost).Parent.Name} 


Get-VMHost | Get-VMHostNetworkAdapter | where { $_.DeviceName -eq "vmk0" } | select vmhost,IP

Get-VMHost | where { $_.Name -match "^tb" } | sort -Property name | Get-VMHostNetworkAdapter | where { $_.DeviceName -match "vmk0" } | select vmhost,IP,SubnetMask,@{L="Gateway";E={ $_.ExtensionData.Spec.IpRouteSpec.IpRouteConfig.DefaultGateway}}
Get-VMHost | where { $_.Name -match "^gt" } | sort -Property name | Get-VMHostNetworkAdapter | where { $_.DeviceName -match "vmk0" } | select vmhost,IP,SubnetMask,@{L="Gateway";E={ $_.ExtensionData.Spec.IpRouteSpec.IpRouteConfig.DefaultGateway}}

$teste = Get-VMHost | where { $_.Name -match "^gt" } | sort -Property name | Get-VMHostNetworkAdapter | where { $_.DeviceName -match "vmk0" } | select -First 1 | Get-Member


    
Get-Folder -Type VM -Name VMware | Get-VM | Get-NetworkAdapter | where { $_.networkname -match '511' } | select @{L="VM";E={$_.Parent}},networkname | foreach { ($_.VM) | select name,@{L="IP";E={$_.Guest.IPAddress[0]}}  }

$vm.Guest.IPAddress


zypper addrepo https://download.opensuse.org/repositories/network:utilities/SLE_15/network:utilities.repo
zypper refresh
zypper install xinetd


zypper addrepo https://download.opensuse.org/repositories/server:http/SLE_15/server:http.repo
zypper refresh
zypper install haproxy

$teste = (Get-VM | where { $_.Name -match "esxi" } | Get-NetworkAdapter | select MacAddress)

$teste


$vmsec = @("TBVMESECWEB2237","TBVMESECWEB4E3B","TBVMESECWEBA908","TBVMESECWEB1F81")
foreach ( $v in $vmsec){
    get-vm | where { $_.Name -match "$v" } | Get-NetworkAdapter | select Parent,networkname
}

Get-Datacenter -Name glete | Get-Cluster -Name 'GT-CLS-DB-001' | Get-VMHost | Get-ScsiLun | where { $_.CapacityGB -match "100" } | select vmhost,CanonicalName,CapacityGb

Get-Datacenter -Name tambore | Get-VMHost -Name tbesxch02l03.pags| Get-VM | select name,@{L="Tag";E={ ($_ | Get-TagAssignment).Tag -replace("DATABASE/","")}},NumCpu,MemoryGB |  sort -Property MemoryGb | ft -AutoSize

$vmsdb = @("GTVMDB043","GTVMDB092","GTVMDB232")

foreach ( $db in $vmsdb){
    Get-VM | where { $_.Name -match "$db" } | select name,numcpu,memoryGB
}


function Get-K8sCluGT {
    $k8sclumemtotal = [math]::Round(((Get-Cluster -Name GT-CLS-K8S-001  | Get-VMHost |  measure -Property MemoryTotalGB -Sum).Sum), 0)
    $k8sclumemusage = [math]::Round(((Get-Cluster -Name GT-CLS-K8S-001  | Get-VMHost |  measure -Property MemoryUsageGB -Sum).Sum), 0)

    $k8smemfree = ($k8sclumemtotal - $k8sclumemusage)

    Write-Host "O total memória disponível no cluster GT-CLS-K8S-001 é $k8smemfree GB" 
}


function Get-Capacity_GT-CLS-DB-001 {

    $totalcpuhost = (Get-Cluster -Name GT-CLS-DB-001 | Get-VMHost | measure -Property numcpu -Sum).sum
    $totalvcpuvms =  [math]::Round(((Get-Cluster -Name GT-CLS-DB-001 | Get-VM | where { $_.powerstate -eq "PoweredOn" } | measure -Property numcpu -Sum).Sum), 0)
    $totalratiocpu = ($totalcpuhost / $totalvcpuvms)
        Write-Host "O ratio do cluster TB-CLS-MGMT-001 é igual:" $totalratiocpu -ForegroundColor Yellow
}



function Get-VMdhcpd {
$ipsdhcp = @("10.184.84.20","10.184.84.21","10.186.84.20","10.186.84.21","10.184.84.22","10.184.84.23","10.186.84.22","10.186.84.23","10.184.84.24","10.184.84.25","10.186.84.24","10.186.84.25")

    foreach ( $vm in $ipsdhcp) {
        Get-VM | where { $_.Guest.IPAddress -match "$vm"} | select name,resourcepool,@{L="IP";E={($_.guest.ipaddress)[0]}}
    }
    
}


Get-Cluster -Name GT-CLS-WIN-PRD |Get-VM |select name,@{L="Tag";E={ ($_ | Get-TagAssignment | select tag)}},@{L="Net";E={ $_ | Get-NetworkAdapter | where { $_.NetworkName -match "-DB-"} | select Networkname}} 

get-cluster -Name GT-CLS-WIN-PRD | Get-VM | % {

    $VM_Name = $_.Name
    $Tag_name  = ($_ | Get-TagAssignment).Tag
    $net_name = ($_ | Get-NetworkAdapter | where {$_.NetworkName -match "-DB-"}).NetworkName

    $item = New-Object -TypeName psObject -Property @{
        Nome = $VM_Name
        Tag = $Tag_name
        Network = $net_name
    }
    $item
    
} | select Nome,Tag,Network | where { $_.tag -notmatch "" -or $_.Network -notmatch "" } 

Get-Cluster -Name GT-CLS-WIN-PRD | Get-VM


function Get-Epg{

    $epgs = @("EPG-PPR-BE-015-GT","EPG-IDC-DB-0195-TB","EPG-PPR-BE-016-TB","EPG-IDC-DB-0195-TB","EPG-PPR-BE-016-TB","EPG-IDC-DB-0194-GT")

    foreach ( $epg in $epgs ) {
    #Get-VDPortgroup | where { $_.Name -match "$epg"} | select name
        $verepg = Get-VDPortgroup | where { $_.Name -match "$epg"}
        if ( $verepg.name -match "PPR") {
            Write-Host "EPG SRC -> $verepg" -ForegroundColor Yellow
            write-host "----------"
        }
       if ( $verepg.Name -match "IDC") {
           Write-Host "EPG DST" -> $verepg -ForegroundColor White
           write-host "----------"
        }
    }

}



 Get-VM | select name,@{L="IP";E={ ($_.guest.ipaddress)[0]}} -First 1


 Get-Cluster -Name "TB-CLS-DB-001" | Get-VMHost | where { $_.connectionState -eq "Connected"} | % {
    $clusterName = ($_).name
    $memoryTotal = $_.MemoryTotalGB
    $memoryUsage = $_.MemoryUsageGB
    $memoryFree = ($memoryTotal - $memoryUsage)

    $item = New-Object -TypeName psObject -Property @{
        Nome =  $clusterName
        MemTotal =$memoryTotal
                MemUsage = $memoryUsage
        MemFree = $memoryFree
    }
    $item 
 } 

 
 
 $vhost = "gtesxch03l05.pags"
 
 Get-VMHost -Name $vhost | Get-VMHostHba | select NodeWorldWideName,PortWorldWideName



 Get-VMhost | Get-VMHostHBA -Type FibreChannel | where {$_.Status -eq "online"} | Select @{N="Cluster";E={$cluster}},VMHost,Device,Status,@{N="WWN";E={"{0:X}"-f$_.PortWorldWideName}}


function Get-ResourceVraGt {
  
     $resourcegt = @("GTVMFNCAPP8442",
            "GTVMFNCWEB9124",
            "GTVMFNCAPPD463",
            "GTVMFNCAPP7AF8",
            "GTVMFNCAPPA917",
            "GTVMFNCWEBC538",
            "GTVMFNCAPP6F68",
            "GTVMFNCAPP4B19",
            "GTVMFNCAPP7A99",
            "GTVMFNCAPP2779",
            "GTVMFNCAPP9AA6",
            "GTVMFNCAPP84C3",
            "GTVMFNCAPPE873",
            "GTVMFNCAPPFDF0",
            "GTVMFNCAPP3C40",
            "GTVMFNCAPPEDDE",
            "GTVMFNCAPP784F",
            "GTVMFNCWEB869A",
            "GTVMFNCWEBAB10",
            "GTVMFNCAPP55D6",
            "GTVMFNCAPPAD1D",
            "GTVMFNCAPP205C",
            "GTVMFNCAPP1571",
            "GTVMFNCAPPA7F4",
            "GTVMFNCAPPDE61",
            "GTVMFNCAPPE1E7"
    )

    foreach ( $vm in $resourcegt) {
        Get-VM -Name $vm | Get-VMResourceConfiguration  #| where { $_.MemSharesLevel -eq "Normal" } | Set-VMResourceConfiguration -MemSharesLevel High -Confirm:$false 
    }

}



function Get-ResourceVraTb {
  
    $resourcetb = @(
	    "TBVMFNCAPP733D",
	    "TBVMFNCWEB45B5",
	    "TBVMFNCAPP2D34",
	    "TBVMFNCAPP7269",
	    "TBVMFNCWEBBB60",
	    "TBVMFNCAPP26F2",
	    "TBVMFNCAPPE420",
	    "TBVMFNCAPP9428",
	    "TBVMFNCAPP2438",
	    "TBVMFNCAPP5601",
	    "TBVMFNCAPP85A9",
	    "TBVMFNCAPPD996",
	    "TBVMFNCAPP2285",
	    "TBVMFNCAPPCD34",
	    "TBVMFNCAPP87DA",
	    "TBVMFNCAPP330B",
	    "TBVMFNCWEB714F",
	    "TBVMFNCWEBE0CC",
	    "TBVMFNCAPP0423",
	    "TBVMFNCAPP2C39",
	    "TBVMFNCAPPBA6A",
	    "TBVMFNCAPP25D6",
	    "TBVMFNCAPPA963",
	    "TBVMFNCAPPE450",
	    "TBVMFNCAPP9428"
    )
    foreach ( $vm in $resourcetb) {
        Get-VM -Name $vm | Get-VMResourceConfiguration #| where { $_.MemSharesLevel -eq "Normal" } | Set-VMResourceConfiguration -MemSharesLevel High -Confirm:$false 
    }

}






naa.600a09803831366d325d4e6350707032

function Get-PathVmhost {

    param (
        [string]$naa,
        [string]$hba,
        [string]$dc
     )
 
    $hostdc = (Get-Datacenter -Name $dc | Get-VMHost | select -First 1).name
    $scsilun = Get-ScsiLun -VmHost $hostdc -LunType disk
    Get-ScsiLunPath -ScsiLun $scsilun | select Name,ScsiCanonicalName,SanId,state,lunpath | where { $_.ScsiCanonicalName -match "$naa" -and $_.Name -match "$hba"}

} 


function Get-VMstatus {

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-Insert-Key", "NRII-0mUmjWKEA1-tml3ZJka97hQeZkYT7N2R")
    $body = "[`n    {`n      `"eventType`": `"sla`",`n      `"status`": 1,`n      `"hostname`": `"blabla2`"`n    },`n        {`n      `"eventType`": `"sla`",`n      `"status`": 1,`n      `"hostname`": `"blabla2`"`n    }`n  ]"
    $response = Invoke-RestMethod 'https://insights-collector.newrelic.com/v1/accounts/2834157/events' -Method 'POST' -Headers $headers -Body $body
    $response | ConvertTo-Json

    $vms = @("TBVMPXE01")

    foreach ( $vm in $vms) {
        $vms = get-vm | where { $_.Name -match "$vm" -and $_.PowerState -eq "PoweredOn"}
        if ( $vms.Count -eq "1") {
            return 1
            Write-Host "VM UP" -ForegroundColor Green
        } else {
            Write-Host "VM DOWN" -ForegroundColor Red
            return 0
        }
    }
}


$array = @()

 Get-VM -Name GTVMDB635 | % {
 
    $vm = $_.Name
    $app = $_ | select
 }



 Get-VM| select name,Powerstate,@{L="App Name";E={($_.CustomFields.value[0])}},@{L="App Type";E={($_.CustomFields.value[3])}},@{L="App Owner";E={($_.CustomFields.value[4])}} -First 500 | ft -AutoSize

 Get-DatastoreCluster -Name 'GT-NETAPP-CLS001' | Get-VM | where { $_.powerstate -eq 'PoweredOn'} | select name,Powerstate,NumCpu,MemoryGB,@{L="Ip";E={($_.guest.ipaddress[0])}},@{L="HostName";E={($_.guest.Hostname)}},@{L="AppName";E={($_.CustomFields.value[0])}},@{L="AppType";E={($_.CustomFields.value[3])}},@{L="AppOwner";E={($_.CustomFields.value[4])}},@{L="Tag";E={($_ | Get-TagAssignment).Tag.Name}},@{L="TagCategory";E={($_ | Get-TagAssignment).Tag.Category}} -First 100 | ft -AutoSize

 
 $report = @()
 Get-DatastoreCluster | % {
 
    $name = $_.Name
    $qtdeDs = $_.Name.count 

    $item = New-Object PSObject -Property @{
        Datastore = $name
        QtdeDatastore = $qtdeDs
    
    }

    $report += $item
}

$report | select Datastore,QtdeDatastore


$ips=@("10.191.132.159","10.184.0.148","10.184.11.175","10.184.12.5","10.184.40.17")

foreach ( $ip in $ips) {

    Get-VM | where { $_.guest.IPAddress -match "$ip" } | select name,Powerstate,NumCpu,MemoryGB,@{L="Ip";E={($_.guest.ipaddress[0])}},@{L="HostName";E={($_.guest.Hostname)}},@{L="AppName";E={($_.CustomFields.value[0])}},@{L="AppType";E={($_.CustomFields.value[3])}},@{L="AppOwner";E={($_.CustomFields.value[4])}},@{L="Tag";E={($_ | Get-TagAssignment).Tag.Name}},@{L="TagCategory";E={($_ | Get-TagAssignment).Tag.Category}} | ft -AutoSize | Out-File -FilePath C:\Users\ednascimento\Documents\vms.txt    
}


Get-Cluster -Location glete | Get-ResourcePool -Name PROD | Get-VM | where { $_.powerstate -eq 'PoweredOn'} | select name,Powerstate,NumCpu,MemoryGB,@{L="Ip";E={($_.guest.ipaddress[0])}},@{L="HostName";E={($_.guest.Hostname)}},@{L="AppName";E={($_.CustomFields.value[0])}},@{L="AppType";E={($_.CustomFields.value[3])}},@{L="AppOwner";E={($_.CustomFields.value[4])}} | ft -AutoSize | Out-File -FilePath C:\Users\ednascimento\Documents\relaco_vms_deep_gt.txt    
Get-Cluster -Location tambore | Get-ResourcePool -Name PROD | Get-VM | where { $_.powerstate -eq 'PoweredOn'} | select name,Powerstate,NumCpu,MemoryGB,@{L="Ip";E={($_.guest.ipaddress[0])}},@{L="HostName";E={($_.guest.Hostname)}},@{L="AppName";E={($_.CustomFields.value[0])}},@{L="AppType";E={($_.CustomFields.value[3])}},@{L="AppOwner";E={($_.CustomFields.value[4])}} | ft -AutoSize | Out-File -FilePath C:\Users\ednascimento\Documents\relaco_vms_deep_tb.txt


Get-VMstatus 


get-datacenter -Name glete | Get-VM | where { $_.powerstate -match 'PoweredOn'} | % {

    $redeCommon = $_ | Get-NetworkAdapter | where { $_.NetworkName -match 'common'} | measure -Property name -Sum
    $redeProd = $_ | Get-NetworkAdapter | where { $_.NetworkName -match 'prod'} | measure -Property Name -Sum
    $rededevqa = $_ | Get-NetworkAdapter | where { $_.NetworkName -match 'dev' -or $_.networkName -eq 'qa'} | measure -Property Name -Sum
    $redege = $_ | Get-NetworkAdapter | where { $_.NetworkName -match 'vlan'} | measure -Property Name -Sum

    $item = New-Object PSObject -Property @{
    
     RedeCommon = $redeCommon.sum
     RedeProd = $redeProd.sum
     RedeQadev = $rededevqa.sum
     RedeGeral = $redege.sum
    
    }

    $item
}

Get-VMHost -Location tambore |  ? { $_.Name -match 'tbesxp2ch03l02.host.pags'} | % {

    $hostname = ($_).Name
    $hostname  = "BOOT" + ":" + $hostname.ToUpper()
    #Write-Host($hostname)
    
    $_ | Get-Datastore | ? { $_.Name -match "^datastore1( \(\d+\))?$" } | Set-Datastore -Name $hostname

}

Get-VMHost -Location glete |  ? { $_.Name -match 'qadev'}


Get-VM -Name TBVMIDCDBB820 |Get-HardDisk | Set-SpbmEntityConfiguration -StoragePolicy 'TB-HighPerformance 10k' -Confirm:false

Get-VM -Name GTVMIDCWEB105C | Get-HardDisk | Get-SpbmEntityConfiguration | select -First 1

$vmteste = Get-VM -Name GTVMDB473

$vmteste | Get-HardDisk| Set-SpbmEntityConfiguration -StoragePolicy "GT-HighPerformance 10k" -Confirm:$false

$vmstransprod = @("GTVMDPAPP4AD2","GTVMDPAPP0A39","GTVMDPAPPFF02","GTVMDPAPP0512","TBVMDPAPPD7BF","TBVMDPAPPF66C","TBVMDPAPPF66C","GTVMDPAPP1439","GTVMDPAPP1B73","TBVMDPAPP2169","TBVMDPAPP1CC4","TBVMDPAPP73B1","TBVMDPAPP6781","TBVMDPAPPD60F","GTVMDPAPPEE5F","GTVMDPAPP144A","GTVMDPAPPAA75","GTVMDPAPPC48B","GTVMDPAPP5C60","TBVMDPAPPF1DB","GTVMDPAPP8455")
$vmstransdevqa = @("TBVMDPWEBE714","TBVMDPAPPC408","TBVMDPAPPFCDB","GTVMDPAPP0FC8","GTVMDPWEB3D35","GTVMDPAPP5035","TBVMDPAPPDE25","TBVMDPAPPF8D0","TBVMDPWEBB176","TBVMDPWEB9BAB")



foreach ($vdevqa in $vmstransdevqa) {
  #  $diskUsageSpaceGB = Get-VM -Name $vmdevqa | select UsedSpaceGB
   # $diskUsageSpaceGB
    $vmname  = (Get-VM -Name $vdevqa).Name
    $ambiente = "devqa"
    $sumUsage = (Get-VM -Name $vdevqa | select Name,@{L="UsedSpace";E={([math]::Round(($_.UsedSpaceGB),0))}},@{L="ProvisionedSpace";E={[math]::Round(($_.ProvisionedSpaceGB),0)}} | measure -Property UsedSpace -Sum).Sum
    $sumProvi = (Get-VM -Name $vdevqa | select Name,@{L="UsedSpace";E={([math]::Round(($_.UsedSpaceGB),0))}},@{L="ProvisionedSpace";E={[math]::Round(($_.ProvisionedSpaceGB),0)}} | measure -Property ProvisionedSpace -Sum).Sum

    $item = New-Object PSObject -Property @{
        VM = $vmname
        Ambiente = $ambiente
        Usado = $sumUsage
        Provisionado = $sumProvi
    }
    $item 
    #[math]::Round(($memtotalclddb - $memusageclddb),1)
} 

echo "VMs Dev/QA"
foreach ( $trans in $vmstransdevqa) {
            
            
            $vmstoragetotal = (Get-VM -Name $trans | Get-HardDisk | measure -Property capacityGB -Sum).Sum
               
            foreach ( $i in $vmstoragetotal) {
                [int]$count = "0"
                $count.GetType().Name
               $result = ($count + $i.ToInt32())
                $result 
            }    
}

(Get-VM -Name GTVMDPAPP0512 | Get-HardDisk | measure -Property capacityGb -Sum).Sum

($vmteste | Get-HardDisk | measure -Property capacityGB -Sum).Sum
    


Get-VM -Name TBVMDB037_CLONE | Get-HardDisk | Get-Datastore | Get-DatastoreCluster


while ($true) {
     Get-VMHost gtesxch* | % {
    
            $name = $_.Name
            $esxcli = Get-EsxCli -VMHost $name -V2
            $vmnic = ($esxcli.network.nic.list.Invoke()).name
            $vmnicstatus = ($esxcli.network.nic.list.Invoke()).linkstatus 
            $item = New-Object PSObject -Property @{
                Hostname = $name
                Interface = $vmnic
                InterfaceStatus = $vmnicstatus
            }
            $item | select Hostname,Interface,InterfaceStatus | sort -Property Hostname
    }
    #sleep 5
    Write-Host "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"

}


#### teste de expressões regulares

Get-VMHost -Location tambore | ? { $_.Name -match '^tb.{9}\d\w{2}\d{2}\w\d{2}\.\w{4}\.\w+'} 

Get-Cluster -Location glete | Get-VMHost |  ? { $_.Name -match '^gt.{9}\d\w{2}\d{2}\w\d{2}\.\w{4}\.\w+'} | Get-VMHostStorage -RescanAllHba 







$vms = @("GTVMDPAPP0431","GTVMDPAPP965A","GTVMDPAPP21E2","GTVMDPAPP7600")

foreach ($vm in $vms) {
    $v = (Get-VM | ? { $_.Name -match "$vm"}) 
    $v
 #   if ($v.powerstate -eq "PoweredOff") {
  #     Write-Host "iniciando vms..."
   #    $v | Start-VM -Confirm:$false
    #}
   
}


Get-VM -Location tambore | ? { $_.PowerState -eq "PoweredOn"} | % {
    $name = $_.Name
    $ip = $_ | % { $_.Guest.IPAddress[0]}
    $item = $item = New-Object PSObject -Property @{
        NOME = $name
        IP = $ip
    }
    $item
} | select NOME,IP | where { $_.IP -match '10.190.32'} | ft -AutoSize



$datastore = Get-Content -Path C:\Users\ednascimento\Documents\scripts\luns_datastore.txt

foreach ( $ds in $datastore) {
    $d = Get-Datastore | select Name,@{N='CanonicalName';E={$_.Extensiondata.Info.Vmfs.Extent[0].DiskName}} | where { $_.CanonicalName -match "$ds"}
    $d.name
}


$vms = @("TBVMIDCDB29A8","TBVMIDCDB44FB","TBVMIDCDB2D14")

foreach ( $i in $vms) {
    $v = Get-VM -Location tambore | where { $_.Name -match '$i'}

    if ($? -eq 1) {
        Write-Host $i "não existe" -ForegroundColor Red
    }
}

$datastoresfile = Get-Content -Path C:\Users\ednascimento\Documents\scripts\luns_datastore.txt
$site = "glete"

foreach ($ds in $datastoresfile) {
    Get-Datastore -Location $site | select Name,@{N='ID';E={$_.Extensiondata.Info.Vmfs.Extent[0].DiskName}} | where { $_.ID -match "$ds"} |% {
        
        $dsname = $_.Name
        $dsfull = Get-Datastore -Name $dsname
        $vm = $dsfull | Get-VM
        $date = Get-Date -Format "MM-dd-yyyy-HH-mm"
        $vm | select Name,PowerState,NumCpu,MemoryGb,@{L="Ip";E={($_.guest.ipaddress)[0]}},@{L="HostName";E={($_.guest.hostname)}},@{L="Os";E={($_.guest.OSFullName)}},@{L="AppName";E={($_.CustomFields['Application name'])}},@{L="AppOnwer";E={($_.CustomFields['VRM Owner'])}} | ft -AutoSize | Out-File -FilePath C:\Users\ednascimento\Documents\report_vm_$date.txt
    }
    
}


####################

$datastoresfile = Get-Content -Path C:\Users\ednascimento\Documents\scripts\luns_datastore.txt
$logsfile = "report_full.txt"
$site = "tambore"

foreach ($ds in $datastoresfile) {
    Get-Datastore -Location $site | select Name,@{N='ID';E={$_.Extensiondata.Info.Vmfs.Extent[0].DiskName}} | where { $_.ID -match "$ds"} |% {
        
        $dsname = $_.Name
        $dsfull = Get-Datastore -Name $dsname
        foreach ($v in $dsfull) {
            $line = Get-VM -Datastore $v | select Name,PowerState,NumCpu,MemoryGb,@{L="Ip";E={($_.guest.ipaddress)[0]}},@{L="HostName";E={($_.guest.hostname)}},@{L="Os";E={($_.guest.OSFullName)}},@{L="AppName";E={($_.CustomFields['Application name'])}},@{L="AppOnwer";E={($_.CustomFields['VRM Owner'])}},@{N='Datastore';E={$v.Name}} 
            Add-Content -Path $logsfile -Value $line  
        }
   }
}


$allvms = @()
$vms = Get-Vm -Location glete | where {$_.PowerState -eq "PoweredOn"}

foreach ($vm in $vms) {
    $vmv = ($vm | Get-View)

    $vms = "" | Select Name 

    if ( $vmv.Config.GuestFullName -match "Windows") {
        $vms.Name = $vm.name

        $allvms += $vms

    }
   
}

 $allvms


$dst = Get-VM -Name tbvmdb037 | Get-HardDisk | where { $_.capacityGB -match '^2'}  | % { $_.filename } | % { $_.split('[')[1];} | % { $_.split(']')[0];} 
foreach ($d in $dst) {
    Get-Datastore $d | Get-DatastoreCluster
}


Get-VM -Name teste-scsi-validation02  | Get-HardDisk | Select @{N='VM';E={$_.Parent.Name}},Name,@{N='SCSIid';E={$hd = $_$ctrl = $hd.Parent.Extensiondata.Config.Hardware.Device | where{$_.Key -eq $hd.ExtensionData.ControllerKey}"$($ctrl.BusNumber):$($_.ExtensionData.UnitNumber)"}}


$hosts = @("tbesxp3ch01l03",
            "tbesxp3ch01l04",
            "tbesxp3ch02l03",
            "tbesxp3ch02l04",
            "tbesxp3ch01l05",
            "tbesxp3ch01l06",
            "tbesxp3ch02l05",
            "tbesxp3ch02l06",
            "tbesxp3ch01l07",
            "tbesxp3ch01l08",
            "tbesxp3ch02l07",
            "tbesxp3ch02l08",
            "tbesxqadevp3ch02l04",
            "tbesxqadevp3ch02l03",
            "tbesxqadevp3ch01l03",
            "tbesxqadevp3ch01l04",
            "tbesxqadevp3ch02l07",
            "tbesxqadevp3ch02l08",
            "tbesxqadevp3ch01l07",
            "tbesxqadevp3ch01l08")

foreach ($h in $hosts) {
    $i = Get-VMHost -Name $h

    if ( $? = 1) {
        Write-Host '$h não localizado' -ForegroundColor Red
    } else {
        Write-Host '$h localizado' -ForegroundColor Green
    }
}



Get-DatastoreCluster -Name GT-NETAPP-ORACLE001 | Get-Datastore | Select Name, Datacenter,CapacityGB,FreeSpaceGB,@{N="ProvisionedGB"; E={[math]::round(($_.ExtensionData.Summary.Capacity - $_.ExtensionData.Summary.FreeSpace + $_.ExtensionData.Summary.Uncommitted)/1GB,2) }}| Sort-Object -Property ProvisionedGB | ft -AutoSize

$vm = Get-VM -Name TBVMDB845
$vmsp = Get-SpbmStoragePolicy -Name "TB-Default VM storage I/O limit"

##New-HardDisk -VM $vm -CapacityGB 500 -StorageFormat Thin -Datastore GT-HITACHI-VSP5500-0503-515 -StoragePolicy $vmsp -Controller "SCSI controller 0"  -Confirm:$false
New-HardDisk -VM $vm -CapacityGB 500 -StorageFormat Thin -Datastore TB-HITACHI-VSP5500-001c-30 -StoragePolicy $vmsp -Confirm:$false | Out-Null



$vms = @("TBVMDPAPPD60F","TBVMDPAPP6781","TBVMDPAPP1CC4")

foreach ($vmelastic in $vms) {
    Get-HardDisk -VM $vmelastic | where { $_.CapacityGB -eq "550" } | select parent,capacityGB
}

$vmsrestated = Get-Content -Path C:\Users\ednascimento\Documents\scripts\vms_restated_16042021.txt

$logsfile = "report_all_vms_restated_GT-CLS-PRD-001.txt"
foreach ($v in $vmsrestated) {
    $line = Get-VM | where { $_.Name -match "$v" } | select Name,PowerState,NumCpu,MemoryGb,@{L="Ip";E={($_.guest.ipaddress)[0]}},@{L="HostName";E={($_.guest.hostname)}},@{L="Os";E={($_.guest.OSFullName)}},@{L="AppName";E={($_.CustomFields['Application name'])}},@{L="AppOnwer";E={($_.CustomFields['VRM Owner'])}} 
    Add-Content -Path $logsfile -Value $line
}



Get-VMHost -Location glete |Get-Random | Get-VMHostService


Get-Cluster -Name GT-CLS-DB | Get-ResourcePool -Name DEV-QA | Get-VM | % {

    $name = $_.name
    $ds = $_ | Get-Datastore
    $dscluster = $_ | get-datastore | Get-DatastoreCluster

    $item = New-Object Psobject -Property @{
        NOME = $name
        DATASORE = $ds.name
        CLUSTERDS = $dscluster
    }
    $item
} | select NOME,CLUSTERDS | sort -Property CLUSTERDS | ft -AutoSize



Write-Host "Tambore Vms com ISOs conectadas" 
Get-Cluster -Location tambore | Get-VM | where { $_.powerstate -eq "PoweredOn"} | Get-CDDrive | where { $_.IsoPath -match '\['} | select parent,isopath | ft -AutoSize| Set-CDDrive -NoMedia -Confirm:$false
Write-Host ""
Write-Host "Glete Vms com ISOs conectadas"
Get-Cluster -Location glete | Get-VM | where { $_.powerstate -eq "PoweredOn"} | Get-CDDrive | select parent,IsoPath | where { $_.IsoPath -match '\[G'}

Get-VM -Name TBVMDPAPP9FBA | Get-CDDrive | Set-CDDrive -NoMedia -Confirm:$false



$vmhostmmemtotal = [math]::Round((Get-Cluster -Location tambore -Name TB-CLS-MGMT-001 | Get-VMHost | Measure-Object -Property MemorytotalGB -Sum).Sum ,0)
$vmsmemtotal = [math]::Round((Get-Cluster -Location tambore -Name TB-CLS-MGMT-001 | Get-VMHost | Get-VM |where { $_.powerstate -eq "PoweredOn"} | Measure-Object -Property MemoryGB -Sum).Sum ,0)


(get-datacenter -name glete| Get-DatastoreCluster| Get-Datastore | Select Name, Datacenter,CapacityGB,FreeSpaceGB,@{N="ProvisionedGB"; E={[math]::round(($_.ExtensionData.Summary.Capacity - $_.ExtensionData.Summary.FreeSpace + $_.ExtensionData.Summary.Uncommitted)/1GB,2) }}| Sort-Object -Property ProvisionedGB | measure -Property ProvisionedGB -Sum).Sum


function Get-CapacityStorage {
    param (
        [string]$dc
    )

    get-datacenter -Name $dc | Get-DatastoreCluster | % {
    
        $clusterName = $_.Name
        $clusterdatastores = $_ | Get-Datastore
        $capacityTotal = $clusterdatastores.CapacityGB
        $capacityfree = $clusterdatastores.FreeSpaceGB
        $capacityProv = $clusterdatastores.ExtensionData.Summary.Capacity - $clusterdatastores.ExtensionData.Summary.FreeSpace + $clusterdatastores.ExtensionData.Summary.Uncommitted/1GB

        $item = New-Object Psobject -Property @{
            
            CLUSTERNAME = $clusterName
            CAPTOTAL = $capacityTotal
            CAPFREE = $capacityfree
            CAPPROV = $capacityProv
        
        }

        $item 
    } | select CLUSTERNAME,CAPTOTAL,CAPFREE,CAPPROV| ft -AutoSize
}


Get-Cluster -Name TB-CLS-K8S-001 | Get-VMHost | % {
    $hostn = $_.Name
    $hostcpu = $_.numCpu * 25
    $hostvms = ($_ | Get-VM | measure -Property NumCpu -Sum).Sum

    
    $item = [PSCustomObject]@{
        HOST = $hostn
        HOSTVCPU = $hostcpu
        HOSTVMVCPU = $hostvms
    }
    $item
}


#####################################################################################


Get-Datacenter -Name tambore | Get-DatastoreCluster | % {
    $cluname = $_.name
    $cluds = ($_ | Get-Datastore).count

    $item = [PSCustomobject]@{
        CLUSTER = $cluname
        NUMDS = $cluds
    }

    $item 

} | ft -AutoSize


#######################

#GTVMIDCDB94F9(10.184.33.2)
#TBVMIDCDB16AE(10.186.34.232)


$politica10k = (Get-SpbmStoragePolicy  | where { $_.Name -match '10k' -and $_.Name -match '^TB'}).Name

Get-VM -Name GTVMIDCDB94F9 | Get-HardDisk | Set-SpbmEntityConfiguration -StoragePolicy $politica10k -Confirm:$false



Get-Datastore -Name "GT-NETAPP-AFFA800-7131-77" | Get-VM | % {
    $nome = $_.Name
    $folder = $_.folder
    $rede = ($_ | Get-NetworkAdapter).NetworkName

    $item = [PSCustomobject]@{
        VMNAME = $nome
        VMFOLDER = $folder
        VMNET = $rede
    }
    $item
}

$hosts = Get-Content .\hosts_update_firmware.txt
foreach ( $h in $hosts) {
    Get-VMHost -Location glete | where { $_.Name -match "$h" } | select name,parent 
} 


###########

function Get-DSFree {

    param (
        [string]$dc
     )
  
    Get-Folder -Type Datastore -Name DS-8TB -Location $dc | Get-Datastore | where { $_.state -eq 'Maintenance'} | % {
        $dsname = $_.ExtensionData.info.vmfs.name
        $dsnaa = $_.ExtensionData.info.vmfs.extent.diskname
        $dsfolder = $_.parentfolder
        $dssize = [math]::Round(($_.capacityGb / 1024), 2)
        $dsstate = $_.state
        $item = [PSCustomObject]@{
            DSNAME = $dsname
            DSSTATE = $dsstate
            DSFOLDER = $dsfolder
            DSSIZE = [string]$dssize + "TB"
            DSLUNID = $dsnaa
        
        }
        $item 
        #Write-Host "$dsname | $dsnaa | $dssize TB | $dsfolder"  -ForegroundColor Yellow

    } | ft -AutoSize
}

########################################################################################################################################################

Get-VMHost -Location glete | where { $_.name -match 'qadevp3'} | select -First 1 | Get-Datastore | % {
    $dsnome = $_.Name
    $dsid = $_.ExtensionData.info.vmfs.extent.diskname
    $ids = @("3831366d395d4e6156567132","3831366d385d4e6350706977","3831366d325d4e6350707234","383136576a244e6350713079")
    $vmnum = ($_ | Get-VM).count
    $dssize = $_.CapacityGb
    $dsclu = ($_ | Get-DatastoreCluster).Name
    foreach ($i in $ids){
        if ($dsid -match "$i") {
            $item = [PSCustomObject]@{
                DATASORENAME = $dsnome
                DATASOTRESIZE = [math]::Round(($dssize), 2)
                DATASOREID = $dsid
                DATASORENUMVM = $vmnum 
                DATASTORECLUSTER = $dsclu
            }
            $item 
            #Write-Host "$dsnome | $dsid | $vmnum"
        } 
  }
} | ft -AutoSize



Get-VMHost -Location tambore | sort -Property name | % {

    $vhostnome = $_.Name
    $vhostnumds = ($_ | Get-Datastore).count

    if ($vhostnome -notmatch 'p2' -and $vhostnome -notmatch 'p3') {
        $location = "POD1"

    } elseif ($vhostnome -match 'p2') {
        $location = "POD2"
    } elseif($vhostnome -match 'p3') {
        $location = "POD3"
    } else {
        $location = "N/A"
    }

    $item = [PSCustomObject] @{
        NOME = $vhostnome
        DS = $vhostnumds
        POD = $location
    }
    $item 
} | sort -Property DS | ft -AutoSize

################################################################################

$dshost = @("tbesxch06l07.pags","tbesxch05l08.pags","tbesxch05l07.pags","tbesxch05l06.pags","tbesxch05l05.pags","tbesxch07l05.pags","tbesxch07l06.pags","tbesxch07l07.pags","tbesxch07l08.pags","tbesxch08l05.pags","tbesxch08l07.pags","tbesxch08l08.pags","tbesxch08l06.pags","tbesxch02l06.pags")

foreach ($i in $dshost) {
    
    Get-VMHost $i | Get-VMHostStorage -RescanAllHba -RescanVmfs
    #$dsstatus = (Get-VMHost -Name $i | Get-Datastore | where { $_.Name -match 'TB-NETAPP-AFFA800-3250-4'}).Name

    #if ($dsstatus -eq 'TB-NETAPP-AFFA800-3250-4'){
    #    Write-Host 'Achou em $i $dsstatus' -ForegroundColor Green
    #} else {
    #    Write-Host "Não acho em $i $dsstatus" -ForegroundColor Red
    #}
}



 Get-VMHost -Location glete | % { $_ | Get-VMHostNetworkAdapter | ? { $_.IP -match '10.190.3.24' } } | select vmhost,IP

 $vhost = "gtesxch02l04.pags"
 $vhostview = Get-VMHost -Name $vhost | Get-View
 $vhosthealth = Get-View $vhostview.configManager.HealthStatusSystem




 $VMHostName = "gtesxch02l04.pags"
$HostView = Get-VMHost -Name $VMHostName | Get-View
$HealthStatusSystem = Get-View $HostView.ConfigManager.HealthStatusSystem
$SystemHealthInfo = $HealthStatusSystem.Runtime.SystemHealthInfo
ForEach ($Sensor in $SystemHealthInfo.NumericSensorInfo) {
 $Report = "" | Select-Object VMHost,Sensor,Status,TimeStamp
 $Report.VMHost = $VMHostName
 $Report.Sensor = $Sensor.Name
 $Report.Status = $Sensor.HealthState.Key
 #$Report.Reading = $Sensor.CurrentReading/100
 $report.TimeStamp = $Sensor.TimeStamp
 $Report | sort -Property TimeStamp
} 

function Get-FCVmhost{
 
     param (
       [string]$wwpn,
       [string]$dc
       #[Parameter(Mandatory=$true, ParameterSetName="naa")]
       #[string]$naa,
       #[Parameter(Mandatory=$true, ParameterSetName="dc")]
       #[string]$dcge

     )
     
     # where { $_.Name -match "p3" -and $_.Name -notmatch "qadev" } 

    Get-VMHost -Location $dc | % {
    $vnome = $_.Name
    $vadapterA = ((Get-EsxCli -V2 -VMHost $vnome).storage.core.adapter.list.Invoke()).HBAName | where { $_ -match 'vmhba0'}
    $vadapterB = ((Get-EsxCli -V2 -VMHost $vnome).storage.core.adapter.list.Invoke()).HBAName | where { $_ -match 'vmhba2'}
    $vfcA = ((Get-EsxCli -V2 -VMHost $vnome).storage.core.adapter.list.Invoke()).UID | ? { $_ -notmatch 'sata'} | select -First 1
    $vfcB = ((Get-EsxCli -V2 -VMHost $vnome).storage.core.adapter.list.Invoke()).UID | ? { $_ -notmatch 'sata'} | select -Last 1

    $item = [PSCustomObject]@{
        NOME = $vnome
        HBAA = $vadapterA
        HBAB = $vadapterB
        FCA =  $vfcA
        FCB = $vfcB
    }
    $item | where { $_.FCA -match "$wwpn" -or $_.FCB -match "$wwpn" }
    } | ft -AutoSize 
}


#########################################################################################################################

Get-VMHost -Location tambore | where { $_.Name -match "p3" -and $_.Name -notmatch "qadev" } | % {
    $vhost = $_.name
    $dscount = ($_ | get-datastore | ? { $_.name -notmatch "boot" }).count
    $item = [PSCustomObject]@{
        Name = $vhost
        NumDs = $dscount
    }
    $item
}

####################

while ($true){
    write-host "###############################"
    Get-Task | where { $_.State -eq 'Queued' } | select name,id
    sleep 3
}



###########################

Get-VM | select name,NumCpu,MemoryGB,@{L="NumDisk";E={($_ | Get-HardDisk).count}} -First 1
Get-VM | ? { $_.Name -eq "TBVMIDCJENKINSTESTE"}

Get-VMHost -Location tambore | select -First 1
$vhost = "tbesxch01l02.pags"

$vhostcli = Get-EsxCli -VMHost $vhost

Get-VMHost -Name $vhost | Get-VMHostHba -Type FibreChannel | Select -ExpandProperty Name


#############


$vdisk = Get-ScsiLun -VmHost $vhost -LunType disk -CanonicalName "naa.600a098038313670435d4e674e773477"  # | ? { $_.vendor -eq "HITACHI" } 

(Get-VMHostHba -VMHost $vhost | ? { $_.Status -eq "online"}).ExtensionData.ScsiLunUids

(Get-ScsiLunPath -ScsiLun $vdisk).count

$hba = Get-VMHostHba -VMHost $vhost -Type FibreChannel | select -ExcludeProperty name
$esxi = Get-EsxCli -V2 -VMHost $vhost
$esxi.storage.core.path.list.Invoke() | where { $hba -contains $_.adapter }



$esxName = 'tbesxch01l02.pags'

$esx = Get-VMHost -Name $esxName

$esxcli = Get-EsxCli -V2 -VMHost $esxName

$hba = Get-VMHostHba -VMHost $esx -Type FibreChannel | Select -ExpandProperty Name

($esxcli.storage.core.path.list.Invoke() | Where{$hba -contains $_.Adapter} | Group-Object -Property Device | Select @{N='LUN';E={$_.Name}},@{N='Path';E={$_.Group.Count}} | measure -Property Path -Sum).Sum


function Get-NumPathHost {
     param(
    [string]$site
  )
Get-Cluster -Location $site |  Get-VMHost | where { $_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance"}| % {
    $name = $_.Name
    $vesxi = Get-EsxCli -V2 -VMHost $name
    $vhba = Get-VMHostHba -VMHost $name -Type FibreChannel | select -ExpandProperty name
    $vpath = ($vesxi.storage.core.path.list.Invoke() | Where { $vhba -contains $_.Adapter } | Group-Object -Property Device | Select @{N='LUN';E={$_.Name}},@{N='Path';E={$_.Group.Count}} | measure -Property Path -Sum).Sum

    $item = [PSCustomObject]@{
        Name = $name
        NumPath = $vpath
    }
    $item
   }
}

Get-VM -Location glete | ? { $_.PowerState -eq "PoweredOn" -or $_.ExtensionData.Guest.ToolsRunningStatus -notmatch "not"}

Get-VM -Location glete | ? { $_.PowerState -eq "PoweredOn" } | select name,@{L="ToolsStatus";E={ $_.ExtensionData.Guest.ToolsRunningStatus }} | ? { $_.ToolsStatus -eq "guestToolsNotRunning" }


Get-Folder -Location glete -Type VM -Name vmware | get-vm | ? { $_.Name -match "pxe" } | select name,@{L="ip";E={$_.guest.ipaddress[0]}},vmhost


Get-VMHost -Location glete | ? { $_.Name -match '^gt\w{5}\d{2}\w\d{2}\.\w+' }  | select name,version,build,@{L="Cluster";E={ $_.parent }} |where { $_.Build -notmatch "17700523" } |sort -Property name
Get-VMHost -Location glete | ? { $_.Name -match '^gt\w{5}\d{2}\w\d{2}\.\w+' }  | select name,version,build,@{L="Cluster";E={ $_.parent }} |sort -Property name | group -Property build | select count,name

(Get-Cluster -Location glete | Get-VMHost | ? { $_.Name -match '^gtesxch0' } | sort -Property name).count


(Get-VMHost -Location glete | where { $_.name -notmatch "p2" -and $_.Name -notmatch "p3"}).count


###########################

function Get-TotalUsageVMPags {

param (
    [string]$site
)


 (Get-Datastore -Name GT-NETAPP-AFFA800-6737-10 | Get-VM | ? { $_.ResourcePool -match "DEV-QA" } | % {

    $totalusageGB = $_.get_UsedSpaceGB()

    $totalround = [math]::Round($totalusageGB,0)

    $item =[PSCustomObject]@{
        Total = $totalround
    }

    $item
} | measure -Property Total -Sum).Sum


}



Get-Datastore -Name GT-NETAPP-AFFA800-6737-10 | Get-VM | select name,@{L="UsageGB";E={ $_.get_UsedSpaceGB() }},ResourcePool


while ($true) {

    Get-Datastore -Name GT-NETAPP-AFFA800-6737-10 | Get-VM | select name,ResourcePool,@{L="Net";E={ ($_ | Get-NetworkAdapter).NetworkName }},@{L="UsageGB";E={ $_.get_UsedSpaceGB() }} | where { $_.net -match "Tn-DEV" -or $_.net -match "Tn-QA" }
    sleep 5
    write-host "######################################################################" -ForegroundColor Yellow
}

Get-Cluster -Location glete | where { $_.Name -eq "GT-CLS-PRD-001" -or $_.Name -eq "GT-CLS-PRD-002" -or $_.Name -eq "GT-CLS-WIN-PRD" } |  Get-VM | % {
    $name = $_.name
    $rp = ($_.ResourcePool).name
    $net = ($_ | Get-NetworkAdapter).NetworkName
    $usesgb = [math]::Round(($_.get_UsedSpaceGB()),0)
    #name,,@{L="Net";E={ ($_ | Get-NetworkAdapter).NetworkName }},@{L="UsageGB";E={ $_.get_UsedSpaceGB() }} | where { $_.net -match "Tn-DEV" -or $_.net -match "Tn-QA" }

    $item = [PSCustomObject]@{
        Name = $name
        ResourcePool = $rp
        NetworkName = $net
        StorageUsage = $usesgb
        
    }
    $item

} | ft -AutoSize | clip

Get-Cluster -Location glete | where { $_.Name -eq "GT-CLS-PRD-001" -or $_.Name -eq "GT-CLS-PRD-002" -or $_.Name -eq "GT-CLS-WIN-PRD" -or $_.Name -eq "GT-CLS-DB" }


(Get-Folder -Location glete -Type VM -Name VMware | Get-VM | ? { $_.Name -match "log" } | select name,@{L="UsageGB";E={ [math]::Round(($_.get_UsedSpaceGB()),0) }} | measure -Property UsageGB -Sum).Sum


Get-Datastore GT-NETAPP-AFFA800-6737-10 |Get-VM | select Name,PowerState,NumCpu,MemoryGb,@{L="Ip";E={($_.guest.ipaddress)[0]}},@{L="HostName";E={($_.guest.hostname)}},@{L="Os";E={($_.guest.OSFullName)}},@{L="AppName";E={($_.CustomFields['Application name'])}},@{L="AppOnwer";E={($_.CustomFields['VRM Owner'])}},@{L="UsageGB";E={ [math]::Round(($_.get_UsedSpaceGB()),0) }} | ft -AutoSize

(Get-Datastore GT-NETAPP-AFFA800-6737-10 | Get-VM | Get-HardDisk | where { $_.filename -match "GT-NETAPP-AFFA800-6737-10"} | measure -Property CapacityGB -Sum).Sum

##########################




Get-DatastoreCluster -Location glete | ? { $_.Name -match "hitachi" } | % {
    $clsdsname = $_.Name
    $clsdscapacity = [math]::Round(([math]::Round(($_.CapacityGB),0)/1024),2)
    $clsdscapacityfree = [math]::Round(([math]::Round(($_.FreeSpaceGB),0)/1024),2)

    $clsdscapacityUsage = [math]::Round(($clsdscapacity - $clsdscapacityfree),2)

    $item = [PSCustomObject]@{
        Name = $clsdsname
        CapacityGb = $clsdscapacity
        CapacitySpaceGB = $clsdscapacityfree
        CapacityUsageGB = $clsdscapacityUsage
    }

    $item

}



Get-Cluster -Location glete | Get-VM | where { $_.powerstate -eq "PoweredOn"} | Get-CDDrive | where { $_.IsoPath -match '\['} | select parent,isopath | ft -AutoSize| Set-CDDrive -NoMedia -Confirm:$false


$vms = Get-Content -Path C:\Users\ednascimento\Documents\vms_valida.txt

$vmsall = [string]$vms.toUpper() -split(' ')

function get-onwervms {

foreach ( $v in $vmsall) {
   $vm =  Get-VM $v 
   
   if ( $vm -eq "") {
        $vm | Out-Null
        Write-Host "$v nao localizada" -ForegroundColor Red
   } else {
        $vm | % {
     $name = $_.name
     $onwer = ($_).ExtensionData.CustomValue.value | select -First 1 
     $folder = $_.folder
     $appname = ($_).ExtensionData.CustomValue.value[3]

     $item = [PSCustomObject]@{
        Name = $name
        Onwer = $onwer
        Folder = $folder
        App = $appname
    }
    $item 

    } 
  }
   
   
    #| select name,@{L="Onwer";E={ $_.ExtensionData.CustomValue.value[0] } },folder
 }

}


$nome = "GTVMCDWEB0279" 
$vm = Get-VM $nome | Out-Null



############

function Get-pnginfra {
    param(
        [string]$dc
    )

    function Get-info {
    
        Get-Folder -Type VM -Location $dc | where { $_.Name -match "VMware" -or $_.Name -match "dhcp" -or $_.Name -match "dns" }  | Get-VM | where { $_.powerstate -eq "PoweredOn" }| % {
        $name = $_.name 
        $ip = $_.guest.ipaddress[0]
        $func = ""
        $ptg =  ($_ | Get-NetworkAdapter).NetworkName
         $vlan = (Get-VDPortgroup -Name $ptg).VlanConfiguration.vlanid

        if ($name -match "vcen" ){
            $func = "VMware vCenter Server Appliance"
        } elseif ($name -match "VROPS") {
            $func = "vRealize Operations Manager Appliance"
        } elseif ( $name -match "SKYLINE") {
            $func = "Skyline VA"
        } elseif ($name -match "LCM") {
            $func = "VMware vRealize Suite Life Cycle Manager Appliance" 
        } elseif ($name -match "VRO") {
            $func = "VMware vRealize Orchestrator Appliance"
        } elseif ($name -match "IDM") {
            $func = "VMware Identity Manager Appliance"
        } elseif ($name -match "REPL") {
            $func = "VMware vsphere replication Appliance"
        } elseif ($name -match "VMVRA" -or $name -match "VRAQA0" -or $name -match "VRADEV" ) {
            $func = "vRealize Automation Applaince"
        } elseif ($name -match "VMVRAWEB") {
            $func = "vRealize Automation IaaS component"
        } elseif ($name -match "VMDEM") {
            $func = "vRealize Automation IaaS component"
        } elseif ($name -match "VMMNG") {
            $func = "vRealize Automation IaaS component"
        } elseif ($name -match "VMAGT") {
            $func = "vRealize Automation IaaS component"
        } elseif ($name -match "VMSQL") {
            $func = "vRealize Automation IaaS component" 
        } elseif ($name -match "VMLOG") {
            $func = "VMware vRealize Log Insight Appliance"
        } elseif ($name -match "PXE0") {
            $func = "DHCP server from infraestruture PXE"
        } elseif ($name -match "PXEWEB") {
            $func = "Server store reponse file from PXE infrestruture"
        } elseif ($name -match "TFTP0") {
            $func = "Server store image from VMware ESXi"
        } elseif ($name -match "PANGEA") {
            $func = "SMTP Server from  Pangea teams - Auth @uolinc.com"
        } elseif ($name -match "dns_recursive") {
            $func = "Server DNS recursive server from PRD"
        } elseif ($name -match "_qa_recursive") {
            $func = "Server DNS recursive server from QA"
        } elseif ($name -match "_dev_recursive") {
            $func = "Server DNS recursive server from DEV" 
        } elseif ($name -match "VMNTPDNS") {
            $func = "Server DNS and NTP PROD zone .pags"
        } elseif ($name -match "dhcp_primary" -or $name -match "dhcp_secondary") {
            $func = "Server DHCPD from PRD envoriemnt"
        } elseif ($name -match "-DEV$" ) {
            $func = "Server DHCPD from DEV envoriemnt "
        } elseif ($name -match "-QA$") {
             $func = "Server DHCPD from QA envoriemnt "
        }


       $item = [PSCustomObject]@{
        Nome = $name
        Ip = $ip
        Funcao = $func
        Rede = $ptg
        vlan = $vlan

       }
       $item

       } | ft -AutoSize

    }

    if ($dc -eq "Glete"  -or $dc -eq "Tambore" ) {
        {get-info}
    } else {
        exit 0
        Write-Host "Site nao llocalizado"  -ForegroundColor Red
    }

    

}
 
 
 
 #| select name,notes,@{L="Ip";E={ $_.guest.ipaddress[0] }}


$listhts = Get-Content -Path C:\Users\ednascimento\Documents\list_hosts.txt

foreach ($h in $listhts) {
    
    #$h = [string]$h.ToLower() + ".host.pags"
    $h = [string]$h.ToLower()

    if ($h -match "p1" -or $h -match "p2" -or $h -match "p3"){
        $hosttmp = $h + ".host.pags"
    } else {
       $hosttmp = $h + ".pags"
    }

   
  $vmhost =  get-vmhost $hosttmp -ErrorAction Ignore | select name,@{L="Cluster";E={ $_.parent}}
  
    #$vmhost =  (get-vmhost | where { $_.Name -match "$h" }).Name

   if ($? -eq "True") {
       $vmhost 
       
   } else {
        #$vmhost
        Write-Host "$hosttmp não localizado" -ForegroundColor Red 
   }
} 


Get-VMHost |  % {
    $nome = $_.NetworkInfo.hostname
    $fullName = $_.Name
    $ip = $_.ExtensionData.config.Network.vnic[1].spec.ip.IpAddress
    $hyperversion = $_.ExtensionData.config.product.FullName

    $item =  [PSCustomObject]@{
        Hostname = $nome
        FullHostname = $fullName
        HypervisorResource = $hyperversion
        IpAddress = $ip
    }

    $item

} | clip


#########################


$hostsall = Get-VMHost

$result = foreach ($esxi in $hostsall) {
    Get-VMHosthba -VMHost $esxi -type FibreChannel | where{$_.STatus -eq 'online'} |

    Select  @{N="Host";E={$esxi.Name}},

        @{N='HBANodeWWN';E={$wwn = "{0:X}" -f $_.NodeWorldWideName; (0..7 | %{$wwn.Substring($_*2,2)}) -join ':'}},

        @{N='HBANodeWWP';E={$wwp = "{0:X}" -f $_.PortWorldWideName; (0..7 | %{$wwp.Substring($_*2,2)}) -join ':'}}

} 

$wwplistall = Get-Content C:\Users\ednascimento\Documents\wwpn_list.txt

foreach ( $h in $wwplistall) {
    $result | where { $_.HBANodeWWP -match "$h"}
}

 

 Get-VMHost |  % {
    $nome = $_.NetworkInfo.hostname
    $fullName = $_.Name
    $ip = $_.ExtensionData.config.Network.vnic[1].spec.ip.IpAddress
    $hyperversion = $_.ExtensionData.config.product.FullName
    $hostmemoryGB = [math]::Round(($_.ExtensionData.summary.hardware.MemorySize)/1024/1024 ,2)
    $hostCpupkg = $_.ExtensionData.summary.hardware.NumCpuPkgs
    $hostCpuCores = $_.ExtensionData.summary.hardware.NumCpuCores
    $hostCpuThreads = $_.ExtensionData.summary.hardware.NumCpuThreads 

    $item =  [PSCustomObject]@{
        Hostname = $nome
        FullHostname = $fullName
        HypervisorResource = $hyperversion
        IpAddress = $ip
        MemorySize = $hostmemoryGB
        NumCpuPkgs = $hostCpupkg
        NumCpuCores = $hostCpuCores
        NumCpuThreads = $hostCpuThreads

    }

    $item

} | ft -AutoSize



$vms = Get-Content -Path C:\Users\ednascimento\Documents\list_vms.txt
$vms = @("GTVMJUMP132",
          "GTVMJUMP132", 
          "GTVMJUMP129", 
           "GTVMJUMP118",
           "GTVMJUMP114",
           "GTVMJUMP234",
            "GTVMJUMP104",
            "GTVMJUMP0039",
            "GTVMFNCAPPB0A6",
            "GTVMFNCAPP8958",
            "GTVMFNCAPPED2D",
            "GTVMFNCAPPB82E",			
            "TBVMJUMP132", 	
            "TBVMFNCAPP0BF3"


)

$teste = foreach ( $v in $vms) {
    $vmname = (Get-vRAResource -Name $v).Name
    $vmowner = (Get-vRAResource -Name $v).Owners
    $vmbu = (Get-vRAResource -Name $v).BusinessGroupName
    $vmcpu = (Get-vRAResource -Name $v).Data.MachineCPU
    $vmmem = (Get-vRAResource -Name $v).Data.MachineMemory
    #Get-vRAResource -Name $v | select name,Owners,BusinessGroupName,@{l="Cpu";E={ $_.Data.VirtualMachine.CPU.Count}} 

    $item = [PSCustomObject]@{
        Name = $vmname
        Owner = $vmowner
        Bu = $vmbu
        Cpu = $vmcpu
        MemoryMb = $vmmem
    
    }
    $item 
} 

$teste | ft -AutoSize

$userad = net user k_corp_kuber8 /domain | findstr /I "Name" | findstr /I "user"]
$userad -replace("User name", "")[2]

function Get-UserAd {

    param(
        [string]$user
    )

    #$user = Read-Host "Digite o nome user"

    $user.ToLower();
    $userad = net user $user /domain > $null 2>&1
     
    if ($? -eq "True" ) {
        Write-Host "$user localizado " -ForegroundColor Green
    } else {
        Write-Host "$user não localizado " -ForegroundColor Red
    }


}


######################################################################################################

$vmsec = @("GTVMESECWEB1F67",
"GTVMESECWEB3568",
"GTVMESECWEB3A61",
"GTVMESECWEB435E",
"GTVMESECWEB5205",
"GTVMESECWEB738F",
"GTVMESECWEB77D3",
"GTVMESECWEB9C8D",
"GTVMESECWEBD282",
"GTVMESECWEBE634",
"TBVMESECWEB004B",
"TBVMESECWEB387D",
"TBVMESECWEB4C44",
"TBVMESECWEB675F",
"TBVMESECWEB827F",
"TBVMESECWEB871F",
"TBVMESECWEBB0CD",
"TBVMESECWEBC8A9",
"TBVMESECWEBD490",
"TBVMESECWEBD9D4" )

foreach ($v in $vmsec) {
    $vmsite = (Get-VM $v | Get-Datacenter).Name
    

    if ($vmsite -eq "Glete") {
        Get-VM $v | Get-NetworkAdapter | Set-NetworkAdapter -NetworkName 'common|APP-COMMON|EPG-VAULT-QA-DEV-GT' -Confirm:$false | Out-Null
         Get-VM $v | Get-NetworkAdapter | select parent,NetworkName

    } else {
        Get-VM $v | Get-NetworkAdapter | Set-NetworkAdapter -NetworkName 'common|APP-COMMON|EPG-VAULT-QA-DEV-TB' -Confirm:$false | Out-Null
        Get-VM $v | Get-NetworkAdapter | select parent,NetworkName
    }
}


Get-VM -Location glete | % {
    $vmname = $_.name
    $appname = $_.ExtensionData.CustomValue[3].value
    $vmpower = $_.PowerState

    $item = [PSCustomObject]@{
        Name = $vmname
        AppName = $appname
        Power = $vmpower
    }
    $item | where {$_.AppName -match "w-pentesting-qa-gt" }

}


Get-VM -Location glete | where { $_.PowerState -eq "PoweredOn"} | % {
    $vmname = $_.Name
    $vmcpu = $_.NumCpu
    $vmmem = $_.MemoryGB
    $vmstoragep = [math]::Round($_.ProvisionedSpaceGB,2)
    #$vmstorageu = [math]::Round($_.UsedSpaceGB,2)get_UsedSpaceGB
    $vmstorageu = [math]::Round($_.get_UsedSpaceGB(),2)
    $vmdatastore = ($_ | Get-Datastore | Get-DatastoreCluster).Name
    #$vapponwer = ($_).ExtensionData.CustomValue.value | select -First 1
    $vappname = ($_.CustomFields['Application name'])

    $item = [PsCustomObject]@{
        Name = $vmname
        NumCpu = $vmcpu
        MemoryGB = $vmmem
        vStorageProvisioned = $vmstoragep
        vStorageUsage = $vmstorageu
        DatastoreClu = $vmdatastore
        AppName = $vappname
    }

    $item 

} | sort -Property vStorageUsage | ft -AutoSize | clip


[math]::Round((Get-VM | where { $_.Powerstate -eq "PoweredOF"} | measure -Property UsedSpaceGB -Sum).Sum, 0)


Get-VMhost | where { $_.Name -match "tbesxch03" -or $_.Name -match "tbesxqadevp1ch03" } | select name,@{L="Cluster";E={ ($_ | get-cluster).name }}

$listvms = Get-Content C:\Users\ednascimento\Documents\vms_infra.txt

foreach ($v in $listvms)
{
    $vm = Get-VM -Name $v | %{
        $vmname = $_.Name
        $vmip = $_.Guest.IPAddress[0]
        $vmnetwork = ($_ |  get-networkadapter | where { $_.networkname -match "DEV"}).NetworkName

        $item = [PsCustomObject]@{
            Nome = $vmname
            Ip = $vmip
            Net = $vmnetwork
        }
        $item

    
    } # | get-networkadapter | where { $_.networkname -match "DEV"} | select parent,networkname
    $vm 
} 




$ips = @('10.184.27.86','10.186.17.173','10.186.25.188')

foreach ($i in $ips){
   
   $vms = @() 
   [string]$v = (Get-VM | where { $_.Guest.IPAddress -eq $i}).Name
   $vms += $v
   #$vms
   foreach ($r in $vms) {
       Get-vRAResource -Name $r | select name,BusinessGroupName
   }
}

<#
for ($i = 0 ; $i -le $ips.count ; $i++) 
{
    $vraresouce = @()
    $vms = (Get-VM | where { $_.Guest.IPAddress -eq $ips[$i] }).Name
    #$vms += $vraresouce
    $vms
    <#foreach ($r in $vraresouce) {
        Get-vRAResource -Name $r | select name
    }
    #>
}
#>


$v = Get-Content C:\Users\ednascimento\Documents\vm.txt

for ($i = 0 ; $i -le $v.Count ; $i++)
{
    #Write-Host $i
    $vm = Get-VM $v[$i] | Out-Null
    if ($? -eq 0) {
        try {
            $vm
        }
        catch {
            Error
        }
    }
}

##################


$hostnames = @("ip-10-184-41-10","ip-10-184-41-9","ip-10-184-32-224","ip-10-184-32-225")

foreach ($hostname in $hostnames) {
    $hostnamenew = $hostname.Replace("-",".").Replace("ip.","")
    Get-VM -Location glete| where { $_.Guest.IPAddress -eq "$hostnamenew" } | select name,vmhost
    <#
        if ($hostnamenew -match "10.184." ) {
            Get-VM -Location glete | where { $_.Guest.IPAddress -eq "$hostnamenew"} 
        } elseif ($hostnamenew -match "10.186.") {
            Get-VM -Location tambore | where { $_.Guest.IPAddress -eq "$hostnamenew"} 
        }
    #>
    
}

Get-VM *AGT*,*MNG*,*DEM*,*VRAWEB* | sort -Property name | % {

    $name = $_.Name
    $guestname = $_.Guest.HostName
    $snapname =  $name + "_" + "SNAP" + "_" + "SDPE-701313" 
    $item = [PsCustomObject]@{
        Nome = $name
        Hostname = $guestname
    }
    $item 

    #New-Snapshot -Name $snapname -VM $name -Confirm:$false
} |  ft -AutoSize

################################

Get-VM GTVMOPERAPPE65A | Get-VMHost | %  {
    $numcpupkg = $_.ExtensionData.hardware.CpuInfo.NumCpuPackages
    $numcpucore = $_.ExtensionData.hardware.CpuInfo.NumCpuCores
    $numcputhreads = $_.ExtensionData.hardware.CpuInfo.NumCpuThreads
    $cpumodel = $_.ProcessorType

    $item = [PsCustomObject]@{
        Model = $cpumodel
        Socketes = $numcpupkg
        Cores = $numcpucore
        Threads = $numcputhreads
    }

    $item
}


$vms = @("GTVMIDCAPP2EC8", 
    "GTVMIDCAPP99B8", 
    "GTVMIDCWEB0868", 
    "GTVMIDCWEBB9DD", 
    "GTVMOPERAPP918C",
    "GTVMOPERAPPEA30",
    "GTVMPGCAPP04EE", 
    "GTVMPGCAPP07AF", 
    "GTVMPGCAPP132F", 
    "GTVMPGCAPP42F8", 
    "GTVMPGCAPP60FB", 
    "GTVMPGCAPP6390", 
    "GTVMPGCAPP7CFE", 
    "GTVMPGCAPPCD94", 
    "GTVMPGCAPPD65B", 
    "GTVMPGCAPPDCC4", 
    "GTVMPGCAPPF3BB", 
    "GTVMPGCAPPFDCD", 
    "GTVMPGCWEB7168", 
    "GTVMPGCWEB79EB", 
    "GTVMPGCWEBB429", 
    "GTVMPOSAPPBCC6", 
    "TBVMIDCAPP05A3", 
    "TBVMIDCAPPA2B9", 
    "TBVMPGCAPP166F", 
    "TBVMPGCAPP1958", 
    "TBVMPGCAPP4BF4", 
    "TBVMPGCAPP7104", 
    "TBVMPGCAPP727F", 
    "TBVMPGCAPP7EEB", 
    "TBVMPGCAPP8F71", 
    "TBVMPGCAPPC211", 
    "TBVMPGCAPPCD07", 
    "TBVMPGCAPPE96A", 
    "TBVMPGCAPPFA2B", 
    "TBVMPGCAPPFCB3", 
    "TBVMPGCWEB996C", 
    "TBVMPGCWEBC661", 
    "TBVMPGCWEBF41E"
)

foreach ($v in $vms) {
    $vm = Get-VM $v 
    
    if ($vm.name -match '^gt') {
        $vm | Get-HardDisk | Get-SpbmEntityConfiguration | Set-SpbmEntityConfiguration -StoragePolicy 'GT-Default VM storage I/O limit' -Confirm:$false | Out-Null
        #Write-Host 'GT ' + $vm.Name 
    }   elseif ($vm.name -match '^tb') {
        #Write-Host 'TB ' + $vm.name
        $vm | Get-HardDisk | Get-SpbmEntityConfiguration | Set-SpbmEntityConfiguration -StoragePolicy 'TB-Default VM storage I/O limit' -Confirm:$false | Out-Null
    }
}

$vm = foreach ($v in $vms) {
    Get-VM $v | % {
        $nome = $_.Name
        $hostname = $_.Guest.HostName

        $item = [PsCustomObject]@{
            Nome = $nome
            Hostname = $hostname
        }
        $item
    
    } 
}
#############

Get-VM  | select -first 1 | % {
    $name = $_.Name 
    $harddisk = ($_ | Get-HardDisk | Get-SpbmEntityConfiguration).Entity
    $storagepolicy = ($_ | Get-HardDisk | Get-SpbmEntityConfiguration).StoragePolicy

    $item = [PsCustomObject]@{
        VmName = $name
        HardDisk = $harddisk[0]
        StoragePolicy = $storagepolicy[0]
    
    }
    $item

} | ft -AutoSize

$vmspoll = @("GTVMGSECAPP12D8", 
    "GTVMGSECAPPFC03", 
    "GTVMGSECAPP7E8F", 
    "GTVMGSECAPPB0DA", 
    "GTVMGSECAPPB7C4", 
    "TBVMGSECAPPFD17",  
    "TBVMGSECAPP4839"  
)

foreach ($v in $vmspoll) {
    $vmcluds = (Get-VM $v | Get-Datastore | Get-DatastoreCluster).Name
    $vmname = "$v $vmcluds" 
    $vmname
}


Get-VMHost | % {
    $hostname = ($_ | Get-VMHostNetwork).HostName
    $hostdomain = ($_ | Get-VMHostNetwork).DomainName

    $item = [PsCustomObject]@{
        Nome = $hostname
        Domain = $hostdomain
    }

    $item

} | Sort -Property Domain | ft -AutoSize

$ips = @("10.189.32.204",
"10.188.32.73",
"10.189.40.129",
"10.191.149.211",
"10.191.17.198",
"10.188.40.228",
"10.189.45.30",
"10.188.33.27",
"10.189.34.152",
"10.188.33.77",
"10.188.40.222",
"10.189.40.213",
"10.191.145.109",
"10.188.33.111",
"10.188.41.70",
"10.188.32.165",
"10.189.34.124",
"10.184.33.117",
"10.188.41.98",
"10.188.33.86",
"10.189.37.108",
"10.189.34.183",
"10.188.33.90",
"10.188.40.62",
"10.189.37.43",
"10.189.40.19",
"10.189.41.220",
"10.188.33.26",
"10.186.38.40",
"10.191.16.115",
"10.189.37.89",
"10.188.32.53",
"10.188.33.81",
"10.188.40.219",
"10.191.17.158",
"10.189.34.94",
"10.189.34.140",
"10.188.32.72",
"10.188.33.110",
"10.188.33.31")

foreach ($ip in $ips) {
    Get-VM | where { $_.Guest.IPAddress -eq "$ip"} | select name,@{L="Onwer";E={($_.CustomFields['VRM Owner'])}}

}


((Get-VM | select -First 1 | Get-HardDisk | Get-SpbmEntityConfiguration).Entity).parent

$sptb = ((Get-VM -Location tambore | where { $_.PowerState -eq "PoweredOn" -and $_.Name -match "VMDB"} | Get-HardDisk | Get-SpbmEntityConfiguration | where { $_.ComplianceStatus -eq "none"}).Entity).parent.name | Get-Unique
$spgt = ((Get-VM -Location glete | where { $_.PowerState -eq "PoweredOn"} | Get-HardDisk | Get-SpbmEntityConfiguration | where { $_.ComplianceStatus -eq "none"}).Entity).parent.name | Get-Unique

$vmspgt = ((Get-VM -Location glete | where { $_.PowerState -eq "PoweredOn"} | Get-HardDisk | Get-SpbmEntityConfiguration | where { $_.ComplianceStatus -eq "none"}).Entity).parent.name | Get-Unique
$vmsptb = ((Get-VM -Location tambore | where { $_.PowerState -eq "PoweredOn"} | Get-HardDisk | Get-SpbmEntityConfiguration | where { $_.ComplianceStatus -eq "none"}).Entity).parent.name | Get-Unique

$vms = Get-Content -Path C:\Users\ednascimento\Documents\vm.txt


$vms_list = foreach ($vm in $vms) {
    Get-VM $vm | % {
      $name = $_.Name
      $harddisksp = ($_ | Get-HardDisk | Get-SpbmEntityConfiguration).StoragePolicy
      
      $tbdefault = "Datastore Default"
      $spdefault2k = "GT-Default VM storage I/O limit"
      $spstatus = ($_ | Get-HardDisk | Get-SpbmEntityConfiguration).ComplianceStatus

      <#
      if ($harddisksp -eq $null) {
         $_ | Get-HardDisk | Set-SpbmEntityConfiguration -StoragePolicy $spdefault2k -Confirm:$false
            $item = [PsCustomObject]@{
                Nome = $name
                StoragePolicy = $harddisksp
            }
             $item
        }
        #> 

     
      $item = [PsCustomObject]@{
                Nome = $name
                StoragePolicy = $harddisksp
            }
      $item
     
   }
}   

$vms_list | ft -AutoSize


Get-VMHost -Location tambore | select name | Get-Random



$teste -eq $null

$teste

#####################

$vms = @("GTVMPOSAPPAECE","TBVMPOSAPP5877","TBVMPOSAPP3C8B","GTVMPOSAPP0F18","GTVMPOSAPP1EEC","GTVMPOSAPPCA5F","TBVMPOSAPPAB80","TBVMPOSAPPD4AB")

foreach ($i in $vms)
{
    Get-VM $i | % {
        $nome = $_.name
        $harddisk = ($_ | Get-HardDisk).CapacityGB
        $harddisksp = ($_ | Get-HardDisk | Get-SpbmEntityConfiguration).storagepolicy
        $item = [PsCustomObject]@{
            Nome = $nome
            Disk = $harddisk
            StoragePolicy = $harddisksp
        }
        $item
    }
}



#########################################

function Set-AllowIP {
     param(
        [string]$clu
    )

Get-Cluster $clu | Get-VMHost | where { $_.ConnectionState -eq "Maintenance" -or $_.connectionState -eq "Connected"} | % {
    
  
    $name = $_.name
    $vhost = get-vmhost -name $name
    $esxcli = Get-Esxcli -VMHost $vhost -V2
    $arguments = @{
        allowedall = $false
        enabled = $true
        rulesetid = 'sshServer'
    }

    $esxcli.network.firewall.ruleset.set.Invoke($arguments)

    
    $arguments2 = @{

        rulesetid = 'sshServer'
        ipaddress = '10.190.0.10'
    }

    $arguments3 = @{

        rulesetid = 'sshServer'
        ipaddress = '10.190.0.11'

    }

    $arguments4 = @{

        rulesetid = 'sshServer'
        ipaddress = '10.190.0.12'

    }

    $arguments5 = @{

        rulesetid = 'sshServer'
        ipaddress = '10.190.0.16'

    }

    $arguments6 = @{

        rulesetid = 'sshServer'
        ipaddress = '10.190.32.31'

    }

    $arguments7 = @{

        rulesetid = 'sshServer'
        ipaddress = '10.190.32.32'

    }


    $esxcli.network.firewall.ruleset.allowedip.add.Invoke($arguments2)
    $esxcli.network.firewall.ruleset.allowedip.add.Invoke($arguments3)
    $esxcli.network.firewall.ruleset.allowedip.add.Invoke($arguments4)
    $esxcli.network.firewall.ruleset.allowedip.add.Invoke($arguments5)
    $esxcli.network.firewall.ruleset.allowedip.add.Invoke($arguments6)
    $esxcli.network.firewall.ruleset.allowedip.add.Invoke($arguments7)


    }
    

}


sum({ Cluster Compute Resource: Memory|Total Capacity , depth=1}) - sum({ Cluster Compute Resource: Memory|Consumed , depth=1})


$ips = @("10.184.18.91","10.184.26.103","10.184.26.110","10.184.26.111","10.184.18.92")

foreach ($ip in $ips)
{
    Get-VM -Location glete | where { $_.guest.IPAddress -eq $ip } | % {
        $nome = $_.Name
        $epgName = ($_ | Get-NetworkAdapter).NetworkName
        $ipvm = $_ | Get-VMGuest | % { $_.IPAddress[0] }

        $item = [PsCustomObject] @{
            NOME = $nome
            IP = $ipvm
            EPG = $epgName
            
        }

        $item
    
    }
}



##############

$datastore = get-datastore | select -First 1


Get-DatastoreCluster GT-HITACHI-QADEV-001 | Get-Datastore | % {
    $name = $_.ExtensionData.Info.vmfs.name
    $naa = $_.ExtensionData.Info.vmfs.extent.diskName
    $ssd = $_.ExtensionData.info.vmfs.ssd

    $item = [PsCustomObject]@{
        Nome = $name
        Naa = $naa
        Ssd = $ssd
    }

    $item
} | ft -AutoSize 



Get-VM *VMFMCV01* | % {
    $name = $_.Name
    $clu = ($_ | get-cluster).Name
    $dsclu = ($_ | Get-Datastore | Get-DatastoreCluster).Name
    $notas = $_.notes

    $item = [PscustomObject]@{
        Name = $name
        Cluster = $clu
        ClusterDatastore = $dsclu
        Notes = $notas
    }
    $item
} | ft -AutoSize


get-cluster | get-vmhost | % {
    $totalcapacityalloc = ($_.MemoryTotalGB | measure -Property MemoryTotalGB -Sum).Sum
    $totalcapacityusage = [math]::Round(($_ | measure -Property MemoryUsageGB -Sum).Sum, 2)
    $totalcapacityfree = [math]::Round(($totalcapacityalloc - $totalcapacityusage),2)

    $item = [PscustomObject]@{
        TotalMemAlloc = $totalcapacityalloc
    }
    $item
} 


$list = foreach ($i in $vms) {
    Get-VM | where { $_.Name -eq $i } | % {
        $nome = $_.Name
        $hostname = $_.guest.HostName
        $storagep = ($_ | Get-HardDisk | Get-SpbmEntityConfiguration).StoragePolicy
    

        $item = [pscustomobject]@{
            Name = $nome
            Hostname = $hostname
            StoragePolicy = $storagep
        }

        $item
    }
}

$list | ft -AutoSize

            
    
    
    #| select name,@{L="HostName";E={$_.guest.hostname }},@{L="StoragePolicy";E={ ($_ | Get-HardDisk | Get-SpbmEntityConfiguration).StoragePolicy } } 


get-cluster | % {
    $name = $_.Name
    $numHost = ($_ | Get-VMHost).count

    
         $item = [PscustomObject]@{
            Name = $name
            NumHost = $numHost
         }
        $item 
   
} | where { $_.NumHost -ne 0 } | sort -Property name  | ft -AutoSize


###

Get-VM TBVMFTDV01 | Get-NetworkAdapter | foreach {
    [array]$network = $_.networkname
    foreach ($pvlan in $network) {
         Get-VDPortgroup | ? { $_.Name -eq $pvlan} | select name,VDSwitch 
    } 
} | ft -AutoSize


$vmdb = Get-VM TBVMDB037
$spdb = Get-SpbmStoragePolicy -Name "TB-HighPerformance 20K"
$count = 0 
while ($count -le 11) {
   $count++
   #$count
   New-HardDisk -VM $vmdb -CapacityGB 2048 -StorageFormat Thin -StoragePolicy $spdb -Datastore ( (Get-DatastoreCluster TB-HITACHI-PROD-001 | Get-Datastore | Get-Random).name ) -Confirm:$false
}

$vmdb | Get-HardDisk | select parent,name,capacitygb

$qtdedstb = (Get-Datastore -Location tambore | where { $_.CapacityGB -eq '8,191.750' }).count
$qtdedsgt = (Get-Datastore -Location glete | where { $_.CapacityGB -eq '8,191.750' }).count
$dstotal = $qtdedstb + $qtdedsgt 
Write-Host
Write-Host "Qtde datastore site Tambore $qtdedstb"
Write-Host
Write-Host "Qtde datastore site Glete $qtdedsgt" 
Write-Host
Write-Host "Total Datastore 8TB: $dstotal"  



$ips = @("10.188.30.159","10.189.44.254","10.189.24.222","10.188.31.98","10.188.33.133")

foreach ($ip in $ips) {
    Get-VM | where { $_.Guest.IPAddress -eq "$ip"}
}


Get-Vm -location glete | % {
    $name = $_.name 
    $ifidc = $_ | Get-NetworkAdapter | where { (($_.NetworkName -match "EPG-IDC" -or $_.NetworkName -match "Tn-PROD")).NetworkName }
    $rp = ($_ | Get-ResourcePool).Name
    $dbtype = (($_ | Get-TagAssignment).tag).name

    if ($ifidc -eq "True" -or $dbtype -eq "ORACLE" ) 
            {
                $item = [PscustomObject]@{
                    Nome = $name
                    Tipo = $dbtype
                    Network = $ifidc.networkname
                }
                $item
            }

   <#
    try {
            if ($ifidc -eq "True" -and $dbtype -eq "MONGODB" ) 
            {
                $item = [PscustomObject]@{
                    Nome = $name
                    Tipo = $dbtype
                }
                $item
            }
    }
    
    catch {
        "Error" 
    }
    #>

}


get-vm -Location glete | where { $_.PowerState -eq "PoweredOn"}| select name,@{L="Type";E={ (($_ | Get-TagAssignment).tag).Name[0] } },@{L="Net";E={ ($_ | Get-NetworkAdapter | where { $_.NetworkName -match 'EPG-IDC' }).NetworkName } } | where { $_.Type -eq "MONGODB" }

-or $_.NetworkName -match "EPG-IDC"


$vmsdb = Get-Content -Path C:\Users\ednascimento\Documents\vmsdb.txt

$all = foreach ($v in $vmsdb)
{
    Get-VM $v | select name,@{L="Type";E={ (($_ | Get-TagAssignment).tag).Name } }
}

function Update-Host {
      param(
        [string]$hostesxi
    )

    #$hostesxi = "tbesxp3ch01l08.host.pags"
   # $cluster = ((Get-VMHost $hostesxi).Parent).Name

   # $vms = Get-VMHost $hostesxi | Get-VM
     
     #foreach ($v in $vms) 
    # {
       # Move-VM -VM $v -Destination (get-cluster -Name $cluster | Get-VMHost | ? { $_.Name -ne $hostesxi | Get-Random}) -RunAsync
    # }
     

    
    $baselines = @("Critical Host Patches (Predefined)","Non-Critical Host Patches (Predefined)")

    foreach ($baseline in $baselines) 
    {
        Get-VMHost -Name $hostesxi | Set-VMHost -State Maintenance -confirm:$false
        scan-inventory -entity $hostesxi
        $basecommon = Get-Baseline -Name $baseline        
        Test-Compliance -Entity $hostesxi
        Copy-Patch -Entity $hostesxi
            #Stage-Patch -Entity $hostesxi
            #Update-Entity -Entity $hostesxi -Baseline $basecommon 
         for ($i=0 ; $i -lt $basecommon.Length ; $i++ ) 
         {
           Add-EntityBaseline -Baseline $basecommon[$i] -Entity $hostesxi -Confirm:$false 
           Update-Entity -Entity $hostesxi -Baseline $basecommon[$i] -ClusterDisableHighAvailability:$true -ClusterDisableFaultTolerance:$true -RunAsync -Confirm:$false
           
         }
        
        Set-VMHost -VMHost $hostesxi -State Connected -Confirm:$false

    }


}

for ($i=0 ; $i -le $basecommon.Length ; $i++ ) {
   $basecommon[$i] 
}

<#

$esxName = 'tbesxp3ch01l08.host.pags'
$cluster = Get-Cluster -VMHost $esxName



if($cluster.DrsAutomationLevel -ne 'FullyAutmated'){



Set-Cluster -Cluster $cluster -DrsAutomationLevel FullyAutomated -Confirm:$false



}



Set-VMHost -VMHost $esxName -State Maintenance -Confirm:$false
#>



$ips = @("10.184.33.87","10.184.33.86","10.184.33.85","10.186.38.26","10.186.34.197","10.186.35.3","10.184.33.90","10.184.33.92","10.184.41.128","10.186.46.53","10.186.34.194","10.186.34.195")

foreach ($ip in $ips) 
{
    $vm = Get-VM | where { $_.Guest.IPAddress -eq "$ip"}

    if ($vm.name -match "^GT" ) {
        $vm | Get-HardDisk | Set-SpbmEntityConfiguration -StoragePolicy 'GT-HighPerformance 10k' -Confirm:$false
    } else {
        $vm | Get-HardDisk | Set-SpbmEntityConfiguration -StoragePolicy 'TB-HighPerformance 10k' -Confirm:$false
    }
} 

function Get-vLan {
    param(
        [string]$vlan,
        [string]$name
    )

    Get-VDPortgroup | where { $_.vlanconfiguration -match "$vlan" -or $_.Name -match "$name"}
}

$vmsall = @()
$auth = Get-VICredentialStoreItem
$user = $auth.user[0].split("\")[1] + "@dc.pags"
$allvms = @()
$vramodule = Import-Module C:\Users\ednascimento\Documents\powervra.3.7.0\PowervRA.psm1
$convraprd = Connect-vRAServer -Server cloud.intranet.pags -Tenant pagseguro -Username $user
$convradev = Connect-vRAServer -Server cloud.intranet.pags -Tenant pagseguro-dev -Username $user
$vmsf = Get-Content -Path C:\Users\ednascimento\Documents\vms_furlan.txt | Get-Random -Count 5


foreach ($vm in $vmsf) {
    

    if ($vm -match "^10.186." ) {
        Get-VM -Location tambore| where { $_.Guest.IPAddress -eq $vm }
    }

    $allvms =+ $vm
}


foreach ($v in $vmsf) {
    #$vmcust = $v.Replace("-",".").replace(".host.pags","").replace("ip.","")
    $vm = Get-VM | where { $_.Guest.IPAddress -eq "$v" }

    $row = "" | select VMName, Onwer, Ip
    $row.VMName = (Get-vRAResource -Name $vm.name).Name
    $row.Onwer = (Get-vRAResource -Name $vm.name).owners.split(" ")
    $row.Ip = (Get-vRAResource -Name $vm.name).data.ip_address
    $vmsall += $row
}

$vmsall


Import-Module C:\Users\ednascimento\Documents\powervra.3.7.0\PowervRA.psm1

function Get-CentOSIso {

    param (
        [string]$version
    )


$srcfile = "http://nyc.mirrors.clouvider.net/CentOS/7.9.2009/isos/x86_64/CentOS-7-x86_64-DVD-2009.iso" 
$dstfile = "C:\Users\ednascimento\Downloads\$fileCetOS" 
$filename = $dstfile.split
$fileIso = Invoke-WebRequest http://nyc.mirrors.clouvider.net/CentOS/7.9.2009/isos/x86_64 
$fileCetOS = $fileIso.links.href | where { $_ -match "CentOS-7-x86_64-DVD" -and $_ -match ".iso"}
$filecentosversion = $fileCetOS.split("-")[-1].split(".")[0]
$contentLGt = Get-ContentLibrary | select -First 1
$fileiso = "C:\Users\ednascimento\Downloads\$fileCetOS"

$filehash = (Invoke-WebRequest -Uri http://nyc.mirrors.clouvider.net/CentOS/7.9.2009/isos/x86_64/sha256sum.txt).content | Out-File -FilePath C:\Users\ednascimento\Downloads\$fileCetOS.txt
$hashremotefile256 = (Get-Content C:\Users\ednascimento\Downloads\$fileCetOS.txt | % { ($_ | ? { $_ -match "CentOS-7-x86_64-DVD-2009.iso" })}).substring(0,64)

$filehashcentOs8 = Invoke-WebRequest -Uri http://mirror.sfo12.us.leaseweb.net/centos/8-stream/isos/x86_64/CHECKSUM -OutFile $path/hashcentos8.txt
$hashcentos8 = ((Get-Content .\hashcentos8.txt) | where { $_ -match "CentOS-Stream-8-x86_64-latest-dvd1.iso" }).split("=")[-1].Trim().Length




    if ($filecentosversion -gt "2009" ) {
        Write-Host "Old version $filecentosversion  $fileCetOS" -ForegroundColor Red
    } else {
        Write-Host "Current version $filecentosversion  $fileCetOS " -ForegroundColor Yellow
        sleep 5
        Write-Host ""
        Write-Host "Download $fileCetOS please wait ..." -ForegroundColor Green
        Invoke-WebRequest -Uri $srcfile -OutFile $dstfile 

        if ($fileIso -eq "$null") {
            Write-Host "Variable is empty ..." 
    
        } else {
            Write-Host "Defining variable of hash ..."
            $hashLocalfile256 = (Get-FileHash -Algorithm SHA256 $fileiso).hash.ToLower()
        }

        if ($hashremotefile256 -eq $hashLocalfile256) {
            Write-Host "File OK to upload .." -ForegroundColor Green
            Write-Host ""
            Write-Host "Doing uploading $fileCetOS to content Library $contentLGt " -ForegroundColor Yellow
            New-ContentLibraryItem -ContentLibrary $contentLGt -Name  $fileCetOS.split(".")[0] -Files $fileiso -Confirm:$false
        } else {
            Write-Host "File Conrrupt ..." -ForegroundColor Red  
        }
        
        
    }

}










function Set-1vCPU {
    $ips = @("10.188.24.186","10.188.24.187","10.189.17.97","10.189.17.99")
    #$ips = @("10.188.24.187","10.189.17.97","10.189.17.99")

    foreach ($ip in $ips) 
    {
        if ($ip -match '10.188' )
        {
            Get-VM -Location glete | where { $_.Guest.IPAddress -eq $ip}
        }
        
        if ($ip -match '10.189')
        {
            Get-VM -Location tambore | where { $_.Guest.IPAddress -eq $ip}
        }

        <#
        $vm = Get-VM| where { $_.Guest.IPAddress -eq $ip }
        
       
        $vm | Shutdown-VMGuest -Confirm:$false
        sleep 60
        $vm | Set-VM -Numcpu 1 -Confirm:$false
        $vm | Start-VM -Confirm:$false
        #>
    }
}


Get-VMHost -Location tambore | % {
    $name = ($_.Name).ToLower()
    $vmguestname = $_ | get-vm
    $hostname = ($vmguestname | get-vmguest).HostName | where { $_ -notmatch 'intranet.pags'} 
    
    $name = $hostname + '.' + 'host.pags' 
    $name
    #$name
    #ping -n 4 $name
}


Get-VICredentialStoreItem


$vmlist = Get-Content -Path C:\Users\ednascimento\Documents\vm.txt

foreach ($vm in $vmlist)
{
    $storagePolicy2k = Get-SpbmStoragePolicy 'TB-Default VM storage I/O limit'
    Get-VM $vm | Get-HardDisk | Set-SpbmEntityConfiguration -StoragePolicy $storagePolicy2k -Confirm:$false
}

$ips = Get-Content -Path C:\Users\ednascimento\Documents\ips.txt


$full = foreach ($ip in $ips) {


    if ($ip -match '10.188.126' -or $ip -match '10.188.8' -or '10.188.86' -or '10.188.87' -or '10.191.10' -or '10.191.13' -or '10.191.14' -or '10.191.17' -or '10.191.18' -or '10.191.21' -or '10.191.23' -or '10.191.41' -or '10.191.9') {
        Get-VM -Location glete | where { $_.guest.IPAddress -eq $ip } | select name,@{L="Ip";E={ $_.guest.IPAddress[0]}},@{L="Onwer";E={ $_.ExtensionData.Value.value[0] } }
    }

    if ($ip -match '10.191.145' -or $ip -match '10.191.173' -or $ip -match '10.191.251' -or $ip -match '10.191.251' -or $ip -match '10.189.126' -or $ip -match '10.189.86' -or $ip -match '10.189.87' -or $ip -match '10.191.137' -or $ip -match '10.191.173' -or $ip -match '10.191.251') {
        Get-VM -Location tambore | where { $_.guest.IPAddress -eq $ip } | select name,@{L="Ip";E={ $_.guest.IPAddress[0]}},@{L="Onwer";E={ $_.ExtensionData.Value.value[0] }  }
    }

}



$netqatb = (Get-VM TBVMFTDVQA01,TBVMFTDVQA02 | Get-NetworkAdapter).NetworkName | % { Get-VDPortgroup $_ | Get-VDSecurityPolicy } | ft -AutoSize
$netqagt = (Get-VM GTVMFTDVQA01,GTVMFTDVQA02 | Get-NetworkAdapter).NetworkName | % { Get-VDPortgroup $_ | Get-VDSecurityPolicy } | ft -AutoSize


$netdevgt = (Get-VM GTVMFTDVDEV01,GTVMFTDVDEV02 | Get-NetworkAdapter).NetworkName | % { Get-VDPortgroup $_ | Get-VDSecurityPolicy } | ft -AutoSize
$netdevtb = (Get-VM TBVMFTDVDEV01,TBVMFTDVDEV02 | Get-NetworkAdapter).NetworkName | % { Get-VDPortgroup $_ | Get-VDSecurityPolicy } | ft -AutoSize


$vmprod = Get-cluster GT-CLS-PRD-001 | Get-VM | where { $_.resourcepool -match 'Resources'} 
$vmjump = Get-cluster GT-CLS-PRD-001 | Get-VM  | where { $_.Name -match 'VMJUMP' } 
$rsjump = Get-cluster GT-CLS-PRD-001|Get-ResourcePool -Name PROD
foreach ($v in $vmprod) {
    Move-VM -VM $v -Destination $rsjump -Confirm:$false
}


foreach ($v in $vmprod) {
    $vm = Get-VM $v
    $spec = New-Object VMware.Vim.VirtualMachineRelocateSpec
    $spec.Pool = $rp.ExtensionData.MoRef
    $rp = Get-cluster GT-CLS-PRD-001|Get-ResourcePool -Name PROD
    $vm.ExtensionData.RelocateVM($spec,  [VMware.Vim.VirtualMachineMovePriority]::defaultPriority)
}

