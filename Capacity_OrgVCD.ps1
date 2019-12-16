Get-OrgVdc -Org (org name) -Name '(org vcd name)' | % {

    $Nome_orgVDC = $_.Name
    $TotalCpu = $_.CpuAllocationGhz
    $TotalCpuUsado = $_.CpuUsedGhz
    $TotalCpuLivre = ($TotalCpu - $TotalCpuUsado)
    $TotalMem = $_.MemoryAllocationGB
    $TotalMemUsage = $_.MemoryUsedGB
    $TotalMemFree = ($TotalMem - $TotalMemUsage)
    $TotalStorage = $_.StorageLimitGB
    $TotalStorageUsage = [math]::Round(($_.StorageUsedGB),0)
    $TotalStorageFree = [math]::Round(($TotalStorage - $TotalStorageUsage),0)
    $TotalQtdeVapp = $_.VAppCount
    $TotalQtdeVMs = (Get-OrgVdc -Org orgname -Name 'orgvcdname' | Get-CIVApp | Get-CIVM | measure).Count

    if ( $TotalCpuLivre -le "15" -and $TotalMemFree -le "10" -and $TotalStorageFree -le "2048"){
        
        Write-Progress -Activity "Calculando Capcity"
        Write-Host "+++++++++++++++++++++++++++++++++++" -ForegroundColor Yellow
        Write-Host "*** Capacity de CPU acabando..." -ForegroundColor Red 
        Write-Host "*** Capacity de Memoria acabando..." -ForegroundColor Red
        Write-host "*** Capacity de Storage acabando..." -ForegroundColor Red
        Write-Host "+++++++++++++++++++++++++++++++++++" -ForegroundColor Yellow
        $item = New-Object -TypeName psobject @{

            Nome = $Nome_orgVDC
            TotalCpu = $TotalCpu
            TotalCpuUsado = $TotalCpuUsado
            TotalCpuLivre = $TotalCpuLivre
            
            TotalMem = $TotalMem
            TotalMemUsado = $TotalMemUsage 
            TotalMemLivre = $TotalMemFree
            TotalStorage = $TotalStorage  
            TotalStorageUsado = $TotalStorageUsage
            TotalStorageLivre = $TotalStorageFree
            TotalQtdevApp = $TotalQtdeVapp
            TotalQtdeVMs = $TotalQtdeVMs
       }
       $item
    } else {
        $item = New-Object -TypeName psobject @{

            Nome = $Nome_orgVDC
            TotalCpu = $TotalCpu
            TotalCpuUsado = $TotalCpuUsado
            TotalCpuLivre = $TotalCpuLivre
            
            TotalMem = $TotalMem
            TotalMemUsado = $TotalMemUsage 
            TotalMemLivre = $TotalMemFree
            TotalStorage = $TotalStorage  
            TotalStorageUsado = $TotalStorageUsage
            TotalStorageLivre = $TotalStorageFree
            TotalQtdevApp = $TotalQtdeVapp
            TotalQtdeVMs = $TotalQtdeVMs
       }
    }
} | select Nome,TotalCpu,TotalCpuUsado,TotalCpuLivre,TotalMem,TotalMemUsado,TotalMemLivre,TotalStorage,TotalStorageUsado,TotalStorageLivre,TotalQtdevApp,TotalQtdeVMs
