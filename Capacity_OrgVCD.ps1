Get-OrgVdc -Org (oeg) -Name '(orgvcdname)' | % {

    $Nome_orgVDC = $_.Name
    $TotalCpu = $_.CpuAllocationGhz
    $TotalCpuUsado = $_.CpuUsedGhz
    $TotalCpuLivre = ($TotalCpu - $TotalCpuUsado)
    $TotalMem = $_.MemoryAllocationGB
    $TotalMemUsage = $_.MemoryUsedGB
    $TotalMemFree = ($TotalMem - $TotalMemUsage)
    $TotalStorage = $_.StorageLimitGB
    $TotalStorageUsage = $_.StorageUsedGB
    $TotalStorageFree = ($TotalStorage - $TotalStorageUsage) 

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
       }
    }
} | select Nome,TotalCpu,TotalCpuUsado,TotalCpuLivre,TotalMem,TotalMemUsado,TotalMemLivre,TotalStorage,TotalStorageUsado,TotalStorageLivre
