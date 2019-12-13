Get-OrgVdc -Org (nome da org) -Name '(Nome da org VCD)' | % {

    $Nome_orgVDC = $_.Name
    $CpuUsage = $_.CpuUsedGhz
    $TotalCPU = $_.CpuAllocationGhz
    $TotalMemory = $_.MemoryAllocationGB
    $MemUsage = $_.MemoryUsedGB
    $TotalStorage = $_.StorageLimitGB
    $StorageUsage = $_.StorageUsedGB

    $item = New-Object -TypeName psobject @{

        Nome = $Nome_orgVDC
        TotalCPU = $TotalCPU
        TotalCPUUsage = $CpuUsage
        TotalMemoria = $TotalMemory
        TotalMemusada = $MemUsage 
        TotalStorage = $TotalStorage
        TotalStorageUsage = $StorageUsage
        TotalFree = ($TotalMemory - $MemUsage)
   }
   $item 
} | select Nome,TotalCPU,TotalCPUUsage,TotalMemoria,TotalMemusada,TotalFree,TotalStorage,TotalStorageUsage | Sort-Object -Property Nome
