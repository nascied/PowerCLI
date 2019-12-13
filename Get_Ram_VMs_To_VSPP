Get-VM | ? { $_.PowerState -eq "PoweredOn" } | % {
    
    $VMbig = [Math]::Round(($_.MemoryGB),0)
    $VMName = $_.Name
    $Memreplace = ($VMbig) -replace "(^$VMbig)","24" -as [decimal]
    $VMTotal = [math]::Round((get-vm | ? { $_.PowerState -eq "PoweredOn" -and $_.MemoryGB -le "24" } | measure -Property MemoryGB -Sum).Sum, 0)
    $VMMemCalc = [decimal]($Memreplace + $VMTotal)
    if ( $VMbig -gt "24"){
        $item = New-Object -TypeName psobject -Property @{
        Nome = $VMName
        TotalMemoria = $VMMemCalc
    }
    $item | select TotalMemoria
    } 
    
}
