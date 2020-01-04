Get-VMHost | ? { $_.Name -match "*" } | Sort-Object -Property name | % {
    $version = $_.Version
    $build = $_.Build
    $nome = $_.Name 
    $ipaddress = $_ | Get-VMHostNetworkAdapter | ? { $_.Name -match "vmk0" } | % {
        $IP = $_.IP 
    }
    Write-Host "$nome + $IP + $version + $build" 
}
Write-Host "$nome --> $IP"
