# Auditoria inicial de Windows 10. SOLO LECTURA: no cambia configuraciones.
$ErrorActionPreference = 'Stop'
$controles = @()
function Registrar-Control {
    param([string]$Id,[string]$Nombre,[string]$Esperado,[string]$Actual,[string]$Estado,[string]$Detalle)
    $script:controles += [pscustomobject]@{id=$Id; nombre=$Nombre; esperado=$Esperado; actual=$Actual; estado=$Estado; detalle=$Detalle}
}

try {
    $perfiles = @(Get-NetFirewallProfile)
    $actual = ($perfiles | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join '; '
    $cumple = $perfiles.Count -gt 0 -and @($perfiles | Where-Object { $_.Enabled -ne $true }).Count -eq 0
    Registrar-Control 'FW-01' 'Firewall habilitado en todos los perfiles' 'Todos habilitados' $actual $(if($cumple){'Cumple'}else{'No cumple'}) 'Revisar los perfiles existentes.'
} catch { Registrar-Control 'FW-01' 'Firewall habilitado en todos los perfiles' 'Todos habilitados' 'No disponible' 'No evaluado' $_.Exception.Message }

try {
    $uac = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA'
    Registrar-Control 'UAC-01' 'UAC habilitado' 'EnableLUA=1' "EnableLUA=$uac" $(if($uac -eq 1){'Cumple'}else{'No cumple'}) 'Verificacion de Control de cuentas de usuario.'
} catch { Registrar-Control 'UAC-01' 'UAC habilitado' 'EnableLUA=1' 'No disponible' 'No evaluado' $_.Exception.Message }

try {
    $smb = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
    $estado = [string]$smb.State
    Registrar-Control 'SMB-01' 'SMBv1 deshabilitado' 'Disabled' $estado $(if($estado -eq 'Disabled'){'Cumple'}else{'No cumple'}) 'Si la caracteristica no esta disponible, registrar como No evaluado.'
} catch { Registrar-Control 'SMB-01' 'SMBv1 deshabilitado' 'Disabled' 'No disponible' 'No evaluado' $_.Exception.Message }

try {
    $rdp = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections'
    if ($rdp.fDenyTSConnections -eq 1) {
        Registrar-Control 'RDP-01' 'RDP deshabilitado o NLA habilitado' 'RDP deshabilitado o NLA=1' 'RDP deshabilitado' 'Cumple' 'No se permite acceso remoto por RDP.'
    } else {
        $nla = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication'
        Registrar-Control 'RDP-01' 'RDP deshabilitado o NLA habilitado' 'RDP deshabilitado o NLA=1' "RDP habilitado; NLA=$($nla.UserAuthentication)" $(if($nla.UserAuthentication -eq 1){'Cumple'}else{'No cumple'}) 'NLA requiere autenticacion antes de la sesion.'
    }
} catch { Registrar-Control 'RDP-01' 'RDP deshabilitado o NLA habilitado' 'RDP deshabilitado o NLA=1' 'No disponible' 'No evaluado' $_.Exception.Message }

$evaluados = @($controles | Where-Object { $_.estado -ne 'No evaluado' })
$aprobados = @($evaluados | Where-Object { $_.estado -eq 'Cumple' }).Count
$porcentaje = if($evaluados.Count -gt 0){[math]::Round(100*$aprobados/$evaluados.Count,2)}else{$null}
$resultado = [ordered]@{
    equipo = $env:COMPUTERNAME
    fecha = (Get-Date).ToString('o')
    sistema = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
    tipo = 'auditoria_inicial_solo_lectura'
    resumen = [ordered]@{total=$controles.Count;evaluados=$evaluados.Count;cumplen=$aprobados;no_evaluados=$controles.Count-$evaluados.Count;porcentaje_cumplimiento=$porcentaje}
    controles = $controles
}
$carpeta = Join-Path $PSScriptRoot '..\datos'
New-Item -Path $carpeta -ItemType Directory -Force | Out-Null
$archivo = Join-Path $carpeta 'auditoria-inicial.json'
$resultado | ConvertTo-Json -Depth 5 | Set-Content -Path $archivo -Encoding UTF8
Write-Host "Auditoria lista. Evaluados: $($evaluados.Count) de $($controles.Count); Cumplen: $aprobados; Porcentaje: $porcentaje%"
Write-Host "JSON creado en: $((Resolve-Path $archivo).Path)"
