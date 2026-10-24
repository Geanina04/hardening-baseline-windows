# Hardening Baseline - Auditoria de Windows 10 Pro
# SOLO LECTURA: consulta configuraciones y genera un JSON.
# No aplica remediaciones ni cambia politicas de seguridad.

$ErrorActionPreference = 'Stop'
$controles = @()

function Registrar-Control {
    param(
        [string]$Id,
        [string]$Nombre,
        [string]$Esperado,
        [string]$Actual,
        [string]$Estado,
        [string]$Detalle
    )

    $script:controles += [pscustomobject]@{
        id       = $Id
        nombre   = $Nombre
        esperado = $Esperado
        actual   = $Actual
        estado   = $Estado
        detalle  = $Detalle
    }
}

# Exportar politica de seguridad local a un archivo temporal para consultarla.
# secedit /export lee la politica; no la modifica.
$politica = @{}
$tempCfg = Join-Path $env:TEMP ("baseline-policy-{0}.cfg" -f [guid]::NewGuid())

try {
    $proceso = Start-Process -FilePath "$env:WINDIR\System32\secedit.exe" `
        -ArgumentList @('/export', '/cfg', "`"$tempCfg`"", '/areas', 'SECURITYPOLICY') `
        -Wait -PassThru -WindowStyle Hidden

    if ($proceso.ExitCode -eq 0 -and (Test-Path -LiteralPath $tempCfg)) {
        foreach ($linea in Get-Content -LiteralPath $tempCfg) {
            if ($linea -match '^\s*([^;=\[][^=]*)\s*=\s*(.*?)\s*$') {
                $politica[$matches[1].Trim()] = $matches[2].Trim()
            }
        }
    }
}
catch {
    # Los controles dependientes quedaran No evaluado si no se puede leer la politica.
}
finally {
    if (Test-Path -LiteralPath $tempCfg) {
        Remove-Item -LiteralPath $tempCfg -Force -ErrorAction SilentlyContinue
    }
}

function Registrar-Politica {
    param(
        [string]$Id,
        [string]$Nombre,
        [string]$Clave,
        [string]$Esperado,
        [scriptblock]$Evaluador
    )

    if (-not $politica.ContainsKey($Clave)) {
        Registrar-Control $Id $Nombre $Esperado 'No disponible' 'No evaluado' `
            "No se pudo leer '$Clave' de la politica local. Verificar permisos y disponibilidad en esta version de Windows."
        return
    }

    $valor = [string]$politica[$Clave]
    try {
        $estado = & $Evaluador $valor
        Registrar-Control $Id $Nombre $Esperado $valor $estado `
            'Valor consultado en la politica local. Confirmar el criterio con la linea base y version elegidas.'
    }
    catch {
        Registrar-Control $Id $Nombre $Esperado $valor 'No evaluado' $_.Exception.Message
    }
}

# 1-3. Firewall: un control por cada perfil.
try {
    $perfiles = @(Get-NetFirewallProfile -ErrorAction Stop)
    foreach ($nombrePerfil in @('Domain', 'Private', 'Public')) {
        $perfil = $perfiles | Where-Object { $_.Name -eq $nombrePerfil } | Select-Object -First 1
        if ($null -eq $perfil) {
            Registrar-Control "FW-$nombrePerfil" "Firewall perfil $nombrePerfil habilitado" `
                'Enabled=True' 'Perfil no encontrado' 'No evaluado' `
                'No se encontro este perfil en la consulta.'
        }
        else {
            Registrar-Control "FW-$nombrePerfil" "Firewall perfil $nombrePerfil habilitado" `
                'Enabled=True' ([string]$perfil.Enabled) `
                $(if ($perfil.Enabled -eq $true) { 'Cumple' } else { 'No cumple' }) `
                'Consulta de solo lectura mediante Get-NetFirewallProfile.'
        }
    }
}
catch {
    foreach ($nombrePerfil in @('Domain', 'Private', 'Public')) {
        Registrar-Control "FW-$nombrePerfil" "Firewall perfil $nombrePerfil habilitado" `
            'Enabled=True' 'No disponible' 'No evaluado' $_.Exception.Message
    }
}

# 4. UAC.
try {
    $uac = Get-ItemPropertyValue `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
        -Name 'EnableLUA' -ErrorAction Stop

    Registrar-Control 'UAC-01' 'UAC habilitado' 'EnableLUA=1' "EnableLUA=$uac" `
        $(if ([int]$uac -eq 1) { 'Cumple' } else { 'No cumple' }) `
        'Consulta de solo lectura del Registro.'
}
catch {
    Registrar-Control 'UAC-01' 'UAC habilitado' 'EnableLUA=1' `
        'No disponible' 'No evaluado' $_.Exception.Message
}

# 5. SMBv1.
try {
    $smb = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
    $estadoSmb = [string]$smb.State
    $cumpleSmb = $estadoSmb -in @('Disabled', 'DisabledWithPayloadRemoved')

    Registrar-Control 'SMB-01' 'SMBv1 deshabilitado' 'Disabled' $estadoSmb `
        $(if ($cumpleSmb) { 'Cumple' } else { 'No cumple' }) `
        'Consulta de solo lectura; si no se puede consultar, se registra No evaluado.'
}
catch {
    Registrar-Control 'SMB-01' 'SMBv1 deshabilitado' 'Disabled' `
        'No disponible' 'No evaluado' $_.Exception.Message
}

# 6. RDP deshabilitado o NLA habilitado.
# Get-ItemPropertyValue devuelve el valor directamente, no un objeto con esa propiedad.
try {
    $rdp = Get-ItemPropertyValue `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
        -Name 'fDenyTSConnections' -ErrorAction Stop

    if ([int]$rdp -eq 1) {
        Registrar-Control 'RDP-01' 'RDP deshabilitado o NLA habilitado' `
            'RDP deshabilitado o NLA=1' 'RDP deshabilitado' 'Cumple' `
            'fDenyTSConnections=1 indica que RDP esta deshabilitado.'
    }
    elseif ([int]$rdp -eq 0) {
        $nla = Get-ItemPropertyValue `
            -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
            -Name 'UserAuthentication' -ErrorAction Stop

        Registrar-Control 'RDP-01' 'RDP deshabilitado o NLA habilitado' `
            'RDP deshabilitado o NLA=1' "RDP habilitado; NLA=$nla" `
            $(if ([int]$nla -eq 1) { 'Cumple' } else { 'No cumple' }) `
            'UserAuthentication=1 indica NLA habilitado. No se modifica la configuracion.'
    }
    else {
        Registrar-Control 'RDP-01' 'RDP deshabilitado o NLA habilitado' `
            'RDP deshabilitado o NLA=1' "Valor RDP inesperado: $rdp" 'No evaluado' `
            'El valor de fDenyTSConnections no es el esperado.'
    }
}
catch {
    Registrar-Control 'RDP-01' 'RDP deshabilitado o NLA habilitado' `
        'RDP deshabilitado o NLA=1' 'No disponible' 'No evaluado' `
        ("No se pudo leer RDP/NLA: " + $_.Exception.Message)
}

# 7-12. Politicas locales de contrasena y bloqueo.
# Estos umbrales son criterios provisionales para el ejercicio, no una afirmacion
# de cumplimiento oficial CIS/Microsoft. Definan y citen el benchmark usado.
Registrar-Politica 'PW-01' 'Longitud minima de contrasena' `
    'MinimumPasswordLength' '>=14 (criterio provisional)' {
        param($v)
        if ([int]$v -ge 14) { 'Cumple' } else { 'No cumple' }
    }

Registrar-Politica 'PW-02' 'Historial de contrasenas' `
    'PasswordHistorySize' '>=24 (criterio provisional)' {
        param($v)
        if ([int]$v -ge 24) { 'Cumple' } else { 'No cumple' }
    }

Registrar-Politica 'PW-03' 'Antiguedad maxima de contrasena' `
    'MaximumPasswordAge' 'Entre 1 y 365 dias (criterio provisional)' {
        param($v)
        if ([int]$v -ge 1 -and [int]$v -le 365) { 'Cumple' } else { 'No cumple' }
    }

Registrar-Politica 'AC-01' 'Umbral de bloqueo de cuenta' `
    'LockoutBadCount' 'Entre 1 y 10 intentos (criterio provisional)' {
        param($v)
        if ([int]$v -ge 1 -and [int]$v -le 10) { 'Cumple' } else { 'No cumple' }
    }

Registrar-Politica 'AC-02' 'Duracion del bloqueo de cuenta' `
    'LockoutDuration' '>=15 minutos (criterio provisional)' {
        param($v)
        if ([int]$v -ge 15) { 'Cumple' } else { 'No cumple' }
    }

Registrar-Politica 'AC-03' 'Restablecimiento del contador de bloqueo' `
    'ResetLockoutCount' '>=15 minutos (criterio provisional)' {
        param($v)
        if ([int]$v -ge 15) { 'Cumple' } else { 'No cumple' }
    }

# 13. Cuenta local Guest deshabilitada.
try {
    $invitado = Get-LocalUser -Name 'Guest' -ErrorAction Stop
    Registrar-Control 'SEC-01' 'Cuenta Guest deshabilitada' 'Enabled=False' `
        ([string]$invitado.Enabled) `
        $(if ($invitado.Enabled -eq $false) { 'Cumple' } else { 'No cumple' }) `
        'Consulta de solo lectura del estado de la cuenta local Guest.'
}
catch {
    Registrar-Control 'SEC-01' 'Cuenta Guest deshabilitada' 'Enabled=False' `
        'No disponible' 'No evaluado' $_.Exception.Message
}

# 14. Registro de seguridad habilitado.
try {
    $log = Get-WinEvent -ListLog Security -ErrorAction Stop
    Registrar-Control 'AU-01' 'Registro de seguridad habilitado' 'IsEnabled=True' `
        ([string]$log.IsEnabled) `
        $(if ($log.IsEnabled -eq $true) { 'Cumple' } else { 'No cumple' }) `
        'Comprueba el registro; no confirma por si solo que todas las subcategorias de auditoria esten configuradas.'
}
catch {
    Registrar-Control 'AU-01' 'Registro de seguridad habilitado' 'IsEnabled=True' `
        'No disponible' 'No evaluado' $_.Exception.Message
}

# 15. Tamano del registro Security.
try {
    $log = Get-WinEvent -ListLog Security -ErrorAction Stop
    $maxMB = [math]::Round($log.MaximumSizeInBytes / 1MB, 2)
    Registrar-Control 'AU-02' 'Tamano del registro Security' `
        '>=20 MB (criterio provisional)' "$maxMB MB" `
        $(if ($log.MaximumSizeInBytes -ge 20MB) { 'Cumple' } else { 'No cumple' }) `
        'Criterio provisional: confirmar el valor esperado con el benchmark elegido.'
}
catch {
    Registrar-Control 'AU-02' 'Tamano del registro Security' `
        '>=20 MB (criterio provisional)' 'No disponible' 'No evaluado' $_.Exception.Message
}

# Calculo del porcentaje: solo Cumple y No cumple forman el denominador.
# No evaluado y No aplica quedan fuera. No se marca ningun control como No aplica
# automaticamente: esa decision debe justificarse para cada control.
$evaluados = @($controles | Where-Object { $_.estado -in @('Cumple', 'No cumple') })
$aprobados = @($evaluados | Where-Object { $_.estado -eq 'Cumple' }).Count
$noCumplen = @($evaluados | Where-Object { $_.estado -eq 'No cumple' }).Count
$noEvaluados = @($controles | Where-Object { $_.estado -eq 'No evaluado' }).Count
$noAplica = @($controles | Where-Object { $_.estado -eq 'No aplica' }).Count

$porcentaje = if ($evaluados.Count -gt 0) {
    [math]::Round(100 * $aprobados / $evaluados.Count, 2)
} else {
    $null
}

$resultado = [ordered]@{
    equipo = $env:COMPUTERNAME
    fecha = (Get-Date).ToString('o')
    sistema = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
    tipo = 'auditoria_solo_lectura'
    nota = 'Los umbrales marcados como provisionales son para el ejercicio. Para afirmar cumplimiento de un estandar, documentar benchmark, version y perfil seleccionados.'
    resumen = [ordered]@{
        total = $controles.Count
        evaluados = $evaluados.Count
        cumplen = $aprobados
        no_cumplen = $noCumplen
        no_evaluados = $noEvaluados
        no_aplica = $noAplica
        porcentaje_cumplimiento = $porcentaje
    }
    controles = $controles
}

# Guardar el JSON en la carpeta datos situada un nivel arriba de script.
$carpeta = Join-Path $PSScriptRoot '..\datos'
New-Item -Path $carpeta -ItemType Directory -Force | Out-Null
$archivo = Join-Path $carpeta 'auditoria-inicial.json'

$resultado | ConvertTo-Json -Depth 6 | Set-Content -Path $archivo -Encoding UTF8

Write-Host "Auditoria terminada. Controles: $($controles.Count); evaluados: $($evaluados.Count); cumplen: $aprobados; no cumplen: $noCumplen; no evaluados: $noEvaluados; cumplimiento: $porcentaje%"
Write-Host "JSON creado en: $((Resolve-Path $archivo).Path)"
