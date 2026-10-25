
# Control: AU-02
# Objetivo: verificar el tamaño del registro de eventos de seguridad.
# Modo piloto: no modifica la configuracion de Windows.

$ErrorActionPreference = "Stop"

$RutaRegistro = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security"
$NombreControl = "AU-02"
$TamanioMinimoMB = 20

function Test-AU02 {
    try {
        $registro = Get-WinEvent -ListLog Security
        $tamanioActualMB = [math]::Round(
            $registro.MaximumSizeInBytes / 1MB, 2
        )

        $cumple = $tamanioActualMB -ge $TamanioMinimoMB

        [PSCustomObject]@{
            Control       = $NombreControl
            TamanioActual = $tamanioActualMB
            TamanioMinimo = $TamanioMinimoMB
            Estado        = if ($cumple) {
                "Cumple"
            } else {
                "No cumple"
            }
            Modo           = "Solo lectura"
        }
    }
    catch {
        Write-Error "No se pudo consultar el registro Security: $($_.Exception.Message)"
    }
}

function Set-AU02 {
    param(
        [int]$NuevoTamanioMB = 20
    )

    $ruta = Join-Path $PSScriptRoot "..\respaldos\AU02-estado-previo.json"

    if (-not (Test-Path $ruta)) {
        Write-Warning "No existe un respaldo. Remediacion cancelada."
        return
    }

    $respaldo = Get-Content $ruta -Raw | ConvertFrom-Json

    if ($respaldo.control -ne "AU-02" -or
        [long]$respaldo.valor_original_bytes -le 0 -or
        $respaldo.equipo -ne $env:COMPUTERNAME) {
        Write-Warning "El respaldo no es valido para este equipo."
        return
    }

    Write-Host "SIMULACION DE REMEDIACION" -ForegroundColor Yellow
    Write-Host "Control: AU-02"
    Write-Host "Valor original: $($respaldo.valor_original_mb) MB"
    Write-Host "Valor propuesto: $NuevoTamanioMB MB"
    Write-Host "No se realizaron cambios en Windows."
}

function Undo-AU02 {
    $ruta = Join-Path $PSScriptRoot "..\respaldos\AU02-estado-previo.json"

    if (-not (Test-Path $ruta)) {
        Write-Warning "No existe respaldo para revertir."
        return
    }

    $respaldo = Get-Content $ruta -Raw | ConvertFrom-Json

    if ($respaldo.control -ne "AU-02" -or
        [long]$respaldo.valor_original_bytes -le 0 -or
        $respaldo.equipo -ne $env:COMPUTERNAME) {
        Write-Warning "El respaldo no es valido para este equipo."
        return
    }

    Write-Host "SIMULACION DE REVERSION" -ForegroundColor Yellow
    Write-Host "Control: AU-02"
    Write-Host "Valor que se restauraria: $($respaldo.valor_original_mb) MB"
    Write-Host "No se realizaron cambios en Windows."
}

function Backup-AU02 {
    try {
        $registro = Get-WinEvent -ListLog Security -ErrorAction Stop

        $respaldo = [PSCustomObject]@{
            control = "AU-02"
            fecha = (Get-Date).ToString("o")
            equipo = $env:COMPUTERNAME
            valor_original_bytes = [long]$registro.MaximumSizeInBytes
            valor_original_mb = [math]::Round(
                $registro.MaximumSizeInBytes / 1MB, 2
            )
        }

        $carpeta = Join-Path $PSScriptRoot "..\respaldos"

        if (-not (Test-Path $carpeta)) {
            New-Item -ItemType Directory -Path $carpeta |
                Out-Null
        }

        $archivo = Join-Path $carpeta "AU02-estado-previo.json"

        if (Test-Path $archivo) {
            throw "Ya existe un respaldo. No se sobrescribira."
        }

        $respaldo |
            ConvertTo-Json -Depth 4 |
            Set-Content -Path $archivo -Encoding UTF8

        Write-Host "Respaldo creado correctamente." -ForegroundColor Green
        Write-Host "Archivo: $archivo"
    }
    catch {
        Write-Warning "Error al crear respaldo: $($_.Exception.Message)"
    }
}

# Pruebas del control AU-02
Test-AU02
Set-AU02 -NuevoTamanioMB 40
Undo-AU02