# Compatibilidad: el piloto anterior solo simulaba. Su original se conserva localmente.
Import-Module (Join-Path $PSScriptRoot 'Baseline.psm1') -Force
function Test-AU02 { Test-BaselineControl -Id 'AU-02' }
function Set-AU02 {
    & (Join-Path $PSScriptRoot 'Remediar-Baseline.ps1') -Controles 'AU-02'
}
function Undo-AU02 {
    param([Parameter(Mandatory=$true)][string]$Respaldo)
    & (Join-Path $PSScriptRoot 'Revertir-Baseline.ps1') -Respaldo $Respaldo
}
# Dot-source para acceder a las funciones; no se ejecutan cambios al importar.
