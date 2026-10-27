# Revierte exclusivamente el respaldo indicado.
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([Parameter(Mandatory=$true)][string]$Respaldo,[switch]$ConfirmarLaboratorio)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'Baseline.psm1') -Force
Assert-BaselineAdministrator
if($WhatIfPreference){Write-Host "Simulación de reversión: $Respaldo";return}
if(-not $ConfirmarLaboratorio){
    if(-not $PSCmdlet.ShouldProcess($Respaldo,'Restaurar valores originales')){return}
    if((Read-Host 'Escriba REVERTIR para confirmar') -cne 'REVERTIR'){throw 'Operación cancelada.'}
}
Invoke-BaselineUndo -Path $Respaldo -ConfirmarLaboratorio
