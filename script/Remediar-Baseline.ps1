# Ningún cambio sin confirmación explícita.
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string[]]$Controles,
    [string]$CarpetaRespaldo=(Join-Path $PSScriptRoot '..\respaldos'),
    [switch]$ConfirmarLaboratorio
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'Baseline.psm1') -Force
Assert-BaselineAdministrator
$catalogo=Get-BaselineCatalog
foreach($id in $Controles){if($id -notin $catalogo.id){throw "Control desconocido: $id"}}
if(@($Controles | Select-Object -Unique).Count -ne $Controles.Count){throw 'No repita controles.'}
if($WhatIfPreference){Write-Host ('Simulación: '+($Controles -join ', '));return}
if(-not $ConfirmarLaboratorio){
    if(-not $PSCmdlet.ShouldProcess(($Controles -join ', '),'Respaldar y remediar Windows')){return}
    if((Read-Host 'Escriba APLICAR para confirmar cambios en esta VM') -cne 'APLICAR'){throw 'Operación cancelada.'}
}
Invoke-BaselineRemediation -Ids $Controles -Directory $CarpetaRespaldo -ConfirmarLaboratorio
