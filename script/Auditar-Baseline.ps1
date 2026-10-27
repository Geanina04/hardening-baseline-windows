[CmdletBinding()]
param(
    [ValidateSet('inicial','posterior','reversion','diagnostico')][string]$Etapa='inicial',
    [string]$Salida=(Join-Path $PSScriptRoot "..\datos\auditoria-$Etapa.json")
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'Baseline.psm1') -Force
Invoke-BaselineAudit -Etapa $Etapa -Salida $Salida
