
# Set crea respaldo individual; Undo exige ese respaldo individual.
function Test-PW01 { Test-BaselineControl -Id 'PW-01' }
function Set-PW01 { & (Join-Path $PSScriptRoot 'Remediar-Baseline.ps1') -Controles 'PW-01' }
function Undo-PW01 { param([Parameter(Mandatory=$true)][string]$Respaldo) Undo-SingleControl -Id 'PW-01' -Respaldo $Respaldo }
function Test-PW02 { Test-BaselineControl -Id 'PW-02' }
function Set-PW02 { & (Join-Path $PSScriptRoot 'Remediar-Baseline.ps1') -Controles 'PW-02' }
function Undo-PW02 { param([Parameter(Mandatory=$true)][string]$Respaldo) Undo-SingleControl -Id 'PW-02' -Respaldo $Respaldo }
function Test-PW03 { Test-BaselineControl -Id 'PW-03' }
function Set-PW03 { & (Join-Path $PSScriptRoot 'Remediar-Baseline.ps1') -Controles 'PW-03' }
function Undo-PW03 { param([Parameter(Mandatory=$true)][string]$Respaldo) Undo-SingleControl -Id 'PW-03' -Respaldo $Respaldo }
function Test-PW04 { Test-BaselineControl -Id 'PW-04' }
function Set-PW04 { & (Join-Path $PSScriptRoot 'Remediar-Baseline.ps1') -Controles 'PW-04' }
function Undo-PW04 { param([Parameter(Mandatory=$true)][string]$Respaldo) Undo-SingleControl -Id 'PW-04' -Respaldo $Respaldo }
function Test-AC01 { Test-BaselineControl -Id 'AC-01' }
function Set-AC01 { & (Join-Path $PSScriptRoot 'Remediar-Baseline.ps1') -Controles 'AC-01' }
function Undo-AC01 { param([Parameter(Mandatory=$true)][string]$Respaldo) Undo-SingleControl -Id 'AC-01' -Respaldo $Respaldo }
function Test-AC02 { Test-BaselineControl -Id 'AC-02' }
function Set-AC02 { & (Join-Path $PSScriptRoot 'Remediar-Baseline.ps1') -Controles 'AC-02' }
function Undo-AC02 { param([Parameter(Mandatory=$true)][string]$Respaldo) Undo-SingleControl -Id 'AC-02' -Respaldo $Respaldo }
function Test-AC03 { Test-BaselineControl -Id 'AC-03' }
function Set-AC03 { & (Join-Path $PSScriptRoot 'Remediar-Baseline.ps1') -Controles 'AC-03' }
function Undo-AC03 { param([Parameter(Mandatory=$true)][string]$Respaldo) Undo-SingleControl -Id 'AC-03' -Respaldo $Respaldo }
function Test-FWDomain { Test-BaselineControl -Id 'FW-Domain' }
function Set-FWDomain { & (Join-Path $PSScriptRoot 'Remediar-Baseline.ps1') -Controles 'FW-Domain' }
function Undo-FWDomain { param([Parameter(Mandatory=$true)][string]$Respaldo) Undo-SingleControl -Id 'FW-Domain' -Respaldo $Respaldo }
function Test-FWPrivate { Test-BaselineControl -Id 'FW-Private' }
function Set-FWPrivate { & (Join-Path $PSScriptRoot 'Remediar-Baseline.ps1') -Controles 'FW-Private' }
function Undo-FWPrivate { param([Parameter(Mandatory=$true)][string]$Respaldo) Undo-SingleControl -Id 'FW-Private' -Respaldo $Respaldo }
function Test-FWPublic { Test-BaselineControl -Id 'FW-Public' }
function Set-FWPublic { & (Join-Path $PSScriptRoot 'Remediar-Baseline.ps1') -Controles 'FW-Public' }
function Undo-FWPublic { param([Parameter(Mandatory=$true)][string]$Respaldo) Undo-SingleControl -Id 'FW-Public' -Respaldo $Respaldo }
function Test-UAC01 { Test-BaselineControl -Id 'UAC-01' }
function Set-UAC01 { & (Join-Path $PSScriptRoot 'Remediar-Baseline.ps1') -Controles 'UAC-01' }
function Undo-UAC01 { param([Parameter(Mandatory=$true)][string]$Respaldo) Undo-SingleControl -Id 'UAC-01' -Respaldo $Respaldo }
function Test-UAC02 { Test-BaselineControl -Id 'UAC-02' }
function Set-UAC02 { & (Join-Path $PSScriptRoot 'Remediar-Baseline.ps1') -Controles 'UAC-02' }
function Undo-UAC02 { param([Parameter(Mandatory=$true)][string]$Respaldo) Undo-SingleControl -Id 'UAC-02' -Respaldo $Respaldo }
function Test-UAC03 { Test-BaselineControl -Id 'UAC-03' }
function Set-UAC03 { & (Join-Path $PSScriptRoot 'Remediar-Baseline.ps1') -Controles 'UAC-03' }
function Undo-UAC03 { param([Parameter(Mandatory=$true)][string]$Respaldo) Undo-SingleControl -Id 'UAC-03' -Respaldo $Respaldo }
function Test-SMB01 { Test-BaselineControl -Id 'SMB-01' }
function Set-SMB01 { & (Join-Path $PSScriptRoot 'Remediar-Baseline.ps1') -Controles 'SMB-01' }
function Undo-SMB01 { param([Parameter(Mandatory=$true)][string]$Respaldo) Undo-SingleControl -Id 'SMB-01' -Respaldo $Respaldo }
function Test-RDP01 { Test-BaselineControl -Id 'RDP-01' }
function Set-RDP01 { & (Join-Path $PSScriptRoot 'Remediar-Baseline.ps1') -Controles 'RDP-01' }
function Undo-RDP01 { param([Parameter(Mandatory=$true)][string]$Respaldo) Undo-SingleControl -Id 'RDP-01' -Respaldo $Respaldo }
function Test-AU01 { Test-BaselineControl -Id 'AU-01' }
function Set-AU01 { & (Join-Path $PSScriptRoot 'Remediar-Baseline.ps1') -Controles 'AU-01' }
function Undo-AU01 { param([Parameter(Mandatory=$true)][string]$Respaldo) Undo-SingleControl -Id 'AU-01' -Respaldo $Respaldo }
function Test-AU03 { Test-BaselineControl -Id 'AU-03' }
function Set-AU03 { & (Join-Path $PSScriptRoot 'Remediar-Baseline.ps1') -Controles 'AU-03' }
function Undo-AU03 { param([Parameter(Mandatory=$true)][string]$Respaldo) Undo-SingleControl -Id 'AU-03' -Respaldo $Respaldo }
function Test-SEC01 { Test-BaselineControl -Id 'SEC-01' }
function Set-SEC01 { & (Join-Path $PSScriptRoot 'Remediar-Baseline.ps1') -Controles 'SEC-01' }
function Undo-SEC01 { param([Parameter(Mandatory=$true)][string]$Respaldo) Undo-SingleControl -Id 'SEC-01' -Respaldo $Respaldo }
function Test-AU02 { Test-BaselineControl -Id 'AU-02' }
function Set-AU02 { & (Join-Path $PSScriptRoot 'Remediar-Baseline.ps1') -Controles 'AU-02' }
function Undo-AU02 { param([Parameter(Mandatory=$true)][string]$Respaldo) Undo-SingleControl -Id 'AU-02' -Respaldo $Respaldo }
function Test-PW05 { Test-BaselineControl -Id 'PW-05' }
function Set-PW05 { & (Join-Path $PSScriptRoot 'Remediar-Baseline.ps1') -Controles 'PW-05' }
function Undo-PW05 { param([Parameter(Mandatory=$true)][string]$Respaldo) Undo-SingleControl -Id 'PW-05' -Respaldo $Respaldo }
