[CmdletBinding()]
param([switch]$ConfirmarLaboratorio)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'Baseline.psm1') -Force
Assert-BaselineAdministrator
if(-not $ConfirmarLaboratorio){
    if((Read-Host 'Esta VM será auditada, remediada y revertida. Escriba EXPERIMENTO para confirmar') -cne 'EXPERIMENTO'){throw 'Cancelado.'}
}
$root=Split-Path $PSScriptRoot -Parent
$out=Join-Path $root 'evidencia\experimento'
$null=New-Item -ItemType Directory -Path $out -Force
$status=Join-Path $out 'estado.json'
function Save-Status($s){$s | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $status -Encoding UTF8}
$run=[ordered]@{fecha=(Get-Date).ToString('o');fase='Inicio';error=$null;respaldo=$null;snapshot='No disponible desde el invitado; respaldo selectivo con hash';reversion_completa=$false}
Save-Status $run
$backup=$null
try{
    foreach($f in @('auditoria-inicial.json','auditoria-posterior.json','auditoria-reversion.json')){
        if(Test-Path -LiteralPath (Join-Path $root ('datos\'+$f))){throw "Ya existe $f. Archive la ejecución anterior antes de repetir."}
    }
    $initial=& (Join-Path $PSScriptRoot 'Auditar-Baseline.ps1') -Etapa inicial
    $run.fase='Auditoría inicial';Save-Status $run
    $ids=@(Get-BaselineCatalog | Select-Object -ExpandProperty id)
    $rem=& (Join-Path $PSScriptRoot 'Remediar-Baseline.ps1') -Controles $ids -ConfirmarLaboratorio
    $backup=$rem.respaldo;$run.respaldo='respaldos/'+[IO.Path]::GetFileName($backup);$run.fase='Remediación';Save-Status $run
    $post=& (Join-Path $PSScriptRoot 'Auditar-Baseline.ps1') -Etapa posterior
    # Idempotencia: una segunda aplicación se mide y conserva con respaldo independiente.
    $again=& (Join-Path $PSScriptRoot 'Remediar-Baseline.ps1') -Controles $ids -ConfirmarLaboratorio
    $again.respaldo='respaldos/'+[IO.Path]::GetFileName($again.respaldo)
    $again | ConvertTo-Json -Depth 14 | Set-Content (Join-Path $out 'idempotencia.json') -Encoding UTF8
    $run.fase='Auditoría posterior';Save-Status $run
    $smoke=[ordered]@{fecha=(Get-Date).ToString('o');firewall=@(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled);servicios=@(Get-Service EventLog,MpsSvc,LanmanServer | Select-Object Name,Status);rdp_habilitado=((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -eq 0);nota='Observación acotada: no se prueban aplicaciones heredadas, contraseñas ni clientes RDP/SMB externos.'}
    $smoke | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $out 'comprobacion-funcional.json') -Encoding UTF8
}catch{
    $run.error=$_.Exception.Message;$run.fase='Error';Save-Status $run
}finally{
    if($backup){
        try{
            $undo=& (Join-Path $PSScriptRoot 'Revertir-Baseline.ps1') -Respaldo $backup -ConfirmarLaboratorio
            $run.reversion_completa=$undo.restauracion_completa
            $null=& (Join-Path $PSScriptRoot 'Auditar-Baseline.ps1') -Etapa reversion
            $run.fase=if($undo.restauracion_completa){'Finalizado y revertido'}else{'Reversión con diferencias'}
        }catch{$run.error=$_.Exception.Message;$run.fase='Error de reversión'}
    }
    Save-Status $run
}
if($run.error -or -not $run.reversion_completa){exit 1}
