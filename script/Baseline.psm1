
# Compatible con Windows PowerShell 5.1. No modifica Windows al importar.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$script:PolicyCache=$null
$script:Root=Split-Path $PSScriptRoot -Parent

function Test-BaselineAdministrator {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Assert-BaselineAdministrator {
    if(-not (Test-BaselineAdministrator)){throw 'Se requiere Windows PowerShell de 64 bits como administrador. No se realizaron cambios.'}
    if(-not [Environment]::Is64BitProcess){throw 'Se requiere proceso de 64 bits.'}
}
function Get-BaselineCatalog {
    $items=Get-Content (Join-Path $PSScriptRoot 'controles.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach($item in $items){$item}
}
function Get-ControlDefinition([string]$Id){
    $c=@(Get-BaselineCatalog | Where-Object id -eq $Id)
    if($c.Count -ne 1){throw "Identificador inválido: $Id"};$c[0]
}
function Write-BaselineJson($Object,[string]$Path){
    $full=[IO.Path]::GetFullPath($Path)
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($full)) | Out-Null
    $tmp=$full+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    $json=$Object | ConvertTo-Json -Depth 18
    [IO.File]::WriteAllText($tmp,$json,(New-Object Text.UTF8Encoding($false)))
    $null=Get-Content -LiteralPath $tmp -Raw -Encoding UTF8 | ConvertFrom-Json
    Move-Item -LiteralPath $tmp -Destination $full -Force
}
function Invoke-NativeChecked([string]$File,[string[]]$Arguments){
    $result=@(& $File @Arguments 2>&1)
    if($LASTEXITCODE -ne 0){throw "Fallo de $([IO.Path]::GetFileName($File)); código $LASTEXITCODE. Verifique privilegios y política."}
    $result
}
function Get-MachineFingerprint {
    $v=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
    $sha=[Security.Cryptography.SHA256]::Create()
    try{([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($v)))).Replace('-','')}finally{$sha.Dispose()}
}
function Get-SecurityPolicy {
    if($null -ne $script:PolicyCache){return $script:PolicyCache}
    Assert-BaselineAdministrator
    $dir=Join-Path $env:TEMP ('isw612-'+[guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($dir) | Out-Null
    try{
        $cfg=Join-Path $dir 'policy.inf'
        $null=Invoke-NativeChecked secedit.exe @('/export','/cfg',$cfg,'/areas','SECURITYPOLICY','/log',(Join-Path $dir 'export.log'),'/quiet')
        if(-not (Test-Path -LiteralPath $cfg)){throw 'Secedit no produjo exportación.'}
        $values=@{}
        foreach($line in Get-Content -LiteralPath $cfg){if($line -match '^\s*([A-Za-z][A-Za-z0-9]*)\s*=\s*(-?\d+)\s*$'){$values[$matches[1]]=[int]$matches[2]}}
        $script:PolicyCache=$values
        return $values
    }finally{
        # Todos los archivos son temporales creados en esta función; sin eliminación recursiva.
        Get-ChildItem -LiteralPath $dir -File | Remove-Item -Force
        Remove-Item -LiteralPath $dir -Force
    }
}
function Set-SecurityPolicyValues([hashtable]$Values){
    Assert-BaselineAdministrator
    $dir=Join-Path $env:TEMP ('isw612-'+[guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($dir) | Out-Null
    try{
        $lines=@('[Unicode]','Unicode=yes','[Version]','signature="$CHICAGO$"','Revision=1','[System Access]')
        foreach($key in $Values.Keys){if($key -notmatch '^[A-Za-z]+$'){throw 'Clave inválida.'};$lines+="$key = $([int]$Values[$key])"}
        $cfg=Join-Path $dir 'apply.inf';$lines | Set-Content -LiteralPath $cfg -Encoding Unicode
        $null=Invoke-NativeChecked secedit.exe @('/configure','/db',(Join-Path $dir 'apply.sdb'),'/cfg',$cfg,'/overwrite','/areas','SECURITYPOLICY','/log',(Join-Path $dir 'configure.log'),'/quiet')
    }finally{
        $script:PolicyCache=$null
        Get-ChildItem -LiteralPath $dir -File | Remove-Item -Force
        Remove-Item -LiteralPath $dir -Force
    }
}
function Get-RegistryState([string]$Path,[string]$Name){
    $exists=Test-Path -LiteralPath $Path
    $property=$false;$value=$null;$kind=$null
    if($exists){
        $key=Get-Item -LiteralPath $Path
        $property=$Name -in $key.GetValueNames()
        if($property){$value=$key.GetValue($Name);$kind=$key.GetValueKind($Name).ToString()}
    }
    [pscustomobject]@{keyExists=$exists;propertyExists=$property;value=$value;kind=$kind}
}
function Restore-RegistryState($C,$Original){
    if($Original.propertyExists){
        if(-not (Test-Path -LiteralPath $C.ruta)){$null=New-Item -Path $C.ruta -Force}
        $null=New-ItemProperty -LiteralPath $C.ruta -Name $C.clave -Value $Original.value -PropertyType $Original.kind -Force
    }else{
        if(Test-Path -LiteralPath $C.ruta){
            Remove-ItemProperty -LiteralPath $C.ruta -Name $C.clave -ErrorAction SilentlyContinue
            $k=Get-Item -LiteralPath $C.ruta
            if(-not $Original.keyExists -and $k.ValueCount -eq 0 -and $k.SubKeyCount -eq 0){Remove-Item -LiteralPath $C.ruta}
        }
    }
}
function Get-ControlState($C){
    switch($C.tipo){
        Policy {
            $p=Get-SecurityPolicy
            if(-not $p.ContainsKey($C.clave)){throw "La exportación no contiene $($C.clave)."}
            [pscustomobject]@{value=[int]$p[$C.clave]}
        }
        Registry { Get-RegistryState $C.ruta $C.clave }
        Firewall {
            $effective=Get-NetFirewallProfile -Name $C.clave -PolicyStore ActiveStore
            $local=Get-NetFirewallProfile -Name $C.clave -PolicyStore PersistentStore
            [pscustomobject]@{value=[int]$effective.Enabled;local=[int]$local.Enabled}
        }
        Smb {[pscustomobject]@{value=[bool](Get-SmbServerConfiguration).EnableSMB1Protocol}}
        Rdp {
            $reg=Get-RegistryState $C.ruta $C.clave
            $setting=Get-CimInstance -Namespace root\cimv2\terminalservices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'"
            if($null -eq $setting){throw 'Listener RDP no disponible.'}
            [pscustomobject]@{value=[int]$setting.UserAuthenticationRequired;source=[int]$setting.PolicySourceUserAuthenticationRequired;registry=$reg}
        }
        Audit {
            Assert-BaselineAdministrator
            $temp=Join-Path $env:TEMP ('isw612-audit-'+[guid]::NewGuid().ToString('N')+'.csv')
            try{
                $null=Invoke-NativeChecked auditpol.exe @('/backup',('/file:'+$temp))
                $all=@(Import-Csv -LiteralPath $temp)
                $rows=@($all | Where-Object {@($_.PSObject.Properties)[3].Value -eq $C.clave})
            }finally{if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Force}}
            if($rows.Count -ne 1){throw 'Salida auditpol ambigua o inesperada; no se infiere cumplimiento.'}
            $props=@($rows[0].PSObject.Properties)
            # /get /r NO contiene máscara numérica; /backup sí incluye Setting Value.
            $value=0
            if(-not [int]::TryParse([string]$props[-1].Value,[ref]$value) -or $value -notin @(0,1,2,3)){throw 'Máscara auditpol no reconocida.'}
            [pscustomobject]@{value=$value}
        }
        Guest {
            $u=@(Get-LocalUser | Where-Object {$_.SID.Value -match '-501$'})
            if($u.Count -ne 1){throw 'Cuenta RID 501 no localizada de forma unívoca.'}
            [pscustomobject]@{value=[bool]$u[0].Enabled}
        }
        Log {
            Assert-BaselineAdministrator
            [pscustomobject]@{value=[long](Get-WinEvent -ListLog Security).MaximumSizeInBytes}
        }
        default {throw 'Tipo de control desconocido.'}
    }
}
function Write-ControlRebootMarker([string]$Id){
    $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
    Write-BaselineJson ([ordered]@{id=$Id;boot=$boot;fecha=(Get-Date).ToString('o')}) (Join-Path $script:Root 'respaldos\reinicio-pendiente.json')
}
function Test-ControlPendingReboot([string]$Id){
    $path=Join-Path $script:Root 'respaldos\reinicio-pendiente.json'
    if(-not (Test-Path -LiteralPath $path)){return $false}
    $m=Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
    return ($m.id -eq $Id -and $m.boot -eq $boot)
}
function Test-BaselineControl {
    [CmdletBinding()]param([Parameter(Mandatory=$true)][string]$Id)
    $c=Get-ControlDefinition $Id
    $result=[ordered]@{id=$c.id;nombre=$c.nombre;esperado=$c.esperado;actual=$null;estado='No evaluado';riesgo=$c.riesgo;explicacion=$c.explicacion;justificacion=$c.justificacion;recomendacion=$c.recomendacion;efectos_secundarios=$c.efectos_secundarios;aplicabilidad=$c.aplicabilidad;fuente=$c.fuente;error=$null;fecha=(Get-Date).ToString('o')}
    try{
        if($c.tipo -in @('Policy','Audit','Log') -and -not (Test-BaselineAdministrator)){$result.error='Privilegios insuficientes: requiere administrador.';return [pscustomobject]$result}
        $s=Get-ControlState $c;$result.actual=$s.value
        if($c.id -eq 'UAC-01' -and (Test-ControlPendingReboot $c.id)){$result.error='EnableLUA modificado por la herramienta: reinicie y audite de nuevo para comprobar la aplicación.';return [pscustomobject]$result}
        if($c.tipo -eq 'Registry' -and -not $s.propertyExists){$result.error='Valor ausente: no se infiere cumplimiento desde un valor predeterminado.';return [pscustomobject]$result}
        $ok=$s.value -eq $c.objetivo
        if($c.PSObject.Properties['comparador']){
            switch($c.comparador){
                ge {$ok=$s.value -ge $c.objetivo}
                threshold {$ok=$s.value -ge 1 -and $s.value -le 10}
                duration {
                    $p=Get-SecurityPolicy
                    if($p.LockoutBadCount -eq 0){$result.estado='No aplica';$result.aplicabilidad='Bloqueo inactivo: AC-01=0; se excluye del denominador.';return [pscustomobject]$result}
                    $ok=$s.value -ge 15 -and $s.value -ge $p.ResetLockoutCount
                }
                reset {
                    $p=Get-SecurityPolicy
                    if($p.LockoutBadCount -eq 0){$result.estado='No aplica';$result.aplicabilidad='Bloqueo inactivo: AC-01=0; se excluye del denominador.';return [pscustomobject]$result}
                    $ok=$s.value -ge 15 -and $s.value -le $p.LockoutDuration
                }
            }
        }
        $result.estado=if($ok){'Cumple'}else{'No cumple'}
    }catch{$result.estado='Error de evaluación';$result.error=$_.Exception.Message}
    [pscustomobject]$result
}
function Get-BaselineSummary($Controls){
    $pass=@($Controls | Where-Object estado -eq 'Cumple').Count
    $fail=@($Controls | Where-Object estado -eq 'No cumple').Count
    $den=$pass+$fail
    [pscustomobject][ordered]@{total=@($Controls).Count;evaluados=$den;cumplen=$pass;no_cumplen=$fail;no_aplica=@($Controls | Where-Object estado -eq 'No aplica').Count;no_evaluados=@($Controls | Where-Object estado -eq 'No evaluado').Count;errores=@($Controls | Where-Object estado -eq 'Error de evaluación').Count;porcentaje_cumplimiento=$(if($den -gt 0){[math]::Round(100.0*$pass/$den,2)}else{$null})}
}
function Invoke-BaselineAudit {
    [CmdletBinding()]param([string]$Etapa='inicial',[Parameter(Mandatory=$true)][string]$Salida)
    $script:PolicyCache=$null
    $controls=@(Get-BaselineCatalog | ForEach-Object {Test-BaselineControl -Id $_.id})
    if(@($controls.id | Select-Object -Unique).Count -ne $controls.Count){throw 'Identificadores duplicados.'}
    $os=Get-CimInstance Win32_OperatingSystem;$cs=Get-CimInstance Win32_ComputerSystem
    $result=[ordered]@{schema_version='1.0';baseline_id='UTN-A5-MS-seleccion-v1';ejecucion_id=[guid]::NewGuid().ToString();fecha=(Get-Date).ToString('o');etapa=$Etapa;origen='real';sistema=[ordered]@{nombre=$os.Caption;version=$os.Version;compilacion=$os.BuildNumber;arquitectura=$os.OSArchitecture;hipervisor=$cs.Model;ram_gib=[math]::Round($cs.TotalPhysicalMemory/1GB,2);cpu_logicos=$cs.NumberOfLogicalProcessors;dominio=[bool]$cs.PartOfDomain;powershell=$PSVersionTable.PSVersion.ToString();administrador=(Test-BaselineAdministrator)};resumen=(Get-BaselineSummary $controls);controles=$controls}
    Write-BaselineJson $result $Salida
    Write-Host ("{0}: {1}/{2}; {3}%; excluidos NA={4}, NE={5}, errores={6}." -f $Etapa,$result.resumen.cumplen,$result.resumen.evaluados,$result.resumen.porcentaje_cumplimiento,$result.resumen.no_aplica,$result.resumen.no_evaluados,$result.resumen.errores)
    [pscustomobject]$result
}
function Set-ControlValue($C,$Original){
    switch($C.tipo){
        Policy {
            $values=@{};$values[$C.clave]=[int]$C.objetivo
            if($C.id -like 'AC-*'){
                $p=Get-SecurityPolicy
                foreach($k in @('LockoutBadCount','LockoutDuration','ResetLockoutCount')){$values[$k]=[int]$p[$k]}
                $values[$C.clave]=[int]$C.objetivo
                # El grupo dependiente se aplica de manera consistente; respaldo del grupo completo.
                if($values.LockoutBadCount -eq 0){$values.LockoutBadCount=10}
                if($values.LockoutDuration -lt 15){$values.LockoutDuration=15}
                if($values.ResetLockoutCount -lt 15){$values.ResetLockoutCount=15}
                if($values.LockoutDuration -lt $values.ResetLockoutCount){$values.LockoutDuration=$values.ResetLockoutCount}
            }
            Set-SecurityPolicyValues $values
        }
        Registry {
            if(-not (Test-Path -LiteralPath $C.ruta)){$null=New-Item -Path $C.ruta -Force}
            if($C.PSObject.Properties['reinicio'] -and $C.reinicio){Write-ControlRebootMarker $C.id}
            $null=New-ItemProperty -LiteralPath $C.ruta -Name $C.clave -PropertyType DWord -Value ([int]$C.objetivo) -Force
        }
        Firewall {Set-NetFirewallProfile -Name $C.clave -PolicyStore PersistentStore -Enabled True}
        Smb {Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false}
        Rdp {
            if($Original.source -ne 0){throw 'NLA administrada por directiva: no se sobrescribe una GPO.'}
            $null=New-ItemProperty -LiteralPath $C.ruta -Name $C.clave -PropertyType DWord -Value 1 -Force
        }
        Audit {$null=Invoke-NativeChecked auditpol.exe @('/set',('/subcategory:'+$C.clave),'/success:enable','/failure:enable')}
        Guest {Get-LocalUser | Where-Object {$_.SID.Value -match '-501$'} | Disable-LocalUser}
        Log {$null=Invoke-NativeChecked wevtutil.exe @('sl','Security',('/ms:'+$C.objetivo))}
    }
}
function Undo-ControlValue($C,$Original){
    switch($C.tipo){
        Policy {$v=@{};$v[$C.clave]=[int]$Original.value;Set-SecurityPolicyValues $v}
        Registry {
            if($C.PSObject.Properties['reinicio'] -and $C.reinicio){Write-ControlRebootMarker $C.id}
            Restore-RegistryState $C $Original
        }
        Firewall {Set-NetFirewallProfile -Name $C.clave -PolicyStore PersistentStore -Enabled $Original.local}
        Smb {Set-SmbServerConfiguration -EnableSMB1Protocol ([bool]$Original.value) -Confirm:$false}
        Rdp {Restore-RegistryState $C $Original.registry}
        Audit {
            $success=if(($Original.value -band 1) -ne 0){'enable'}else{'disable'}
            $failure=if(($Original.value -band 2) -ne 0){'enable'}else{'disable'}
            $null=Invoke-NativeChecked auditpol.exe @('/set',('/subcategory:'+$C.clave),('/success:'+$success),('/failure:'+$failure))
        }
        Guest {
            $u=Get-LocalUser | Where-Object {$_.SID.Value -match '-501$'}
            if($Original.value){$u | Enable-LocalUser}else{$u | Disable-LocalUser}
        }
        Log {$null=Invoke-NativeChecked wevtutil.exe @('sl','Security',('/ms:'+$Original.value))}
    }
}
function Compare-ControlState($A,$B){
    # Orden de propiedades estable del contrato de estado; compara valor, tipo y existencia.
    ($A | ConvertTo-Json -Depth 8 -Compress) -ceq ($B | ConvertTo-Json -Depth 8 -Compress)
}
function Read-VerifiedBackup([string]$Path){
    $hashPath=$Path+'.sha256'
    if(-not (Test-Path -LiteralPath $hashPath)){throw 'Falta hash del respaldo.'}
    if((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne (Get-Content -LiteralPath $hashPath -Raw).Trim()){throw 'Respaldo alterado o incompleto.'}
    $b=Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    if($b.schema_version -ne 'backup-1.0' -or $b.machine -ne (Get-MachineFingerprint)){throw 'Respaldo incompatible o de otra máquina.'}
    if(@($b.entries.id | Select-Object -Unique).Count -ne @($b.entries).Count){throw 'Respaldo duplicado.'}
    foreach($e in $b.entries){$null=Get-ControlDefinition $e.id;if($null -eq $e.original){throw 'Respaldo sin estado original.'}}
    $b
}
function Invoke-BaselineRemediation {
    [CmdletBinding()]param([string[]]$Ids,[string]$Directory,[switch]$ConfirmarLaboratorio)
    Assert-BaselineAdministrator
    if(-not $ConfirmarLaboratorio){throw 'Falta confirmación explícita. Use Remediar-Baseline.ps1.'}
    if((Get-CimInstance Win32_ComputerSystem).PartOfDomain){throw 'Remediación local rechazada en equipo unido a dominio.'}
    $script:PolicyCache=$null
    $entries=@()
    foreach($id in $Ids){$c=Get-ControlDefinition $id;$s=Get-ControlState $c;$entries+=[pscustomobject]@{id=$id;original=$s}}
    $locks=$null
    if(@($Ids | Where-Object {$_ -like 'AC-*'}).Count -gt 0){
        $p=Get-SecurityPolicy;$locks=[ordered]@{LockoutBadCount=$p.LockoutBadCount;LockoutDuration=$p.LockoutDuration;ResetLockoutCount=$p.ResetLockoutCount}
    }
    $run=[guid]::NewGuid().ToString('N');$path=Join-Path $Directory ($run+'.json')
    $b=[ordered]@{schema_version='backup-1.0';machine=(Get-MachineFingerprint);fecha=(Get-Date).ToString('o');catalog_hash=(Get-FileHash (Join-Path $PSScriptRoot 'controles.json')).Hash;locks=$locks;entries=$entries}
    Write-BaselineJson $b $path
    (Get-FileHash -LiteralPath $path).Hash | Set-Content -LiteralPath ($path+'.sha256') -Encoding ASCII
    $null=Read-VerifiedBackup $path
    $operations=@()
    foreach($e in $entries){
        $c=Get-ControlDefinition $e.id
        $op=[ordered]@{id=$e.id;fecha=(Get-Date).ToString('o');accion='Set';resultado='Error';antes=$e.original;despues=$null;error=$null;reinicio_requerido=$false}
        try{
            # No sobrescribir una configuración que haya cambiado desde la captura.
            if(-not (Compare-ControlState (Get-ControlState $c) $e.original) -and $c.id -notlike 'AC-*'){throw 'Cambio concurrente detectado; vuelva a auditar.'}
            $t=Test-BaselineControl -Id $c.id
            if($t.estado -eq 'Cumple'){$op.resultado='Sin cambios'}
            elseif($t.estado -in @('Error de evaluación','No evaluado')){throw 'No se remedia un control que no puede evaluarse.'}
            else{
                Set-ControlValue $c $e.original
                $script:PolicyCache=$null
                $test=Test-BaselineControl -Id $c.id
                $op.despues=Get-ControlState $c
                if($c.PSObject.Properties['reinicio'] -and $c.reinicio){
                    $op.reinicio_requerido=$true
                    if($op.despues.value -ne $c.objetivo){throw 'El registro no coincide con el objetivo.'}
                    $op.resultado='Aplicado; pendiente de reinicio'
                }else{
                    if($test.estado -ne 'Cumple'){throw "Verificación posterior: $($test.estado)"}
                    $op.resultado='Verificado'
                }
            }
        }catch{$op.error=$_.Exception.Message}
        $operations+=[pscustomobject]$op
        Write-BaselineJson ([ordered]@{respaldo_id=$run;operaciones=$operations}) (Join-Path $script:Root ('evidencia\remediacion\'+$run+'.json'))
    }
    Write-Host "Respaldo verificado: $path"
    [pscustomobject]@{respaldo=[IO.Path]::GetFullPath($path);operaciones=$operations}
}
function Invoke-BaselineUndo {
    [CmdletBinding()]param([string]$Path,[switch]$ConfirmarLaboratorio)
    Assert-BaselineAdministrator
    if(-not $ConfirmarLaboratorio){throw 'Falta confirmación explícita. Use Revertir-Baseline.ps1.'}
    $b=Read-VerifiedBackup $Path
    if($b.catalog_hash -ne (Get-FileHash (Join-Path $PSScriptRoot 'controles.json')).Hash){throw 'Catálogo modificado desde el respaldo.'}
    $script:PolicyCache=$null;$ops=@();$entries=@($b.entries);[array]::Reverse($entries)
    foreach($e in $entries){
        $c=Get-ControlDefinition $e.id
        if($c.id -like 'AC-*'){continue}
        $op=[ordered]@{id=$c.id;accion='Undo';resultado='Error';original=$e.original;restaurado=$null;error=$null}
        try{
            $current=Get-ControlState $c
            if(-not (Compare-ControlState $current $e.original)){Undo-ControlValue $c $e.original}
            $script:PolicyCache=$null
            $op.restaurado=Get-ControlState $c
            if(-not (Compare-ControlState $op.restaurado $e.original)){throw 'Diferencia persistente después de Undo.'}
            $op.resultado='Restaurado y verificado'
        }catch{$op.error=$_.Exception.Message}
        $ops+=[pscustomobject]$op
    }
    if($null -ne $b.locks){
        $op=[ordered]@{id='AC-grupo';accion='Undo';resultado='Error';original=$b.locks;restaurado=$null;error=$null}
        try{
            $values=@{};foreach($prop in $b.locks.PSObject.Properties){$values[$prop.Name]=[int]$prop.Value}
            Set-SecurityPolicyValues $values
            $p=Get-SecurityPolicy;$after=[ordered]@{}
            foreach($prop in $b.locks.PSObject.Properties){$after[$prop.Name]=$p[$prop.Name];if($p[$prop.Name] -ne $prop.Value){throw 'Grupo de bloqueo no restaurado.'}}
            $op.restaurado=$after;$op.resultado='Restaurado y verificado'
        }catch{$op.error=$_.Exception.Message}
        $ops+=[pscustomobject]$op
    }
    $report=[ordered]@{fecha=(Get-Date).ToString('o');respaldo_id=[IO.Path]::GetFileNameWithoutExtension($Path);operaciones=$ops;restauracion_completa=(@($ops | Where-Object resultado -eq 'Error').Count -eq 0)}
    Write-BaselineJson $report (Join-Path $script:Root ('evidencia\reversion\'+$report.respaldo_id+'.json'))
    [pscustomobject]$report
}
function Undo-SingleControl([string]$Id,[string]$Respaldo){
    Assert-BaselineAdministrator
    $b=Read-VerifiedBackup $Respaldo
    if(@($b.entries).Count -ne 1 -or $b.entries[0].id -ne $Id){throw 'Use el respaldo individual creado por Set de este control, o Revertir-Baseline.ps1 para revertir un lote completo.'}
    & (Join-Path $PSScriptRoot 'Revertir-Baseline.ps1') -Respaldo $Respaldo
}
. (Join-Path $PSScriptRoot 'Funciones-Controles.ps1')
$public=@('Test-BaselineAdministrator','Assert-BaselineAdministrator','Get-BaselineCatalog','Test-BaselineControl','Get-BaselineSummary','Invoke-BaselineAudit','Invoke-BaselineRemediation','Invoke-BaselineUndo')
foreach($c in Get-BaselineCatalog){$n=$c.id.Replace('-','');$public+=@("Test-$n","Set-$n","Undo-$n")}
Export-ModuleMember -Function $public
