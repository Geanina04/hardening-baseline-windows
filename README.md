# Hardening con baseline — UTN / ISW-612

Herramienta de **A.5** para medir configuraciones de Windows, remediar una selección confirmada y restaurar sus valores originales. PowerShell → JSON → web local. Proyecto de Geanina Acosta Perez y David Sancho Marín, profesor Marcos Castro, entrega del 26 de octubre de 2026.

**Resultado real:** 11/20 (55 %) → 20/20 (100 %), **+45 puntos porcentuales**; Undo recuperó los veinte valores y el 55 % inicial. La VM quedó revertida. La segunda aplicación produjo veinte controles sin cambios. No hubo exclusiones ni errores en esas tres auditorías. El 100 % solo describe esta selección, no seguridad integral.

## Abrir los entregables

- `web/index.html`: abrir directamente, sin servidor ni internet.
- `docs/Informe-ISW612-APA7.pdf`: 15 páginas de cuerpo y referencias, más anexos. Editable: `.docx`; fuentes: `informe-fuente.md` e `informe.html`.
- `evidencia/`: mediciones, registros de cambios y reversión, capturas y grabación de la web.

## Requisitos

Se verificó en **Windows 11 Enterprise Evaluation 10.0.26200 (64 bits)**, VirtualBox (Guest Additions 7.2.20), 4 GB RAM, dos CPU, sin dominio y Windows PowerShell **5.1.26100.6584**. Usar una VM propia de laboratorio. La web solo necesita navegador moderno; se probó Microsoft Edge 156 por `file://`. No requiere npm, claves, cuentas ni servicios externos.

Auditar permite lecturas parciales sin administrador y marca explícitamente las restantes como No evaluado. Para la auditoría completa, Set y Undo, abrir **Windows PowerShell de 64 bits como administrador** y ubicarse en la raíz. Los scripts también verifican permisos. Se rechaza remediar equipos unidos a dominio; no se ha validado MDM.

Los comandos siguientes usan `RemoteSigned` **solo para el proceso hijo**. No cambian ExecutionPolicy de la máquina ni desactivan protecciones. Si una política organizacional exige firma, respetarla: no intentar eludirla. No se utiliza Bypass. Los archivos locales del proyecto se ejecutaron con esta modalidad desde sesiones nuevas.

## Auditar sin cambiar Windows

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\script\Auditar-Baseline.ps1 -Etapa diagnostico -Salida .\datos\mi-auditoria.json
```

Consultar el JSON y abrirlo en la web. Para conservar la medición entregada, no escribir sobre `datos/auditoria-inicial.json`. La auditoría solo consulta configuración y crea el archivo de resultados; las herramientas nativas pueden generar sus propios eventos de actividad.

## Remediar una selección y revertir

Antes, crear un snapshot desde el **anfitrión VirtualBox** si está disponible. En esta sesión no se tuvo acceso al host; se usaron respaldos efectivos y selectivos de configuración. Nunca ejecutar en una máquina ajena o de producción.

Desde una sesión elevada con política que permita scripts locales:

```powershell
# Si la sesión actual restringe scripts, iniciar otra con política de proceso:
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned
```

En esa sesión, desde la raíz:

```powershell
$resultado = & .\script\Remediar-Baseline.ps1 -Controles 'PW-01','PW-02','AU-02'
# Confirmar el aviso y escribir APLICAR. Conservar el objeto resultado.
$resultado.respaldo
& .\script\Auditar-Baseline.ps1 -Etapa posterior -Salida .\datos\mi-posterior.json
& .\script\Revertir-Baseline.ps1 -Respaldo $resultado.respaldo
# Confirmar el aviso y escribir REVERTIR.
& .\script\Auditar-Baseline.ps1 -Etapa reversion -Salida .\datos\mi-reversion.json
```

El respaldo se genera con UUID en `respaldos/` y se valida leyendo el JSON, hash y huella de la máquina. **Guardar JSON y `.sha256` juntos**. No reutilizar el respaldo anterior de AU-02: corresponde al piloto y tiene otro contrato. Si se pierde la variable, localizar el UUID de la ejecución en `respaldos/` y usar su ruta exacta. No elegir automáticamente «el más reciente»: la prueba de idempotencia creó otro respaldo del estado endurecido.

Set guarda existencia de clave y propiedad, tipo y valor; Undo restaura el estado guardado. El grupo AC-01/02/03 se respalda y restaura completo porque sus parámetros dependen entre sí. No se sobrescribe una configuración local administrada por GPO para NLA. Un comando sin error no basta: consultar la nueva auditoría.

Los scripts aceptan `-WhatIf` para previsualizar desde una sesión elevada. `-ConfirmarLaboratorio` es una **confirmación explícita para automatización autorizada**, usada por el procedimiento de laboratorio; no se agrega por defecto a los comandos de uso interactivo. Las funciones internas exportadas también exigen esa confirmación para cambiar Windows.

## Repetir el experimento

El experimento entregado se ejecutó con:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\script\Ejecutar-Laboratorio.ps1 -ConfirmarLaboratorio
```

**No volver a lanzarlo sobre los JSON entregados:** el procedimiento los protege y se detiene si ya existen. En una copia nueva para repetir, conservar primero una copia completa del repositorio entregado fuera de esa copia de trabajo; retirar de la copia nueva los tres JSON `auditoria-inicial.json`, `auditoria-posterior.json`, `auditoria-reversion.json`, manteniendo las evidencias originales en el archivo conservado. No borrar `respaldos/` de esta VM: contienen la vía de recuperación del experimento original. En una VM diferente, nunca usar respaldos de otra máquina.

El procedimiento obtiene todos los IDs del catálogo, audita, respalda, remedia, audita otra vez, comprueba idempotencia y ejecuta Undo dentro de `finally`. Deja `evidencia/experimento/estado.json`; comprobar que diga Finalizado y revertido y `reversion_completa=true`. No reinicia automáticamente. Si EnableLUA cambia, marca el control como pendiente de reinicio; reiniciar manualmente en una ventana prevista y auditar después. La reversión de ese valor también puede necesitar reinicio. Esta rama no se ejercitó en la medición porque ya valía 1.

Para una repetición individual sin sobrescribir las mediciones originales, usar nombres propios con `-Salida`, capturar `$resultado.respaldo` y ejecutar el flujo anterior. Las remediaciones de esta investigación no cambian contraseñas, no generan bloqueos ni habilitan RDP.

## Utilizar la web

```powershell
Start-Process .\web\index.html
```

1. Pulsar **Cargar datos de ejemplo** o seleccionar/arrastrar un JSON moderno. El ejemplo es real: copia de la auditoría inicial, con su misma fecha e ID.
2. Revisar el puntaje junto con cobertura, no aplicables, no evaluados y errores.
3. Filtrar controles y abrir sus detalles; activar la justificación técnica si hace falta.
4. En Antes y después, cargar `datos/auditoria-inicial.json` y `datos/auditoria-posterior.json`. Aparecen +45 pp y nueve mejoras.
5. Descargar JSON o usar Imprimir/PDF. La comparación también tiene descarga propia.

La aplicación no remedia ni envía datos. Su CSP impide conexiones; las fuentes oficiales solo se visitan si se abre deliberadamente un enlace. Los colores llevan etiquetas. Los JSON históricos se rechazan por tener otro esquema e IDs con significados distintos.

## Datos y controles

Estados: Cumple, No cumple, No aplica, No evaluado, Error de evaluación. **Cumplimiento = cumplen / (cumplen + no cumplen) × 100**; si no hay evaluables, null/indeterminado. Los demás estados no entran al denominador. La comparación muestra denominadores y una intersección fija de controles comparables, para advertir cambios de cobertura.

Hay cinco controles de contraseñas, tres de bloqueo, tres perfiles de firewall, tres de UAC, SMBv1 servidor, NLA, dos subcategorías de auditoría, Invitado y tamaño de Security. No se afirma que cubran toda la baseline Microsoft actual. SecCon está archivado y se usa como referencia histórica explícita del objetivo de longitud.

Cada control tiene funciones explícitas, por ejemplo:

```powershell
Import-Module .\script\Baseline.psm1 -Force
Test-PW01
Set-PW01
# Con la ruta del respaldo individual que devuelve Set-PW01:
Undo-PW01 -Respaldo '.\respaldos\UUID-de-esa-operacion.json'
```

No copiar literalmente el UUID ilustrativo. Undo individual solo acepta el respaldo de ese único control; para respaldos de lotes usar Revertir-Baseline.ps1.

## Pruebas

PowerShell no requiere Pester:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\tests\Test-PowerShell.ps1
```

Para las pruebas de desarrollo de la web y la generación de documentos se usó Node **24.22.1**, npm y las versiones fijas de `package-lock.json`. No son dependencias de ejecución para usuarios de la herramienta.

```powershell
npm.cmd ci --ignore-scripts --no-fund --no-audit
npx.cmd playwright install ffmpeg
npm.cmd test
node tools\Preparar-Datos.cjs
npm.cmd run docs
node tools\Renderizar-Documentos.cjs
node tests\test-documentos.cjs
```

Se necesita Edge instalado para `test:web` y `docs`. La primera instalación de dependencias requiere internet; la web entregada y la defensa posterior funcionan offline. Se comprobó una instalación nueva con `npm ci` y se repitieron las pruebas web/JSON después de ella.  No ejecutar generación de documentos desde resultados diferentes sin revisar las conclusiones: la investigación entregada corresponde a la ejecución registrada.

Los registros verificables están en `evidencia/pruebas/`; Las pruebas no introducen fallos deliberados en protecciones. La prueba de registro usa una clave HKCU temporal única, respaldada antes de crearla y eliminada al terminar.

## Estructura

| Ruta | Contenido |
|---|---|
| `script/` | Módulo, catálogo, funciones por control y comandos de entrada. |
| `datos/` | Tres mediciones reales, ejemplo, comparación, diagnóstico y contrato. |
| `datos/historico/` | Auditoría anterior y prueba AU-02 simulada, sin mezclar con el experimento. |
| `web/` | Aplicación local sin dependencias ni build. |
| `evidencia/` | Entorno, diagnóstico, operaciones, pruebas y capturas/grabación auténticas. |
| `docs/` | Ficha original, informe PDF, PPTX. |
| `respaldos/`| Recuperación local . |

## Límites y estado de entrega

No se probaron aplicaciones heredadas, clientes externos ni un clon en VM limpia. No se modificaron controles que ya cumplían solo para ejercitar Set/Undo; esas ramas no cuentan como remediaciones probadas. Las veinte lecturas y las nueve configuraciones mejoradas sí se comprobaron. La reversión de valores no borra eventos creados ni recupera eventos sobrescritos. respaldo selectivo usado y verificado. No se asigna una nota ni se declara cumplimiento humano automático de la rúbrica.

