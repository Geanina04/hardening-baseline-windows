# A.5 Hardening con Baseline

## Descripción

Este proyecto consiste en revisar algunas configuraciones de seguridad de Windows 10 utilizando un script de PowerShell

La idea es conocer el estado actual de seguridad del equipo y verificar si cumple con algunos controles básicos Por ahora, el script solo revisa la configuración y genera un archivo con los resultados, sin realizar cambios en el sistema

## Cómo ejecutar el proyecto

1. Descargar el proyecto completo
2. Abrir Windows PowerShell como administrador
3. Entrar a la carpeta donde se encuentra el proyecto
4. Ejecutar el siguiente comando:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\script\Auditar-Baseline.ps1"
```

5. Al terminar, revisar el archivo `datos/auditoria-inicial.json`, donde se guardan los resultados

## ¿Qué revisa el script?

Por el momento se revisan cuatro aspectos de seguridad:

- **Firewall:** verifica si está activado
- **UAC:** revisa si el control de cuentas de usuario está habilitado
- **SMBv1:** comprueba si esta función antigua está desactivada
- **Escritorio remoto (RDP):** revisa si está desactivado o si tiene activada la autenticación NLA

Si alguno de los controles aparece como "No evaluado", significa que no se pudo comprobar su estado, por lo que no se toma en cuenta en el porcentaje de cumplimiento

## Seguridad

El script solamente consulta información del equipo No cambia configuraciones ni activa o desactiva funciones de Windows

Es importante revisar el archivo JSON antes de compartirlo, ya que puede contener información del equipo Si es necesario, se pueden ocultar esos datos

## Estado del proyecto

Esta es la primera versión del proyecto Actualmente permite realizar una revisión básica de seguridad

Más adelante se agregarán otros controles y se trabajará en posibles soluciones para las configuraciones que no cumplan con las recomendaciones de seguridad, realizando las pruebas en un entorno controlado
