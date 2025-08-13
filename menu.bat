@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Menu de Provisionamiento - provision.ps1

rem ======================== CONFIGURACIÓN INICIAL (valores por defecto) ========================
set "DOMAIN=instructores.senati.local"
set "GATEWAY=172.16.64.1"
set "NETMASK=255.255.248.0"
rem Lista separada por comas -> se convertirá a argumentos individuales -DnsServers
set "DNSSERVERS=172.16.11.2,172.16.11.4"
rem Nombre de NIC preferida (opcional). Déjelo vacío para auto-selección cableada más rápida
set "ADAPTERNAME="
rem 0 = permite reinicio automático; 1 = pasar -NoReboot al script
set "NOREBOOT=0"

rem ======================== UBICACIÓN DEL SCRIPT ========================
set "SCRIPT_DIR=%~dp0"
set "PS1=%SCRIPT_DIR%provision.ps1"

if not exist "%PS1%" (
  echo [ERROR] No se encuentra "provision.ps1" en: "%SCRIPT_DIR%"
  echo Copie este menu.bat junto a provision.ps1 y vuelva a intentarlo.
  pause
  exit /b 1
)

rem ======================== FUNCIONES AUXILIARES ========================
:PressKey
echo.
pause
goto :eof

:BuildDNSArgs
rem Convierte DNSSERVERS "a,b,c" en DNS_ARGS="a b c"
set "DNS_ARGS="
for %%D in (%DNSSERVERS:,= %) do (
  if defined DNS_ARGS (set "DNS_ARGS=!DNS_ARGS! %%D") else (set "DNS_ARGS=%%D")
)
goto :eof

:ShowConfig
cls
echo ===============================================================
echo                 CONFIGURACION ACTUAL APLICADA
echo ===============================================================
echo   DomainFQDN : %DOMAIN%
echo   Gateway    : %GATEWAY%
echo   NetMask    : %NETMASK%
echo   DnsServers : %DNSSERVERS%
echo   Adapter    : %ADAPTERNAME%
echo   NoReboot   : %NOREBOOT%
echo ---------------------------------------------------------------
echo   Script     : %PS1%
echo ===============================================================
echo.
goto :eof

:RunPS
rem %1 = ACTION
call :BuildDNSArgs
set "EXE=powershell.exe"
set "BASE_ARGS=-NoProfile -ExecutionPolicy Bypass -File"
set "COMMON=-DomainFQDN \"%DOMAIN%\" -Gateway \"%GATEWAY%\" -NetMask \"%NETMASK%\" -DnsServers !DNS_ARGS!"
if defined ADAPTERNAME set "COMMON=%COMMON% -AdapterName \"%ADAPTERNAME%\""
if "%NOREBOOT%"=="1" set "COMMON=%COMMON% -NoReboot"

echo.
echo ---------------------------------------------------------------
echo Ejecutando: %EXE% %BASE_ARGS% "%PS1%" -Action %1 %COMMON%
echo ---------------------------------------------------------------
%EXE% %BASE_ARGS% "%PS1%" -Action %1 %COMMON%
set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="0" (
  echo [OK] Accion "%~1" finalizada correctamente. (RC=%RC%)
) else (
  echo [ERROR] Accion "%~1" fallo. Codigo de salida: %RC%
)
echo ---------------------------------------------------------------
call :PressKey
goto :eof

:ToggleNoReboot
if "%NOREBOOT%"=="0" (set "NOREBOOT=1") else (set "NOREBOOT=0")
goto :eof

:EditParam
rem %1 = etiqueta mostrada, %2 = nombre de variable
set "LABEL=%~1"
set "VARNAME=%~2"
set "CURRENT=!%VARNAME%!"
set "INPUT="
echo.
set /p "INPUT=Nuevo valor para %LABEL% [actual: %CURRENT%] (Enter = mantener) : "
if defined INPUT (
  set "%VARNAME%=%INPUT%"
)
goto :eof

:EditDns
echo.
echo Ingrese servidores DNS separados por coma. Ejemplo: 172.16.11.2,172.16.11.4
set "INPUT="
set /p "INPUT=DNS [actual: %DNSSERVERS%] (Enter = mantener) : "
if defined INPUT (
  rem Normalizar espacios y comas
  set "TMP=%INPUT: =%"
  set "TMP=%TMP:,,=,%"
  set "DNSSERVERS=%TMP%"
)
goto :eof

rem ======================== MENÚ PRINCIPAL ========================
:MENU
call :ShowConfig
echo Seleccione una accion para provision.ps1:
echo.
echo   [1] Full         : Validar + Red estatica + Renombrar + Unir dominio (reinicia si corresponde)
echo   [2] NetOnly      : Solo red estatica
echo   [3] JoinOnly     : Solo union a dominio
echo   [4] RenameOnly   : Solo renombrar equipo
echo   [5] Validate     : Validaciones de conectividad e inventario (no modifica)
echo   [6] InventoryAdd : Agregar/actualizar registro al inventario
echo   [7] CredsSetup   : Configurar credenciales seguras en el USB
echo   [8] DryRun       : Simulacion (sin cambios ni escritura)
echo.
echo   ----- Parametros / Ajustes -----
echo   [D] Cambiar DomainFQDN
echo   [G] Cambiar Gateway
echo   [M] Cambiar NetMask
echo   [N] Cambiar DnsServers
echo   [A] Cambiar AdapterName (opcional)
echo   [R] Alternar NoReboot  (actual: %NOREBOOT%)
echo.
echo   [V] Ver configuracion
echo   [Q] Salir
echo.

set "OPT="
set /p "OPT=Opcion: "
if not defined OPT goto MENU
set "OPT=%OPT: =%"
set "OPT=%OPT:~0,2%"

if /I "%OPT%"=="1"  (call :RunPS Full       & goto MENU)
if /I "%OPT%"=="2"  (call :RunPS NetOnly    & goto MENU)
if /I "%OPT%"=="3"  (call :RunPS JoinOnly   & goto MENU)
if /I "%OPT%"=="4"  (call :RunPS RenameOnly & goto MENU)
if /I "%OPT%"=="5"  (call :RunPS Validate   & goto MENU)
if /I "%OPT%"=="6"  (call :RunPS InventoryAdd & goto MENU)
if /I "%OPT%"=="7"  (call :RunPS CredsSetup & goto MENU)
if /I "%OPT%"=="8"  (call :RunPS DryRun     & goto MENU)

if /I "%OPT%"=="D"  (call :EditParam "DomainFQDN" DOMAIN    & goto MENU)
if /I "%OPT%"=="G"  (call :EditParam "Gateway"    GATEWAY   & goto MENU)
if /I "%OPT%"=="M"  (call :EditParam "NetMask"    NETMASK   & goto MENU)
if /I "%OPT%"=="N"  (call :EditDns                         & goto MENU)
if /I "%OPT%"=="A"  (call :EditParam "AdapterName" ADAPTERNAME & goto MENU)
if /I "%OPT%"=="R"  (call :ToggleNoReboot                  & goto MENU)

if /I "%OPT%"=="V"  (call :ShowConfig & call :PressKey & goto MENU)
if /I "%OPT%"=="Q"  (goto END)

echo.
echo Opcion no valida.
call :PressKey
goto MENU

:END
echo Saliendo...
endlocal
exit /b 0
