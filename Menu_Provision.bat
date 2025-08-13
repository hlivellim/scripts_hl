@echo off
setlocal EnableExtensions

rem ===== RUTAS BASICAS =====
set "BASE=%~dp0"
set "PS1=%BASE%Provision.ps1"
set "LOGS=%BASE%logs"

rem SCRIPTS = carpeta padre de PROVISION (sin for /f sobre PowerShell)
pushd "%BASE%\.."
set "SCRIPTS=%CD%"
popd

set "BDCSV=%SCRIPTS%\BD_CSV"
set "PLAN=%BDCSV%\Provision_Plan.csv"
set "RESULTS=%BDCSV%\Provision_Results.csv"

if not exist "%LOGS%" md "%LOGS%"

rem ===== COMPROBACIONES =====
if not exist "%PS1%" echo [X] No se encontro "%PS1%" & pause & exit /b 1

rem Aviso (no auto-eleva)
net session >nul 2>&1
if errorlevel 1 (
  echo [!] Sugerencia: abre este CMD como ADMINISTRADOR para evitar errores.
  echo     Presiona una tecla para continuar...
  pause >nul
)

rem ===== MENU =====
:MENU
cls
echo ================= PROVISION MENU =================
echo [policy] Join unificado: ACTIVO (Add-Computer -NewName cuando aplique)
echo Los logs se guardan en: %LOGS%\Provision_YYYYMMDD_HHMMSSxx.log
echo 1) Simular (DryRun)
echo 2) Provisionar ahora (REAL)   ^<-- pide confirmacion
echo 3) Provisionar especificando NIC (Nombre exacto)
echo 4) Provisionar manteniendo Wi-Fi (ignorar auto-desactivacion)
echo 5) Validar Plan (solo valida CSV)
echo 6) Abrir carpeta de logs
echo 7) Abrir BD_CSV (plan/resultados)
echo 8) Ver Provision_Results.csv
echo 9) Ver ULTIMO log
echo F) Provisionar con -Force     ^<-- pide confirmacion
echo C) Limpiar logs (>30 dias)
echo 0) Salir
echo ==================================================
set "SEL="
set /p SEL=Opcion: 

if /I "%SEL%"=="1" goto DRYRUN
if /I "%SEL%"=="2" goto RUN
if /I "%SEL%"=="3" goto RUNNIC
if /I "%SEL%"=="4" goto RUNKEEPIW
if /I "%SEL%"=="5" goto VALIDATE
if /I "%SEL%"=="6" start "" "%LOGS%" & goto MENU
if /I "%SEL%"=="7" if not exist "%BDCSV%" md "%BDCSV%" & start "" "%BDCSV%" & goto MENU
if /I "%SEL%"=="8" goto VIEWRES
if /I "%SEL%"=="9" goto VIEWLAST
if /I "%SEL%"=="F" goto RUNFORCE
if /I "%SEL%"=="C" goto CLEANLOGS
if /I "%SEL%"=="0" goto END
goto MENU

rem ===== Genera STAMP robusto sin PowerShell =====
:STAMP
set "STAMP=%date%_%time%"
set "STAMP=%STAMP: =0%"
set "STAMP=%STAMP:/=%"
set "STAMP=%STAMP:\=%"
set "STAMP=%STAMP::=%"
set "STAMP=%STAMP:.=%"
set "STAMP=%STAMP:,=%"
set "STAMP=%STAMP%%RANDOM%"
exit /b

:DRYRUN
call :STAMP
set "LOG=%LOGS%\Provision_%STAMP%.log"
echo [*] DRYRUN - Log: "%LOG%"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -DryRun > "%LOG%" 2>&1
echo [i] RC=%ERRORLEVEL%
echo [i] Ver: %LOG%
echo.
pause
goto MENU

:RUN
echo.
echo [!] ESTO APLICA CAMBIOS EN ESTE EQUIPO (hostname/IP/join).
set "OK="
set /p OK=Escribe SI para confirmar y continuar (cualquier otra cosa cancela): 
if /I not "%OK%"=="SI" goto MENU
call :STAMP
set "LOG=%LOGS%\Provision_%STAMP%.log"
echo [*] RUN - Log: "%LOG%"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" > "%LOG%" 2>&1
echo [i] RC=%ERRORLEVEL%
echo [i] Ver: %LOG%
echo.
pause
goto MENU

:RUNNIC
set "NIC="
set /p NIC=Nombre EXACTO de la NIC (ej. Ethernet): 
if not defined NIC goto MENU
echo.
echo [!] ESTO APLICA CAMBIOS EN ESTE EQUIPO (hostname/IP/join).
set "OK="
set /p OK=Escribe SI para confirmar y continuar (cualquier otra cosa cancela): 
if /I not "%OK%"=="SI" goto MENU
call :STAMP
set "LOG=%LOGS%\Provision_%STAMP%.log"
echo [*] RUN (NIC="%NIC%") - Log: "%LOG%"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -NicName "%NIC%" > "%LOG%" 2>&1
echo [i] RC=%ERRORLEVEL%
echo [i] Ver: %LOG%
echo.
pause
goto MENU

:RUNKEEPIW
echo.
echo [!] ESTO APLICA CAMBIOS EN ESTE EQUIPO (hostname/IP/join).
set "OK="
set /p OK=Escribe SI para confirmar y continuar (cualquier otra cosa cancela): 
if /I not "%OK%"=="SI" goto MENU
call :STAMP
set "LOG=%LOGS%\Provision_%STAMP%.log"
echo [*] RUN (mantener Wi-Fi) - Log: "%LOG%"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -NoWifiAuto > "%LOG%" 2>&1
echo [i] RC=%ERRORLEVEL%
echo [i] Ver: %LOG%
echo.
pause
goto MENU

:RUNFORCE
echo.
echo [!] ESTO APLICA CAMBIOS EN ESTE EQUIPO (hostname/IP/join) CON -Force.
set "OK="
set /p OK=Escribe SI para confirmar y continuar (cualquier otra cosa cancela): 
if /I not "%OK%"=="SI" goto MENU
call :STAMP
set "LOG=%LOGS%\Provision_%STAMP%.log"
echo [*] RUN (-Force) - Log: "%LOG%"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -Force > "%LOG%" 2>&1
echo [i] RC=%ERRORLEVEL%
echo [i] Ver: %LOG%
echo.
pause
goto MENU

:VALIDATE
call :STAMP
set "LOG=%LOGS%\Provision_%STAMP%.log"
echo [*] VALIDATE PLAN - Log: "%LOG%"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -ValidatePlan > "%LOG%" 2>&1
echo [i] RC=%ERRORLEVEL%
echo [i] Ver: %LOG%
echo.
pause
goto MENU

:VIEWRES
if exist "%RESULTS%" (
  start "" "%RESULTS%"
) else (
  echo [i] No existe: "%RESULTS%"
  echo.
  pause
)
goto MENU

:VIEWLAST
set "LAST="
for /f "delims=" %%L in ('dir /b /a-d /o-d "%LOGS%\Provision_*.log" 2^>nul') do (
  if not defined LAST set "LAST=%LOGS%\%%~L"
)
if defined LAST (
  start "" "%LAST%"
) else (
  echo [i] Aun no hay logs en: %LOGS%
  echo.
  pause
)
goto MENU

:CLEANLOGS
echo [*] Limpiando logs con antiguedad > 30 dias...
forfiles /p "%LOGS%" /m *.* /d -30 /c "cmd /c del /q @path" >nul 2>&1
echo [OK] Limpieza hecha.
echo.
pause
goto MENU

:END
endlocal
exit /b
