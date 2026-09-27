@echo off
rem ---------------------------------------------------------------------------
rem  Launches the O365 Management Toolkit menu.
rem  Finds the engine in ..\ScriptMenu\, .\ScriptMenu\, or beside this file.
rem  Use a hostname UNC path, never an IP, or the files land in the Internet
rem  zone and are blocked regardless of execution policy.
rem ---------------------------------------------------------------------------
setlocal
set "HERE=%~dp0"
set "MANIFEST=%HERE%menu.psd1"
set "ENGINE="

for %%C in ("%HERE%..\ScriptMenu\Start-ScriptMenu.ps1" "%HERE%ScriptMenu\Start-ScriptMenu.ps1" "%HERE%Start-ScriptMenu.ps1") do (
    if not defined ENGINE if exist "%%~fC" set "ENGINE=%%~fC"
)

if not defined ENGINE (
    echo.
    echo  Could not find Start-ScriptMenu.ps1. Looked in:
    echo    %HERE%..\ScriptMenu\
    echo    %HERE%ScriptMenu\
    echo    %HERE%
    echo.
    echo  Put the ScriptMenu folder beside this one and try again.
    echo.
    pause
    exit /b 1
)

if not exist "%MANIFEST%" (
    echo.
    echo  No menu.psd1 beside this file:
    echo    %MANIFEST%
    echo.
    pause
    exit /b 1
)

powershell.exe -NoProfile -NoLogo -ExecutionPolicy Bypass -File "%ENGINE%" -ManifestPath "%MANIFEST%"
set RC=%ERRORLEVEL%

if not "%RC%"=="0" (
    echo.
    echo  ------------------------------------------------------------------
    echo   The menu exited with code %RC%. The error above says why.
    echo  ------------------------------------------------------------------
    echo.
    pause
)

endlocal
