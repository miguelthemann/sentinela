@echo off
title Sentinela HIDS - Instalador Windows
echo.
echo ======================================================
echo    Sentinela HIDS - A iniciar instalador Windows...
echo ======================================================
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERRO] Ocorreu uma falha durante a instalacao.
    pause
    exit /b %ERRORLEVEL%
)

echo.
pause
