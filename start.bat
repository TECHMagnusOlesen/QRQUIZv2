@echo off
REM Skift til den mappe, hvor denne .bat ligger
cd /d "%~dp0"

echo Starter server...
REM Kør server.js med Node
node server.js

echo.
pause