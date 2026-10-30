@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\OEM\install.ps1
exit /b %errorlevel%
