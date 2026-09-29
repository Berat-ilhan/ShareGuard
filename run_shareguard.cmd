@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo ShareGuard sanal ortami bulunamadi.
  echo Once scripts\build_windows.ps1 dosyasini calistirin.
  pause
  exit /b 1
)

".venv\Scripts\python.exe" main.py
if errorlevel 1 pause
