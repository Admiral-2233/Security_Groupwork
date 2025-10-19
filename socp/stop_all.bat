@echo off
echo Stopping all SOCP processes...
taskkill /F /IM python.exe 2>nul
echo All Python processes stopped.
pause