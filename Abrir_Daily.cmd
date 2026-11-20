@echo off
cd /d "%~dp0"
python main.py --daily-live
if errorlevel 1 pause
