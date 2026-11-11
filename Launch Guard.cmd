@echo off
python "%~dp0guard.py" --gui
if errorlevel 1 pause
