@echo off
type nul > "%~dp0automatic-state\stop.request"
echo Monitor will stop after its current scan. Login startup remains enabled.
pause
