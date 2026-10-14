@echo off
setlocal
cd /d "%~dp0"
if not exist "%~dp0Gmail Unsubscriber.pyw" goto missingfiles
where pyw.exe >nul 2>nul
if not errorlevel 1 (
    start "" pyw.exe "%~dp0Gmail Unsubscriber.pyw"
    exit /b
)
where pythonw.exe >nul 2>nul
if not errorlevel 1 (
    start "" pythonw.exe "%~dp0Gmail Unsubscriber.pyw"
    exit /b
)
echo Python's windowed launcher was not found.
echo Install Python 3.10 or newer from https://www.python.org/downloads/windows/
echo Include Tcl/Tk and the Python launcher, then reopen Gmail Unsubscriber.pyw.
pause
exit /b 1
:missingfiles
echo Extract the complete ZIP first, then run the launcher from that folder.
pause
exit /b 1
