@echo off
setlocal
cd /d "%~dp0"
chcp 65001 >nul

set "LOCAL_PYTHON=%LOCALAPPDATA%\Python\bin\python.exe"
if not exist "%LOCAL_PYTHON%" set "LOCAL_PYTHON=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if not exist "%LOCAL_PYTHON%" goto no_python

echo Checking whether the local app is already running...
powershell -NoProfile -Command "$c=New-Object Net.Sockets.TcpClient; try {$c.Connect('127.0.0.1',8000); $c.Close(); exit 0} catch {exit 1}"
if not errorlevel 1 goto open_browser

echo Starting the app in a separate server window...
start "Ansimnote server" cmd /k ""%LOCAL_PYTHON%" -u app.py > server-startup.log 2>&1"

echo Waiting for the server to respond on port 8000...
powershell -NoProfile -Command "$deadline=(Get-Date).AddSeconds(20); do {$c=New-Object Net.Sockets.TcpClient; try {$c.Connect('127.0.0.1',8000); $c.Close(); exit 0} catch {Start-Sleep -Milliseconds 500}} while ((Get-Date) -lt $deadline); exit 1"
if errorlevel 1 goto server_error

:open_browser
echo Opening http://127.0.0.1:8000/
start "" "http://127.0.0.1:8000/"
exit /b 0

:server_error
echo The server did not open port 8000. Check server-startup.log for the error.
if exist server-startup.log type server-startup.log
pause
exit /b 1

:no_python
echo Python was not found at the expected location.
echo Install Python 3 or send this message to the project maintainer.
pause
exit /b 1
