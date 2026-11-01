@echo off
setlocal
cd /d "%~dp0"
start "PKI RSA SM4 Server" /min cmd /c "npm.cmd start"

set "READY=0"
for /l %%i in (1,1,30) do (
  curl.exe --silent --fail http://localhost:3000/api/overview >nul 2>nul && set "READY=1" && goto :open
  timeout /t 1 /nobreak >nul
)

:open
if "%READY%"=="1" (
  start "" "http://localhost:3000"
) else (
  echo Server did not become ready in time.
)
exit /b
