@echo off
rem ============================================================
rem  lan-file-share  one-click setup (Windows)
rem  Checks Node.js, installs optional deps, builds the HTTPS
rem  certificate, then starts the server.
rem ============================================================
chcp 65001 >nul 2>&1
cd /d "%~dp0"
set NODE=node
where node >nul 2>&1 || set NODE=node.exe

echo ============================================================
echo   LAN File Share - one-click setup
echo ============================================================
echo.

rem ---- 1) Node.js -------------------------------------------------
where node >nul 2>&1
if errorlevel 1 goto :NO_NODE
for /f "delims=" %%v in ('%NODE% -v') do echo [OK]   Node.js %%v
goto :CHECK_DEPS

:NO_NODE
echo [ERROR] Node.js not found.
echo         Please install Node.js 18 or newer from https://nodejs.org/
echo         then run setup.bat again.
goto :FIN

rem ---- 2) optional dependencies ----------------------------------
:CHECK_DEPS
if exist "node_modules\sharp" goto :DEPS_DONE
echo [..]   installing optional dependencies: sharp / archiver / webdav-server
echo        this may take a few minutes on first run ...
call npm install --no-audit --no-fund
if errorlevel 1 goto :DEPS_FAIL
echo [OK]   dependencies installed.
goto :CHECK_CERT

:DEPS_FAIL
echo [WARN] npm install failed. The server still runs, but these are disabled:
echo        low-res previews, ZIP batch download, WebDAV. Fix it later with: npm install
goto :CHECK_CERT

:DEPS_DONE
echo [OK]   dependencies already installed.

rem ---- 3) HTTPS certificate -------------------------------------
:CHECK_CERT
if exist "certs\server.crt" goto :CERT_DONE
echo [..]   generating self-signed HTTPS certificate ...
%NODE% gen-cert.js
if errorlevel 1 goto :CERT_FAIL
echo [OK]   certificate generated.
goto :START

:CERT_FAIL
echo [WARN] certificate generation failed - openssl is required.
echo        Install Git for Windows or Win64 OpenSSL, then run setup.bat again.
echo        You can also generate it manually:  node gen-cert.js
goto :FIN

:CERT_DONE
echo [OK]   certificate already exists.

rem ---- 4) run ----------------------------------------------------
:START
if not exist "share" mkdir "share"
echo.
echo ============================================================
echo   Setup finished. Starting the server ...
echo ============================================================
echo.
%NODE% server.js

:FIN
echo.
echo Window will close on any key. Read the messages above if there was an error.
pause
