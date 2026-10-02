@echo off
rem lan-file-share launcher - goto style, ascii only
chcp 65001 >nul 2>&1
cd /d "%~dp0"
set NODE=node
where node >nul 2>&1 || set NODE=node.exe

if exist "config.json" goto :HAVE_CFG
echo [ERROR] config.json not found in project folder.
goto :FIN

:HAVE_CFG
if exist "certs\server.crt" goto :HAVE_CERT
echo [NOTICE] HTTPS certificate not found yet, generating...
%NODE% gen-cert.js
if errorlevel 1 goto :CERT_FAILED

:HAVE_CERT
echo Starting HTTPS file-share server...
%NODE% server.js
goto :FIN

:CERT_FAILED
echo [ERROR] certificate generation failed.
echo         openssl required (Git for Windows or Win64 OpenSSL).
echo         Or rerun manually:  node gen-cert.js

:FIN
echo.
echo Window will close on any key. Read messages above if any error.
pause
