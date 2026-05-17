@echo off
setlocal EnableExtensions

set "ROOT=%~dp0..\.."
pushd "%ROOT%" >nul

python tools\runtime\start_trace.py %*
set "CODE=%ERRORLEVEL%"
popd >nul
exit /b %CODE%
