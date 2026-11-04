@echo off
setlocal
rem ============================================================
rem  chromium-audit launcher for Windows
rem  - Finds Python 3, py launcher first and then python
rem  - Installs Python with winget when it is missing
rem  - Runs chromium-audit.py with any arguments you pass
rem     run.bat            audit only
rem     run.bat --update   audit and update what can be updated
rem     run.bat --json     machine-readable output
rem ============================================================
set "SCRIPT_DIR=%~dp0"
set "PYEXE="

py -3 --version >nul 2>&1
if not errorlevel 1 set "PYEXE=py -3"
if defined PYEXE goto have_python

python --version >nul 2>&1
if errorlevel 1 goto no_python
python --version 2>&1 | findstr /C:"Python 3" >nul
if errorlevel 1 goto no_python
set "PYEXE=python"
goto have_python

:no_python
echo Python 3 was not found on this PC.
echo.
where winget >nul 2>&1
if errorlevel 1 goto no_winget
echo Installing Python 3 with winget. This can take a minute...
winget install -e --id Python.Python.3.12 --accept-source-agreements --accept-package-agreements
if errorlevel 1 goto install_failed
py -3 --version >nul 2>&1
if errorlevel 1 goto install_failed
set "PYEXE=py -3"
goto have_python

:no_winget
echo winget is not available, so Python cannot be installed automatically.
echo Please install Python 3 from https://www.python.org/downloads/
echo and then run this file again.
start https://www.python.org/downloads/
goto finish_fail

:install_failed
echo Python installation did not complete.
echo Please install Python 3 from https://www.python.org/downloads/
echo and then run this file again.
goto finish_fail

:have_python
echo Using %PYEXE%
%PYEXE% "%SCRIPT_DIR%chromium-audit.py" %*
set "RC=%errorlevel%"
if "%~1"=="" pause
exit /b %RC%

:finish_fail
if "%~1"=="" pause
exit /b 1
