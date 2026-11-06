@echo off
REM ===== WAPT orchestrator - one-click start (Windows) =====
REM Double-click this file. It installs what's needed, starts the engine,
REM and opens the dashboard in your browser. Leave this window open.

cd /d "%~dp0"
echo.
echo   Starting WAPT orchestrator...
echo.

REM find python (python, then py)
where python >nul 2>nul
if %errorlevel%==0 (set PY=python) else (set PY=py)

%PY% --version >nul 2>nul
if not %errorlevel%==0 (
  echo   Python is not installed.
  echo   Install it from https://www.python.org/downloads/  ^(tick "Add to PATH"^), then run this again.
  echo.
  pause
  exit /b 1
)

echo   Installing a small helper library ^(first time only^)...
%PY% -m pip install --quiet requests >nul 2>nul

echo   Launching the dashboard...
%PY% run.py --serve --open --mode lab

echo.
echo   Stopped. You can close this window.
pause
