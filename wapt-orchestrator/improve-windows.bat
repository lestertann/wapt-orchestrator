@echo off
REM ===== WAPT orchestrator - benchmark + self-improve (Windows) =====
cd /d "%~dp0"
where python >nul 2>nul
if %errorlevel%==0 (set PY=python) else (set PY=py)

echo.
echo   [1/2] Running the benchmark (scores the tool, writes gap_report.md)...
%PY% bench.py

echo.
if "%ANTHROPIC_API_KEY%"=="" (
  echo   [2/2] Self-improve SKIPPED: no ANTHROPIC_API_KEY set.
  echo         To let it improve itself, set your key first, e.g. in PowerShell:
  echo             $env:ANTHROPIC_API_KEY="sk-ant-..."
  echo         then run this again. The benchmark + gap_report.md above still work.
) else (
  echo   [2/2] Self-improving ^(bounded; only keeps changes that pass all tests^)...
  %PY% -m pip install --quiet requests >nul 2>nul
  %PY% autoimprove.py --iterations 5
)
echo.
pause
