@echo off
title NFC Crew System V7.5
echo Checking required Python packages...
python -c "import flask, flask_wtf, flask_limiter, waitress, PIL, reportlab" >nul 2>&1
if errorlevel 1 (
  echo Installing required packages from requirements.lock...
  python -m pip install --require-hashes -r requirements.lock
  if errorlevel 1 (
    echo.
    echo Dependency installation failed. Run: python -m pip install --require-hashes -r requirements.lock
    pause
    exit /b 1
  )
)
echo Starting NFC Crew System V7.5...
python server.py
pause
