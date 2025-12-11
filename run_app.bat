@echo off
cd /d "%~dp0"
python app.py
if %errorlevel% neq 0 (
    echo.
    echo The application crashed or failed to start.
    echo Please make sure Python is installed and added to your PATH.
    pause
)
