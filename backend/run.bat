@echo off
title Quantum-Proof Systems Scanner — Backend
echo.
echo ============================================================
echo   Quantum-Proof Systems Scanner API
echo   Team CypherRed261 ^| PSB Hackathon 2026 ^| LPU
echo ============================================================
echo.
echo [1/3] Moving to backend folder...
cd /d "%~dp0backend"

echo [2/3] Installing dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
  echo ERROR: pip install failed. Make sure Python 3.10+ is installed.
  pause
  exit /b 1
)

echo [3/3] Starting FastAPI server...
echo.
echo   API running at: http://localhost:8000
echo   Docs available: http://localhost:8000/docs
echo   Frontend:       Open frontend/index.html in Chrome
echo.
uvicorn main:app --reload --host 0.0.0.0 --port 8000
pause
