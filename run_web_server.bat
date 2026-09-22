@echo off
chcp 65001 > nul
cls
echo ============================================================
echo   JJNET MSSP Sovereign AI Agent - Web Dashboard 運籌伺服器
echo ============================================================
echo.
python "%~dp0server.py"
pause
