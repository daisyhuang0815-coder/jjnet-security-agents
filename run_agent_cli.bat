@echo off
chcp 65001 > nul
cls
echo ============================================================
echo   JJNET MSSP Sovereign AI Agent - 終端機互動控制台
echo ============================================================
echo.
python "%~dp0agent_cli.py"
pause
