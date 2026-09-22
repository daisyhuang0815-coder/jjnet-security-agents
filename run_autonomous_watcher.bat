@echo off
chcp 65001 > nul
cls
echo ============================================================
echo   JJNET MSSP Sovereign AI Agent - 本機日誌目錄常駐自主監控
echo ============================================================
echo.
python "%~dp0agent_cli.py" --watch
pause
