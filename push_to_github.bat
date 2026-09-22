@echo off
chcp 65001 >nul
title JJNET GitHub Deployment Tool
echo ================================================================================
echo           🚀 JJNET Cyber SOC Multi-Agent Platform - GitHub 快速部署
echo ================================================================================
echo.
set /p GITHUB_TOKEN=請輸入您的 GitHub Personal Access Token (PAT): 
if "%GITHUB_TOKEN%"=="" (
    echo [ERROR] Token 不能為空！
    pause
    exit /b 1
)

set /p GITHUB_REPO=請輸入 Repository 名稱 (直接按 Enter 預設 jjnet-security-agents): 
if "%GITHUB_REPO%"=="" set GITHUB_REPO=jjnet-security-agents

set /p IS_PRIVATE=是否建立為 Private 私有庫？(y/N，直接按 Enter 為公開 Public): 
if /i "%IS_PRIVATE%"=="y" (
    python scripts\push_to_github.py --token "%GITHUB_TOKEN%" --repo "%GITHUB_REPO%" --private
) else (
    python scripts\push_to_github.py --token "%GITHUB_TOKEN%" --repo "%GITHUB_REPO%"
)

echo.
pause
