@echo off
chcp 65001 >nul
cd /d "%~dp0"
python main.py
if errorlevel 1 (
    echo.
    echo 启动失败，请先运行 install.bat 安装依赖
    pause
)
