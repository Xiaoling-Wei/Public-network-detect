@echo off
chcp 65001 >nul
echo ========================================
echo   公共网络安全检测工具 - 环境安装
echo ========================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未检测到 Python，请先安装 Python 3.11+
    echo 下载地址: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [1/3] 升级 pip...
python -m pip install --upgrade pip -q

echo [2/3] 安装依赖包...
python -m pip install -r requirements.txt

if errorlevel 1 (
    echo.
    echo [错误] 依赖安装失败，请检查网络连接后重试
    pause
    exit /b 1
)

echo [3/3] 依赖安装完成！
echo.
echo ========================================
echo 提示: ARP 检测功能需要安装 Npcap 驱动
echo 下载地址: https://npcap.com/#download
echo ========================================
echo.
echo 启动方式: 双击 run.bat 或运行 python main.py
echo.
pause
