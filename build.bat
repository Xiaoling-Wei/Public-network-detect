@echo off
chcp 65001 >nul
echo ========================================
echo   打包为独立 EXE
echo ========================================

python -m pip install pyinstaller -q

pyinstaller --noconfirm --onefile --windowed ^
  --name "网络安全检测" ^
  --add-data "assets;assets" ^
  --hidden-import PyQt6.QtSvg ^
  --hidden-import scapy.layers.l2 ^
  --hidden-import scapy.layers.inet ^
  main.py

echo.
echo 打包完成！EXE 文件位于 dist\ 目录
pause
