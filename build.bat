@echo off
echo === Building Custom Flow ===
echo.

pip install pyinstaller >nul 2>&1

pyinstaller main.py ^
    --onefile ^
    --windowed ^
    --name CustomFlow ^
    --add-data ".env.example;."

echo.
if exist "dist\CustomFlow.exe" (
    echo Build successful!
    echo.
    echo Output: dist\CustomFlow.exe
    echo.
    echo To distribute:
    echo   1. Give users CustomFlow.exe + .env.example
    echo   2. They rename .env.example to .env and add their API keys
    echo   3. They double-click CustomFlow.exe
    echo   4. Right-click the pill to add to startup
) else (
    echo Build FAILED. Check errors above.
)

echo.
pause
