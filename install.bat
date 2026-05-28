@echo off
REM ShadowNet - Windows Installer
REM Run: install.bat

echo.
echo ╔══════════════════════════════════════╗
echo ║         ShadowNet Installer          ║
echo ╚══════════════════════════════════════╝
echo.

REM Check Python
where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [-] Python 3 not found! Download from https://python.org
    pause
    exit /b 1
)

python --version
echo [*] Python detected

REM Install pip deps
echo [*] Installing dependencies...
python -m pip install --upgrade pip >nul 2>nul
python -m pip install dnspython >nul 2>nul

REM Create shortcut
set SCRIPTPATH=%~dp0
echo.
echo [*] To run from anywhere, add %SCRIPTPATH% to your PATH
echo     or use: python "%SCRIPTPATH%shadownet.py"

REM Create batch launcher
echo @echo off > "%SCRIPTPATH%shadownet.cmd"
echo python "%~dp0shadownet.py" %%* >> "%SCRIPTPATH%shadownet.cmd"

echo.
echo [+] ShadowNet installed!
echo.
echo   shadownet interactive     - Launch interactive mode
echo   shadownet scan ^<target^>   - Full scan
echo   shadownet quick ^<target^>  - Quick recon
echo   shadownet modules         - List modules
echo.
pause

