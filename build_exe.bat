@echo off
echo Installing PyInstaller...
pip install pyinstaller tkinterdnd2 customtkinter cryptography

echo.
echo Building CrypterPro.exe...
echo This may take a minute.
python -m PyInstaller --noconfirm --onefile --windowed --name "CrypterPro" --collect-all tkinterdnd2 --collect-all customtkinter app.py

if %errorlevel% neq 0 (
    echo.
    echo Build Failed! See errors above.
    pause
    exit /b
)

echo.
echo Build Success!
echo moving executable to current folder...
move dist\CrypterPro.exe .
rmdir /s /q build
rmdir /s /q dist
del CrypterPro.spec

echo.
echo Done! You can now run CrypterPro.exe
pause
