@echo off
echo Сборка приложения...
pyinstaller --onefile --windowed --icon=icon.ico encryptor_app.py
echo Готово! Исполняемый файл находится в папке dist\encryptor_app.exe
pause