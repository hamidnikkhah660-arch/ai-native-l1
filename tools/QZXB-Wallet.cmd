@echo off
setlocal
set "PYW=%LocalAppData%\Programs\Python\Python311\pythonw.exe"
if not exist "%PYW%" set "PYW=pythonw.exe"
start "QRun Wallet — QZXB" "%PYW%" "%~dp0QZXB-Wallet-App.py"
endlocal
