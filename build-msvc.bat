@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b %errorlevel%
if "%AOTRX_HDE_DIR%"=="" (
    echo Set AOTRX_HDE_DIR to MinHook's src\hde directory.
    exit /b 1
)
if not exist "%AOTRX_HDE_DIR%\hde64.c" (
    echo hde64.c was not found in AOTRX_HDE_DIR.
    exit /b 1
)
if not exist build mkdir build
cl /nologo /std:c11 /W4 /wd4701 /O2 /D_CRT_SECURE_NO_WARNINGS /DAOTRX_USE_HDE=1 /I src /I "%AOTRX_HDE_DIR%" src\dump.c src\main.c src\out.c src\pe.c src\sig.c "%AOTRX_HDE_DIR%\hde64.c" /Fe:build\aotrx.exe
exit /b %errorlevel%
