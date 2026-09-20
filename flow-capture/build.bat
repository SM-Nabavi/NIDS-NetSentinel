@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

REM =================== Configuration ===================
set "NPCAP_SDK=C:\Npcap-SDK"
set "CC=x86_64-w64-mingw32-gcc"
set "LIBDIR=x64"
set "OUT=bin\flow-capture.exe"
set "SRCS=src\main.c src\capture.c src\flow_table.c"
REM ======================================================

echo ============================================
echo   flow-capture build  (MinGW-W64 / gcc)
echo ============================================

REM --- 1. Check compiler ---
where %CC% >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Compiler not found: %CC%
    echo         Install MinGW-W64 ^(64-bit^) and add it to PATH.
    exit /b 1
)

REM --- 2. Check Npcap SDK ---
if not exist "%NPCAP_SDK%\Include\pcap.h" (
    echo [ERROR] Npcap SDK not found at "%NPCAP_SDK%".
    echo         Download from https://npcap.com/#download
    echo         Extract it there, or edit NPCAP_SDK in this script.
    exit /b 1
)

REM --- 3. Create bin\ if missing ---
if not exist bin (
    echo [INFO] Creating bin\ directory...
    mkdir bin
    if errorlevel 1 (
        echo [ERROR] Failed to create bin\ directory.
        exit /b 1
    )
)

REM --- 4. Skip if already built (unless "force") ---
if exist "%OUT%" if /i not "%~1"=="force" (
    echo [INFO] "%OUT%" already exists. Skipping build.
    echo        Run "build.bat force" to rebuild anyway.
    endlocal
    exit /b 0
)

REM --- 5. Compile ---
echo [INFO] Compiling flow-capture...
%CC% -O2 -Wall -Wextra -std=c11 ^
    -Iinclude ^
    -I"%NPCAP_SDK%\Include" ^
    %SRCS% ^
    -L"%NPCAP_SDK%\Lib\%LIBDIR%" ^
    -lwpcap -lPacket -lws2_32 -lIPHlpApi ^
    -o "%OUT%"

if errorlevel 1 (
    echo.
    echo [ERROR] Build failed. See errors above.
    endlocal
    exit /b 1
)

echo.
echo [OK] Built: %OUT%
endlocal
exit /b 0