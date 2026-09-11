@echo off
setlocal

set "PROJECT_ROOT=%~dp0"
set "GUI_DIR=%PROJECT_ROOT%gui"
set "MINGW_PATH=D:\mingw64\bin"
set "SLINT_NO_QT=1"

set "CMD=%~1"
if "%CMD%"=="" set "CMD=build"

if /I "%CMD%"=="help"     goto :help
if /I "%CMD%"=="doctor"   goto :doctor
if /I "%CMD%"=="check"    goto :check
if /I "%CMD%"=="build"    goto :build
if /I "%CMD%"=="dev"      goto :dev
if /I "%CMD%"=="test"     goto :test
if /I "%CMD%"=="selftest" goto :selftest
if /I "%CMD%"=="run"      goto :run
if /I "%CMD%"=="clean"    goto :clean
if /I "%CMD%"=="all"      goto :all

echo [ERROR] Unknown command: %CMD%
echo Run "build.cmd help" for available commands.
exit /b 1


:help
echo Available commands:
echo.
echo   build.cmd doctor    - Check prerequisites
echo   build.cmd check     - Fast syntax check
echo   build.cmd build     - Full release build
echo   build.cmd dev       - Debug build
echo   build.cmd test      - Run unit tests
echo   build.cmd selftest  - Run offline self-test
echo   build.cmd run       - Build and run (Admin)
echo   build.cmd clean     - Clean artifacts
echo   build.cmd all       - doctor + check + build
echo.
exit /b 0


:doctor
echo [DOCTOR] Checking environment...
echo.

set FAILED=0

where rustc >nul 2>&1
if errorlevel 1 goto :doctor_no_rustc
rustc --version
goto :doctor_rustc_done
:doctor_no_rustc
echo [MISSING] rustc
set FAILED=1
:doctor_rustc_done

where cargo >nul 2>&1
if errorlevel 1 goto :doctor_no_cargo
cargo --version
goto :doctor_cargo_done
:doctor_no_cargo
echo [MISSING] cargo
set FAILED=1
:doctor_cargo_done

rustup show 2>nul | findstr /C:"windows-gnu" >nul
if errorlevel 1 goto :doctor_no_gnu
echo [OK] Toolchain: windows-gnu
goto :doctor_gnu_done
:doctor_no_gnu
echo [WARN] Default toolchain is not GNU
echo        Run: rustup default stable-x86_64-pc-windows-gnu
:doctor_gnu_done

where x86_64-w64-mingw32-gcc >nul 2>&1
if not errorlevel 1 goto :doctor_mingw_ok

if not exist "%MINGW_PATH%\x86_64-w64-mingw32-gcc.exe" goto :doctor_no_mingw
echo [WARN] MinGW at %MINGW_PATH% but not in PATH
echo        Adding for this session
set "PATH=%MINGW_PATH%;%PATH%"
goto :doctor_mingw_ok

:doctor_no_mingw
echo [MISSING] x86_64-w64-mingw32-gcc
set FAILED=1
goto :doctor_mingw_done

:doctor_mingw_ok
x86_64-w64-mingw32-gcc --version | findstr /R "gcc"
:doctor_mingw_done

if not exist "%PROJECT_ROOT%Cargo.toml" goto :doctor_no_root
echo [OK] Found Cargo.toml
goto :doctor_root_done
:doctor_no_root
echo [MISSING] Cargo.toml at %PROJECT_ROOT%
set FAILED=1
:doctor_root_done

if not exist "%GUI_DIR%\Cargo.toml" goto :doctor_no_gui
echo [OK] Found gui\Cargo.toml
goto :doctor_gui_done
:doctor_no_gui
echo [MISSING] gui\Cargo.toml
set FAILED=1
:doctor_gui_done

if not exist "%GUI_DIR%\ui\main.slint" goto :doctor_no_slint
echo [OK] Found gui\ui\main.slint
goto :doctor_slint_done
:doctor_no_slint
echo [WARN] gui\ui\main.slint not found
:doctor_slint_done

echo.
if "%FAILED%"=="1" goto :doctor_fail
echo [DOCTOR] Ready to build.
exit /b 0

:doctor_fail
echo [DOCTOR] Issues found. Fix and retry.
exit /b 1


:check
call :setup_env
echo [CHECK] Running cargo check...
cd /d "%PROJECT_ROOT%"
cargo check --workspace
if errorlevel 1 goto :check_fail
echo [CHECK OK]
exit /b 0
:check_fail
echo [CHECK FAILED]
exit /b 1


:build
call :setup_env
echo [BUILD] Release build...
cd /d "%PROJECT_ROOT%"
cargo build --release
if errorlevel 1 goto :build_fail
echo [BUILD OK]
echo.
echo Output: %PROJECT_ROOT%target\release\sni-gui.exe
exit /b 0
:build_fail
echo [BUILD FAILED]
echo.
echo Troubleshooting:
echo   1. Run: build.cmd doctor
echo   2. Make sure SLINT_NO_QT=1
echo   3. Try: build.cmd clean
exit /b 1


:dev
call :setup_env
echo [DEV] Debug build...
cd /d "%PROJECT_ROOT%"
cargo build
if errorlevel 1 goto :dev_fail
echo [DEV OK]
exit /b 0
:dev_fail
echo [DEV FAILED]
exit /b 1


:test
call :setup_env
echo [TEST] Running tests...
cd /d "%PROJECT_ROOT%"
cargo test --workspace --lib
if errorlevel 1 goto :test_fail
echo [TEST OK]
exit /b 0
:test_fail
echo [TEST FAILED]
exit /b 1


:selftest
call :setup_env
if not exist "%PROJECT_ROOT%target\release\sni-gui.exe" call :build
if errorlevel 1 exit /b 1
echo [SELFTEST] Running...
"%PROJECT_ROOT%target\release\sni-gui.exe" --self-test
if errorlevel 1 goto :selftest_fail
echo [SELFTEST OK]
exit /b 0
:selftest_fail
echo [SELFTEST FAILED]
exit /b 1


:run
call :build
if errorlevel 1 exit /b 1

net session >nul 2>&1
if errorlevel 1 goto :run_asadmin
start "" "%PROJECT_ROOT%target\release\sni-gui.exe"
exit /b 0
:run_asadmin
echo [WARN] Requesting Administrator privileges...
powershell -Command "Start-Process -FilePath '%PROJECT_ROOT%target\release\sni-gui.exe' -Verb RunAs"
exit /b 0


:clean
echo [CLEAN] Removing target/ ...
cd /d "%PROJECT_ROOT%"
if exist "target" rmdir /S /Q "target"
if exist "%GUI_DIR%\target" rmdir /S /Q "%GUI_DIR%\target"
echo [CLEAN OK]
exit /b 0


:all
call :doctor
if errorlevel 1 exit /b 1
echo.
call :check
if errorlevel 1 exit /b 1
echo.
call :build
if errorlevel 1 exit /b 1
echo.
echo [ALL DONE]
exit /b 0


:setup_env
set "SLINT_NO_QT=1"
set "CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc"
set "AR_x86_64_pc_windows_gnu=x86_64-w64-mingw32-ar"
if not exist "%MINGW_PATH%\x86_64-w64-mingw32-gcc.exe" exit /b 0
echo %PATH% | findstr /C:"%MINGW_PATH%" >nul
if not errorlevel 1 exit /b 0
set "PATH=%MINGW_PATH%;%PATH%"
exit /b 0