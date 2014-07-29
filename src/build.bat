:: ============================================================================
:: Windows build script
:: Notes:
::   To disable the pause-on-error behavior, run as one of the following:
::       build.bat -p
::       build.bat --no-pause
:: ============================================================================
@echo off
cls



:: ============================================================================
:: Editable settings
:: ============================================================================

:: Path to the python.exe used execute the builder
set PYTHON=python

:: Path to the chrome.exe used to compile the extension
set CHROME=C:\Program Files (x86)\Google\Chrome\Application\chrome.exe

:: Path to the ffmpeg.exe used resize images
set FFMPEG=ffmpeg

:: Path to the ffprobe.exe used test images
set FFPROBE=ffprobe

:: Path of the userscript
set USERSCRIPT=%~dp0%EDIT_THIS.user.js

:: Path of the extension private key file
set KEY_FILE=%~dp0%EDIT_THIS.pem

:: Path of the built extension
set CRX_FILE=%~dp0%EDIT_THIS.crx

:: Path of the built extension
set CRX_UPDATE_FILE=%~dp0%EDIT_THIS.update.xml



:: ============================================================================
:: Setup
:: ============================================================================

set NO_PAUSE=0
if "%1%"=="-p" set NO_PAUSE=1
if "%1%"=="--no-pause" set NO_PAUSE=1

set BUILD_BATCH_FULL_FILENAME=build.bat
for %%A in ("%BUILD_BATCH_FULL_FILENAME%") do (
    set BUILD_BATCH_PATH=%%~dpA
    set BUILD_BATCH_FILENAME=%%~nxA
)

:: ============================================================================
:: Check for python
:: ============================================================================

"%PYTHON%" --version > NUL 2> NUL || goto :error_no_python

:: ============================================================================
:: Build execution
:: ============================================================================

"%PYTHON%" js2crx.py ^
	--chrome "%CHROME%" ^
	--ffmpeg "%FFMPEG%" ^
	--ffprobe "%FFPROBE%" ^
	--chrome-not-found-error "Chrome executable file was not found.\n\n\nEdit %BUILD_BATCH_FILENAME%'s ""CHROME"" setting at the top of the file;\n  change it to the full path of where chrome.exe is installed." ^
	--ffmpeg-not-found-error "FFmpeg executable file was not found.\n\n\nIf you have ffmpeg installed, either:\n  - Copy the ffmpeg.exe into the same directory as %BUILD_BATCH_FILENAME%\n    (should work if you use a static build of ffmpeg)\n  or\n  - Edit %BUILD_BATCH_FILENAME%'s ""FFMPEG"" setting at the top of the file;\n    change it to the full path of where ffmpeg.exe is installed\n  or\n  - Add ffmpeg to your path environment variable (google how to do this)\n\n\nIf you don't have ffmpeg, install it from one of the following links:\n  https://www.ffmpeg.org/download.html\n  http://ffmpeg.zeranoe.com/builds/" ^
	--ffprobe-not-found-error "FFprobe executable file was not found.\n\n\nIf you have ffprobe installed, either:\n  - Copy the ffprobe.exe into the same directory as %BUILD_BATCH_FILENAME%\n    (should work if you use a static build of ffprobe)\n  or\n  - Edit %BUILD_BATCH_FILENAME%'s ""FFPROBE"" setting at the top of the file;\n    change it to the full path of where ffprobe.exe is installed\n  or\n  - Add ffprobe to your path environment variable (google how to do this)\n\n\nIf you don't have ffprobe, install it from one of the following links:\n  https://www.ffmpeg.org/download.html\n  http://ffmpeg.zeranoe.com/builds/" ^
	--private-key "%KEY_FILE%" --private-key-generate-if-missing ^
	--userscript "%USERSCRIPT%" ^
	--crx "%CRX_FILE%" ^
	--crx-update-file "%CRX_UPDATE_FILE%" ^
	|| goto :error_build

:: ============================================================================
:: Success
:: ============================================================================


goto :eof

:: ============================================================================
:: Build error
:: ============================================================================
:error_build
if %NO_PAUSE%==0 (
	color 0c
	pause > NUL 2> NUL
	color
)
goto :eof

:: ============================================================================
:: No python error
:: ============================================================================
:error_no_python
if %NO_PAUSE%==0 color 0c
echo The python.exe version check failed.
echo.
echo.
echo The most likely problem is that you do not have python installed,
echo   or python is not in your path environment variable.
echo.
echo.
echo If you have python installed, either:
echo   - Edit %BUILD_BATCH_FILENAME%'s "PYTHON" setting at the top of the file;
echo     change it to the full path of where python.exe is installed
echo   or
echo   - Add python to your path environment variable (google how to do this)
echo.
echo.
echo If you don't have python, install it from the following link:
echo   https://www.python.org/
echo   (any up-to-date version should work)
if %NO_PAUSE%==0 (
	pause > NUL 2> NUL
	color
)
goto :eof


