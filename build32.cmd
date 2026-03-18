@echo off

setlocal

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VSDEVCMD="

if exist "%VSWHERE%" (
	for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find Common7\Tools\VsDevCmd.bat`) do (
		set "VSDEVCMD=%%I"
	)
)

if not defined VSDEVCMD (
	if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" set "VSDEVCMD=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
)

if not defined VSDEVCMD (
	if exist "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\Tools\VsDevCmd.bat" set "VSDEVCMD=C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\Tools\VsDevCmd.bat"
)

if not defined VSDEVCMD (
	echo ERROR: Could not find VsDevCmd.bat. Install Visual Studio Build Tools or use MinGW make.
	exit /b 1
)

call "%VSDEVCMD%" -arch=x86 -host_arch=x86
if errorlevel 1 exit /b 1

cd /d "%~dp0"

set CL=/nologo /errorReport:none /Gm- /GF /GS- /MP /MT /W4 /WX /wd4324 /D_CRT_SECURE_NO_DEPRECATE
set LINK=/errorReport:none /INCREMENTAL:NO

set CL=%CL% /Ox
rem set CL=%CL% /Od /Zi
rem set LINK=%LINK% /DEBUG

cl.exe pkg2zip*.c miniz_tdef.c puff.c /Fepkg2zip.exe
endlocal
