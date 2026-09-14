@echo off
rem Launcher for the rust-agent bundle on Windows: exec the bundled binary,
rem forwarding all arguments. The bundle ships an x86_64 build, which also runs
rem on arm64 Windows via emulation.
setlocal
set "AGENT=%~dp0x86_64-pc-windows-gnu\htp-agent.exe"

if not exist "%AGENT%" (
  echo rust-agent: missing x86_64-pc-windows-gnu\htp-agent.exe in the bundle 1>&2
  exit /b 1
)

"%AGENT%" %*
exit /b %ERRORLEVEL%
