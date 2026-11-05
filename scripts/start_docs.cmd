@echo off
setlocal
set "APF_NODE="
for %%I in (node.exe) do set "APF_NODE=%%~$PATH:I"
if not defined APF_NODE if exist "%ProgramFiles%\nodejs\node.exe" set "APF_NODE=%ProgramFiles%\nodejs\node.exe"
if not defined APF_NODE (
  echo Node.js was not found. Install a supported Node runtime and retry.
  exit /b 1
)
"%APF_NODE%" "%~dp0start_docs.cjs" %*
exit /b %errorlevel%
