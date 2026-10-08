@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\scopepilot.exe" (
  echo ScopePilot is not installed. Follow README.md first.
  exit /b 1
)
set "SCOPEPILOT_ENABLE_LOCAL_TOOLS=1"
set "SCOPEPILOT_ENABLE_LOCAL_LLM=0"
echo ScopePilot: http://127.0.0.1:8000
echo Local tools can process built-in synthetic files only. Press Ctrl+C to stop.
".venv\Scripts\scopepilot.exe" --host 127.0.0.1 --port 8000
endlocal
