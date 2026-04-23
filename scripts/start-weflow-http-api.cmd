@echo off
setlocal
set "WORKSPACE_ROOT=%~dp0.."
call "%WORKSPACE_ROOT%\node_modules\.bin\electron.cmd" "%WORKSPACE_ROOT%\scripts\run-electron-ts.js" "%WORKSPACE_ROOT%\.tmp\start-weflow-http-api.ts"
