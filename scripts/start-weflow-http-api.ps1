$ErrorActionPreference = 'Stop'

$workspaceRoot = Split-Path -Parent $PSScriptRoot
$electronCmd = Join-Path $workspaceRoot 'node_modules\.bin\electron.cmd'
$runnerScript = Join-Path $workspaceRoot 'scripts\run-electron-ts.js'
$entryScript = Join-Path $workspaceRoot '.tmp\start-weflow-http-api.ts'

if (-not (Test-Path $electronCmd)) {
  throw "electron.cmd not found: $electronCmd"
}

Push-Location $workspaceRoot
try {
  & $electronCmd $runnerScript $entryScript
} finally {
  Pop-Location
}
