const path = require('path')
const { workspaceRoot } = require('./register-ts-runtime')

const input = process.argv[2]

if (!input) {
  console.error('Usage: electron scripts/run-electron-ts.js <script>')
  process.exit(1)
}

const scriptPath = path.isAbsolute(input)
  ? input
  : path.resolve(workspaceRoot, input)

require(scriptPath)
