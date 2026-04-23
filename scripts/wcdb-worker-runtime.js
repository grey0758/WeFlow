const path = require('path')
const { workspaceRoot } = require('./register-ts-runtime')

require(path.join(workspaceRoot, 'electron', 'wcdbWorker.ts'))
