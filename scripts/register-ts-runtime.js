const fs = require('fs')
const path = require('path')
const ts = require('typescript')
const Module = require('module')

const runtimeFlag = Symbol.for('weflow.tsRuntime.registered')

if (!global[runtimeFlag]) {
  require.extensions['.ts'] = function registerTs(mod, filename) {
    const source = fs.readFileSync(filename, 'utf8')
    const out = ts.transpileModule(source, {
      compilerOptions: {
        module: ts.ModuleKind.CommonJS,
        target: ts.ScriptTarget.ES2020,
        esModuleInterop: true,
        allowSyntheticDefaultImports: true,
        jsx: ts.JsxEmit.ReactJSX
      },
      fileName: filename
    })
    mod._compile(out.outputText, filename)
  }

  const originalResolveFilename = Module._resolveFilename
  Module._resolveFilename = function patchedResolve(request, parent, isMain, options) {
    try {
      return originalResolveFilename.call(this, request, parent, isMain, options)
    } catch (error) {
      if (typeof request === 'string' && request.endsWith('.js')) {
        const tsRequest = request.slice(0, -3) + '.ts'
        return originalResolveFilename.call(this, tsRequest, parent, isMain, options)
      }
      throw error
    }
  }

  global[runtimeFlag] = true
}

module.exports = {
  workspaceRoot: path.resolve(__dirname, '..')
}
