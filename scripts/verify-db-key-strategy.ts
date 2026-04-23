import { app } from 'electron'
import { KeyService } from '../electron/services/keyService'

type StatusItem = { message: string; level: number; ts: number }
let exitCode = 0

function includesAny(input: string, patterns: string[]): boolean {
  return patterns.some((pattern) => input.includes(pattern))
}

async function main() {
  const keyService = new KeyService()
  const statuses: StatusItem[] = []

  await app.whenReady()

  try {
    const startedAt = Date.now()
    const result = await keyService.autoGetDbKey(20_000, (message, level) => {
      const item = { message: String(message || ''), level, ts: Date.now() }
      statuses.push(item)
      console.log(`[status:${level}] ${item.message}`)
    })

    const messages = statuses.map((item) => item.message)
    const findIndex = (patterns: string[]) => messages.findIndex((message) => includesAny(message, patterns))

    const pyAttemptIndex = findIndex(['Trying PyWxDump bridge first...'])
    const nativeAttemptIndex = findIndex(['Trying native memory scan...'])
    const dllAttemptIndex = findIndex(['Falling back to wx_key.dll as the last resort...', 'DLL fallback:'])

    const summary = {
      success: result.success,
      source: result.source ?? null,
      durationMs: Date.now() - startedAt,
      hasKey: Boolean(result.key),
      wcdbKeyCount: result.wcdbKeys ? Object.keys(result.wcdbKeys).length : 0,
      error: result.error ?? null,
      attemptedPy: pyAttemptIndex >= 0,
      attemptedNative: nativeAttemptIndex >= 0,
      attemptedDll: dllAttemptIndex >= 0,
      noDllFallback: dllAttemptIndex < 0,
      nativeCaughtAfterPyMiss: result.success && result.source === 'native',
      pyCaughtDirectly: result.success && result.source === 'pywxdump',
      finalLogsTail: (result.logs ?? []).slice(-12),
      statusCount: statuses.length
    }

    if (!summary.success || !summary.attemptedPy || summary.attemptedDll || result.source === 'dll') {
      exitCode = 1
    }

    console.log('---SUMMARY_START---')
    console.log(JSON.stringify(summary, null, 2))
    console.log('---SUMMARY_END---')
  } finally {
    app.quit()
  }
}

function finalizeExit() {
  const code = Number.isInteger(exitCode) ? exitCode : 1
  setTimeout(() => {
    try {
      app.exit(code)
    } finally {
      process.exit(code)
    }
  }, 100)
}

main().catch((error) => {
  console.error(error)
  exitCode = 1
}).finally(() => {
  finalizeExit()
})
