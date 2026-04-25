const fs = require('fs')
const path = require('path')
const { app } = require('electron')

const workspaceRoot = process.cwd()
const smokeRoot = path.join(workspaceRoot, '.tmp', 'functional-smoke')
const runId = new Date().toISOString().replace(/[:.]/g, '-')
const runRoot = path.join(smokeRoot, runId)
const userDataDir = path.join(runRoot, 'userData')
const documentsDir = path.join(runRoot, 'documents')
const resourcesDir = path.join(workspaceRoot, 'resources')
let exitCode = 0

for (const dir of [smokeRoot, runRoot, userDataDir, documentsDir]) {
  fs.mkdirSync(dir, { recursive: true })
}

const sep = process.platform === 'win32' ? ';' : ':'
process.env.PATH = process.env.PATH
  ? `${resourcesDir}${sep}${process.env.PATH}`
  : resourcesDir
process.env.Path = process.env.PATH
process.env.WCDB_WORKER_PATH = path.join(workspaceRoot, 'scripts', 'wcdb-worker-runtime.js')

app.setPath('userData', userDataDir)

function pickSessionId(session: any): string {
  return String(
    session?.sessionId ||
    session?.username ||
    session?.userName ||
    session?.user_name ||
    ''
  ).trim()
}

function listFiles(baseDir: string, limit = 12): string[] {
  if (!fs.existsSync(baseDir)) return []
  const queue = [baseDir]
  const result: string[] = []
  while (queue.length > 0 && result.length < limit) {
    const current = queue.shift()
    if (!current) break
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const fullPath = path.join(current, entry.name)
      if (entry.isDirectory()) {
        queue.push(fullPath)
        continue
      }
      result.push(path.relative(baseDir, fullPath))
      if (result.length >= limit) break
    }
  }
  return result
}

function pickFirstValue(rows: any[] | undefined, keys: string[]): string {
  if (!Array.isArray(rows) || rows.length === 0) return ''
  const row = rows[0] || {}
  for (const key of keys) {
    const value = row?.[key]
    if (value !== undefined && value !== null && String(value).trim()) {
      return String(value).trim()
    }
  }
  return ''
}

async function main() {
  await app.whenReady()

  const { ConfigService } = require('../electron/services/config')
  const { dbPathService } = require('../electron/services/dbPathService')
  const { KeyService } = require('../electron/services/keyService')
  const { chatService } = require('../electron/services/chatService')
  const { snsService } = require('../electron/services/snsService')
  const { exportService } = require('../electron/services/exportService')
  const { contactExportService } = require('../electron/services/contactExportService')
  const { wcdbService } = require('../electron/services/wcdbService')

  const config = new ConfigService()
  const statusLogs: string[] = []
  const startedAt = Date.now()
  const step = (message: string) => console.log(`[functional-smoke] ${message}`)

  wcdbService.setPaths(resourcesDir, userDataDir)
  wcdbService.setLogEnabled(true)

  step('auto detect db path')
  const detected = await dbPathService.autoDetect()
  if (!detected?.success || !detected.path) {
    throw new Error(`dbPath auto detect failed: ${detected?.error || 'unknown'}`)
  }

  const wxids = dbPathService.scanWxids(detected.path)
  if (!Array.isArray(wxids) || wxids.length === 0) {
    throw new Error('no wxid found under detected db path')
  }

  const wxid = String(wxids[0].wxid || '').trim()
  if (!wxid) {
    throw new Error('detected wxid is empty')
  }

  step(`auto get db key for ${wxid}`)
  const keyService = new KeyService()
  const keyResult = await keyService.autoGetDbKey(30_000, (message: string, level: number) => {
    statusLogs.push(`[${level}] ${String(message || '').trim()}`)
  })
  if (!keyResult.success) {
    throw new Error(`autoGetDbKey failed: ${keyResult.error || 'unknown'}`)
  }

  step('seed config for service layer')
  config.set('dbPath', detected.path)
  config.set('myWxid', wxid)
  config.set('decryptKey', String(keyResult.key || ''))
  config.set('wcdbKeys', keyResult.wcdbKeys || {})
  config.set('cachePath', path.join(documentsDir, 'cache'))

  step('chat connect')
  const chatConnect = await chatService.connect()
  step('chat getSessions')
  const sessionsResult = await chatService.getSessions()
  step('chat getContacts')
  const contactsResult = await chatService.getContacts()
  const firstSession = sessionsResult?.sessions?.[0]
  const firstSessionId = pickSessionId(firstSession)

  step(`chat getMessages ${firstSessionId || '(skip)'}`)
  const messagesResult = firstSessionId
    ? await chatService.getMessages(firstSessionId, 0, 10)
    : { success: false, error: 'no session available' }

  step('sns getExportStats')
  const snsStatsResult = await snsService.getExportStats({ allowTimelineFallback: true })
  step('sns getTimeline')
  const timelineResult = await snsService.getTimeline(5, 0)

  const accountDir = path.join(detected.path, wxid)
  const hardlinkDbPath = path.join(accountDir, 'db_storage', 'hardlink', 'hardlink.db')
  const headImageDbPath = path.join(accountDir, 'db_storage', 'head_image', 'head_image.db')
  const emoticonDbPath = path.join(accountDir, 'db_storage', 'emoticon', 'emoticon.db')

  step('hardlink db query')
  const hardlinkTableResult = await wcdbService.execQuery(
    'media',
    hardlinkDbPath,
    "SELECT name FROM sqlite_master WHERE type='table' AND (name LIKE 'image_hardlink_info%' OR name='video_hardlink_info_v4') ORDER BY name"
  )
  const imageHardlinkTable = pickFirstValue(
    hardlinkTableResult.rows?.filter((row: any) => String(row?.name || '').startsWith('image_hardlink_info')),
    ['name']
  )
  const hardlinkImageSample = imageHardlinkTable
    ? await wcdbService.execQuery(
      'media',
      hardlinkDbPath,
      `SELECT md5, file_name, dir1, dir2 FROM ${imageHardlinkTable} LIMIT 1`
    )
    : { success: false, error: 'image hardlink table missing' }
  const hardlinkVideoSample = await wcdbService.execQuery(
    'media',
    hardlinkDbPath,
    "SELECT md5, file_name FROM video_hardlink_info_v4 LIMIT 1"
  )

  step('head_image db query')
  const headImageSample = await wcdbService.execQuery(
    'media',
    headImageDbPath,
    "SELECT username, length(image_buffer) AS image_size FROM head_image LIMIT 1"
  )

  step('emoticon db query')
  const emoticonTableResult = await wcdbService.execQuery(
    'media',
    emoticonDbPath,
    "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('EmojiInfo', 'kNonStoreEmoticonTable') ORDER BY name"
  )
  const emoticonTable = pickFirstValue(emoticonTableResult.rows, ['name'])
  const emoticonSample = emoticonTable === 'kNonStoreEmoticonTable'
    ? await wcdbService.execQuery(
      'media',
      emoticonDbPath,
      "SELECT md5, cdn_url, extern_url, thumb_url FROM kNonStoreEmoticonTable LIMIT 1"
    )
    : emoticonTable === 'EmojiInfo'
      ? await wcdbService.execQuery(
        'media',
        emoticonDbPath,
        "SELECT md5, cdnUrl, CdnUrl FROM EmojiInfo LIMIT 1"
      )
      : { success: false, error: 'no supported emoticon table found' }
  const emoticonMd5 = pickFirstValue(emoticonSample.rows, ['md5', 'Md5'])
  const emoticonLookup = emoticonMd5
    ? await wcdbService.getEmoticonCdnUrl(emoticonDbPath, emoticonMd5)
    : { success: false, error: 'no emoticon sample found' }

  step(`export getExportStats ${firstSessionId || '(skip)'}`)
  const exportStatsResult = firstSessionId
    ? await exportService.getExportStats([firstSessionId], {
      format: 'txt',
      exportMedia: false,
      exportAvatars: false,
      txtColumns: ['time', 'senderNickname', 'content']
    })
    : null

  const contactExportDir = path.join(documentsDir, 'exports', 'contacts')
  const sessionExportDir = path.join(documentsDir, 'exports', 'sessions')
  const snsExportDir = path.join(documentsDir, 'exports', 'sns')

  step('contact export json')
  const contactExportResult = await contactExportService.exportContacts(contactExportDir, {
    format: 'json',
    exportAvatars: false,
    contactTypes: {
      friends: true,
      groups: true,
      officials: true
    }
  })

  step(`session export txt ${firstSessionId || '(skip)'}`)
  const sessionExportResult = firstSessionId
    ? await exportService.exportSessions([firstSessionId], sessionExportDir, {
      format: 'txt',
      exportMedia: false,
      exportAvatars: false,
      txtColumns: ['time', 'senderNickname', 'content']
    })
    : { success: false, error: 'no session available', successCount: 0, failCount: 0 }

  step('sns export json')
  const snsExportResult = await snsService.exportTimeline({
    outputDir: snsExportDir,
    format: 'json',
    exportMedia: false
  })

  try {
    await wcdbService.close()
  } catch { }

  const summary = {
    success:
      Boolean(chatConnect?.success) &&
      Boolean(sessionsResult?.success) &&
      Boolean(contactsResult?.success) &&
      Boolean(messagesResult?.success) &&
      Boolean(snsStatsResult?.success) &&
      Boolean(timelineResult?.success) &&
      Boolean(hardlinkTableResult?.success) &&
      Boolean(headImageSample?.success) &&
      Boolean(emoticonSample?.success) &&
      Boolean(contactExportResult?.success) &&
      Boolean(sessionExportResult?.success) &&
      Boolean(snsExportResult?.success),
    durationMs: Date.now() - startedAt,
    keySource: keyResult.source || null,
    wcdbKeyCount: keyResult.wcdbKeys ? Object.keys(keyResult.wcdbKeys).length : 0,
    detectedPath: detected.path,
    runRoot,
    wxid,
    chatConnect,
    sessions: {
      success: Boolean(sessionsResult?.success),
      count: Array.isArray(sessionsResult?.sessions) ? sessionsResult.sessions.length : 0,
      firstSessionId
    },
    contacts: {
      success: Boolean(contactsResult?.success),
      count: Array.isArray(contactsResult?.contacts) ? contactsResult.contacts.length : 0
    },
    messages: {
      success: Boolean(messagesResult?.success),
      count: Array.isArray(messagesResult?.messages) ? messagesResult.messages.length : 0
    },
    snsStats: snsStatsResult,
    timeline: {
      success: Boolean(timelineResult?.success),
      count: Array.isArray(timelineResult?.timeline) ? timelineResult.timeline.length : 0
    },
    hardlink: {
      success: Boolean(hardlinkTableResult?.success),
      tableCount: Array.isArray(hardlinkTableResult?.rows) ? hardlinkTableResult.rows.length : 0,
      imageTable: imageHardlinkTable || null,
      imageSample: hardlinkImageSample,
      videoSample: hardlinkVideoSample
    },
    headImage: {
      success: Boolean(headImageSample?.success),
      sampleCount: Array.isArray(headImageSample?.rows) ? headImageSample.rows.length : 0,
      sample: headImageSample
    },
    emoticon: {
      success: Boolean(emoticonSample?.success),
      table: emoticonTable || null,
      sampleCount: Array.isArray(emoticonSample?.rows) ? emoticonSample.rows.length : 0,
      sample: emoticonSample,
      lookup: emoticonLookup
    },
    exportStats: exportStatsResult,
    contactExport: {
      ...contactExportResult,
      files: listFiles(contactExportDir)
    },
    sessionExport: {
      ...sessionExportResult,
      files: listFiles(sessionExportDir)
    },
    snsExport: {
      ...snsExportResult,
      files: listFiles(snsExportDir)
    },
    keyStatusTail: statusLogs.slice(-16)
  }

  console.log('---SUMMARY_START---')
  console.log(JSON.stringify(summary, null, 2))
  console.log('---SUMMARY_END---')

  if (!summary.success) {
    throw new Error('functional smoke failed')
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

main()
  .catch((error: any) => {
    console.error(error && error.stack ? error.stack : String(error))
    exitCode = 1
  })
  .finally(() => {
    finalizeExit()
  })
