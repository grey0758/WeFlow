const fs = require('fs')
const path = require('path')
const { app } = require('electron')

const workspaceRoot = process.cwd()
const smokeRoot = path.join(workspaceRoot, '.tmp', 'media-service-smoke')
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

function countFilesWithExt(rootDir: string, ext: string): number {
  if (!fs.existsSync(rootDir)) return 0
  let count = 0
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const fullPath = path.join(dir, entry.name)
      if (entry.isDirectory()) {
        walk(fullPath)
        continue
      }
      if (entry.isFile() && entry.name.toLowerCase().endsWith(ext)) {
        count += 1
      }
    }
  }
  walk(rootDir)
  return count
}

async function main() {
  await app.whenReady()

  const { ConfigService } = require('../electron/services/config')
  const { dbPathService } = require('../electron/services/dbPathService')
  const { KeyService } = require('../electron/services/keyService')
  const { chatService } = require('../electron/services/chatService')
  const { videoService } = require('../electron/services/videoService')
  const { wcdbService } = require('../electron/services/wcdbService')

  const config = new ConfigService()
  const statusLogs: string[] = []
  const startedAt = Date.now()
  const step = (message: string) => console.log(`[media-service-smoke] ${message}`)

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

  config.set('dbPath', detected.path)
  config.set('myWxid', wxid)
  config.set('decryptKey', String(keyResult.key || ''))
  config.set('wcdbKeys', keyResult.wcdbKeys || {})
  config.set('cachePath', path.join(documentsDir, 'cache'))

  step('chat connect')
  const connectResult = await chatService.connect()
  if (!connectResult.success) {
    throw new Error(`chat connect failed: ${connectResult.error || 'unknown'}`)
  }

  step('load contacts and sessions')
  const contactsResult = await chatService.getContacts()
  const sessionsResult = await chatService.getSessions()
  if (!contactsResult.success || !Array.isArray(contactsResult.contacts)) {
    throw new Error(`getContacts failed: ${contactsResult.error || 'unknown'}`)
  }
  if (!sessionsResult.success || !Array.isArray(sessionsResult.sessions)) {
    throw new Error(`getSessions failed: ${sessionsResult.error || 'unknown'}`)
  }

  const accountDir = path.join(detected.path, wxid)
  const headImageDbPath = path.join(accountDir, 'db_storage', 'head_image', 'head_image.db')

  step('verify head_image avatar path')
  const headImageRows = await wcdbService.execQuery(
    'media',
    headImageDbPath,
    'SELECT username FROM head_image WHERE length(image_buffer) > 0 LIMIT 100'
  )
  const headImageCandidates = Array.isArray(headImageRows.rows)
    ? headImageRows.rows.map((row: any) => String(row?.username || '').trim()).filter(Boolean)
    : []
  if (headImageCandidates.length === 0) {
    throw new Error('head_image sample username not found')
  }
  const avatarMap = await (chatService as any).getAvatarsFromHeadImageDb(headImageCandidates) as Record<string, string>
  const avatarTarget = headImageCandidates.find((username: string) => {
    const value = String(avatarMap?.[username] || '').trim()
    return value.startsWith('data:image/')
  }) || ''
  if (!avatarTarget) {
    throw new Error('head_image helper returned no usable avatar sample')
  }
  const avatarUrl = String(avatarMap?.[avatarTarget] || '').trim()
  const avatarContact = contactsResult.contacts.find((contact: any) => String(contact?.username || '').trim() === avatarTarget) || null

  const hardlinkDbPath = path.join(accountDir, 'db_storage', 'hardlink', 'hardlink.db')
  const emoticonDbPath = path.join(accountDir, 'db_storage', 'emoticon', 'emoticon.db')

  step('load emoticon sample from db')
  const emoticonTableResult = await wcdbService.execQuery(
    'media',
    emoticonDbPath,
    "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('EmojiInfo', 'kNonStoreEmoticonTable') ORDER BY name"
  )
  const emoticonTable = Array.isArray(emoticonTableResult.rows) && emoticonTableResult.rows.length > 0
    ? String(emoticonTableResult.rows[0]?.name || '').trim()
    : ''
  const emoticonSampleResult = emoticonTable === 'kNonStoreEmoticonTable'
    ? await wcdbService.execQuery(
      'media',
      emoticonDbPath,
      "SELECT md5 FROM kNonStoreEmoticonTable WHERE cdn_url != '' OR extern_url != '' LIMIT 10"
    )
    : await wcdbService.execQuery(
      'media',
      emoticonDbPath,
      "SELECT md5 FROM EmojiInfo WHERE cdnUrl != '' OR CdnUrl != '' LIMIT 10"
    )
  const emojiMd5Candidates = Array.isArray(emoticonSampleResult.rows)
    ? emoticonSampleResult.rows.map((row: any) => String(row?.md5 || row?.Md5 || '').trim()).filter(Boolean)
    : []
  const emojiMsg: any = emojiMd5Candidates.length > 0
    ? { emojiMd5: emojiMd5Candidates[0] }
    : null
  if (!emojiMsg?.emojiMd5) {
    throw new Error('emoji sample md5 not found in emoticon.db')
  }
  step(`download emoji ${emojiMsg.emojiMd5}`)
  const emojiLocalPath = await chatService.downloadEmojiFile(emojiMsg)

  const videoBaseDir = path.join(accountDir, 'msg', 'video')
  const localMp4Count = countFilesWithExt(videoBaseDir, '.mp4')

  let videoInfo: any = null
  let videoMd5 = ''
  let videoSkippedReason: string | null = null
  let videoCandidateCount = 0

  if (localMp4Count > 0) {
    step('load video sample from hardlink db')
    const videoSampleResult = await wcdbService.execQuery(
      'media',
      hardlinkDbPath,
      "SELECT md5, file_name FROM video_hardlink_info_v4 LIMIT 200"
    )
    const videoCandidates = Array.isArray(videoSampleResult.rows) ? videoSampleResult.rows : []
    videoCandidateCount = videoCandidates.length
    for (const row of videoCandidates) {
      const candidateMd5 = String(row?.md5 || '').trim()
      if (!candidateMd5) continue
      const info = await videoService.getVideoInfo(candidateMd5)
      if (info?.exists && info.videoUrl && fs.existsSync(info.videoUrl)) {
        videoInfo = info
        videoMd5 = candidateMd5
        break
      }
    }
    if (!videoInfo || !videoMd5) {
      throw new Error('video sample could not be resolved from hardlink.db')
    }
  } else {
    videoSkippedReason = 'no local mp4 samples under msg/video'
  }

  try {
    await wcdbService.close()
  } catch {}

  const summary = {
    success:
      Boolean(avatarUrl) &&
      avatarUrl.startsWith('data:image/') &&
      Boolean(emojiLocalPath && fs.existsSync(emojiLocalPath)) &&
      (videoSkippedReason !== null || Boolean(videoInfo?.exists && videoInfo.videoUrl && fs.existsSync(videoInfo.videoUrl))),
    durationMs: Date.now() - startedAt,
    runRoot,
    keySource: keyResult.source || null,
    wcdbKeyCount: keyResult.wcdbKeys ? Object.keys(keyResult.wcdbKeys).length : 0,
    detectedPath: detected.path,
    wxid,
    avatar: {
      username: avatarTarget,
      helperHit: Boolean(avatarUrl),
      helperIsDataUrl: avatarUrl.startsWith('data:image/'),
      contactHasAvatar: Boolean(String(avatarContact?.avatarUrl || '').trim()),
      contactAvatarPreview: String(avatarContact?.avatarUrl || '').slice(0, 64) || null
    },
    emoji: {
      table: emoticonTable || null,
      md5: emojiMsg.emojiMd5,
      cdnUrlPresent: Boolean(String(emojiMsg.emojiCdnUrl || '').trim()),
      localPath: emojiLocalPath || null,
      localExists: Boolean(emojiLocalPath && fs.existsSync(emojiLocalPath))
    },
    video: {
      skipped: videoSkippedReason !== null,
      skippedReason: videoSkippedReason,
      localMp4Count,
      candidateCount: videoCandidateCount,
      md5: videoMd5,
      exists: Boolean(videoInfo?.exists),
      videoUrl: videoInfo?.videoUrl || null,
      videoExists: Boolean(videoInfo?.videoUrl && fs.existsSync(videoInfo.videoUrl)),
      coverPresent: Boolean(videoInfo?.coverUrl),
      thumbPresent: Boolean(videoInfo?.thumbUrl)
    },
    keyStatusTail: statusLogs.slice(-16)
  }

  console.log('---SUMMARY_START---')
  console.log(JSON.stringify(summary, null, 2))
  console.log('---SUMMARY_END---')

  if (!summary.success) {
    throw new Error('media service smoke failed')
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
  }, 50)
}

main()
  .then(() => {
    exitCode = 0
    finalizeExit()
  })
  .catch((error: any) => {
    exitCode = 1
    console.error(error)
    finalizeExit()
  })
