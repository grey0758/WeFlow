/**
 * HTTP API 服务
 * 提供 ChatLab 标准化格式的消息查询 API
 */
import * as http from 'http'
import * as fs from 'fs'
import * as path from 'path'
import * as crypto from 'crypto'
import * as fzstd from 'fzstd'
import { URL } from 'url'
import { chatService, Message } from './chatService'
import { wcdbService } from './wcdbService'
import { ConfigService } from './config'
import { KeyService } from './keyService'
import { nativeSqlcipherService } from './nativeSqlcipherService'
import { videoService } from './videoService'
import { imageDecryptService } from './imageDecryptService'
import { groupAnalyticsService } from './groupAnalyticsService'
import { wechatPayVerifierService } from './wechatPayVerifierService'

// ChatLab 格式定义
interface ChatLabHeader {
  version: string
  exportedAt: number
  generator: string
  description?: string
}

interface ChatLabMeta {
  name: string
  platform: string
  type: 'group' | 'private'
  groupId?: string
  groupAvatar?: string
  ownerId?: string
}

interface ChatLabMember {
  platformId: string
  accountName: string
  groupNickname?: string
  aliases?: string[]
  avatar?: string
}

interface ChatLabMessage {
  sender: string
  accountName: string
  groupNickname?: string
  timestamp: number
  type: number
  content: string | null
  platformMessageId?: string
  replyToMessageId?: string
  mediaPath?: string
}

interface ChatLabData {
  chatlab: ChatLabHeader
  meta: ChatLabMeta
  members: ChatLabMember[]
  messages: ChatLabMessage[]
}

interface ApiMediaOptions {
  enabled: boolean
  exportImages: boolean
  exportVoices: boolean
  exportVideos: boolean
  exportEmojis: boolean
}

type MediaKind = 'image' | 'voice' | 'video' | 'emoji'

interface ApiExportedMedia {
  kind: MediaKind
  fileName: string
  fullPath: string
  relativePath: string
}

interface PayApiEnvelope<T = any> {
  requestId: string
  success: boolean
  code: string
  message: string
  timestamp: number
  data: T | null
}

interface HiddenSessionSummaryItem {
  username: string
  talker: string
  displayName: string
  summary: string
  category: 'official' | 'system'
  reason: string
  contactType: string | null
  type: number
  unreadCount: number
  lastTimestamp: number
  payLike: boolean
  hasSummary: boolean
  matchText: string
}

// ChatLab 消息类型映射
const ChatLabType = {
  TEXT: 0,
  IMAGE: 1,
  VOICE: 2,
  VIDEO: 3,
  FILE: 4,
  EMOJI: 5,
  LINK: 7,
  LOCATION: 8,
  RED_PACKET: 20,
  TRANSFER: 21,
  POKE: 22,
  CALL: 23,
  SHARE: 24,
  REPLY: 25,
  FORWARD: 26,
  CONTACT: 27,
  SYSTEM: 80,
  RECALL: 81,
  OTHER: 99
} as const

class HttpService {
  private server: http.Server | null = null
  private configService: ConfigService
  private port: number = 5031
  private running: boolean = false
  private connections: Set<import('net').Socket> = new Set()
  private connectionMutex: boolean = false
  private payApiNonceCache: Map<string, number> = new Map()

  constructor() {
    this.configService = ConfigService.getInstance()
  }

  /**
   * 启动 HTTP 服务
   */
  async start(port: number = 5031): Promise<{ success: boolean; port?: number; error?: string }> {
    if (this.running && this.server) {
      return { success: true, port: this.port }
    }

    this.port = port

    try {
      await wechatPayVerifierService.start()
    } catch (error) {
      return { success: false, error: `Failed to start wechat pay verifier: ${String(error)}` }
    }

    return new Promise((resolve) => {
      this.server = http.createServer((req, res) => this.handleRequest(req, res))

      // 跟踪所有连接，以便关闭时能强制断开
      this.server.on('connection', (socket) => {
        // 使用互斥锁防止并发修改
        if (!this.connectionMutex) {
          this.connectionMutex = true
          this.connections.add(socket)
          this.connectionMutex = false
        }
        
        socket.on('close', () => {
          // 使用互斥锁防止并发修改
          if (!this.connectionMutex) {
            this.connectionMutex = true
            this.connections.delete(socket)
            this.connectionMutex = false
          }
        })
      })

      this.server.on('error', (err: NodeJS.ErrnoException) => {
        if (err.code === 'EADDRINUSE') {
          console.error(`[HttpService] Port ${this.port} is already in use`)
          resolve({ success: false, error: `Port ${this.port} is already in use` })
        } else {
          console.error('[HttpService] Server error:', err)
          resolve({ success: false, error: err.message })
        }
      })

      this.server.listen(this.port, '127.0.0.1', () => {
        this.running = true
        console.log(`[HttpService] HTTP API server started on http://127.0.0.1:${this.port}`)
        resolve({ success: true, port: this.port })
      })
    })
  }

  /**
   * 停止 HTTP 服务
   */
  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        // 使用互斥锁保护连接集合操作
        this.connectionMutex = true
        const socketsToClose = Array.from(this.connections)
        this.connections.clear()
        this.connectionMutex = false
        
        // 强制关闭所有活动连接
        for (const socket of socketsToClose) {
          try {
            socket.destroy()
          } catch (err) {
            console.error('[HttpService] Error destroying socket:', err)
          }
        }

        this.server.close(async () => {
          this.running = false
          this.server = null
          await wechatPayVerifierService.stop().catch((error) => {
            console.error('[HttpService] Failed to stop wechat pay verifier:', error)
          })
          console.log('[HttpService] HTTP API server stopped')
          resolve()
        })
      } else {
        this.running = false
        wechatPayVerifierService.stop().catch((error) => {
          console.error('[HttpService] Failed to stop wechat pay verifier:', error)
        }).finally(() => resolve())
      }
    })
  }

  /**
   * 检查服务是否运行
   */
  isRunning(): boolean {
    return this.running
  }

  /**
   * 获取当前端口
   */
  getPort(): number {
    return this.port
  }

  getDefaultMediaExportPath(): string {
    return this.getApiMediaExportPath()
  }

  /**
   * 处理 HTTP 请求
   */
  private async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    // 设置 CORS 头
    res.setHeader('Access-Control-Allow-Origin', '*')
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-WeFlow-Timestamp, X-WeFlow-Nonce, X-WeFlow-Signature')

    if (req.method === 'OPTIONS') {
      res.writeHead(204)
      res.end()
      return
    }

    const url = new URL(req.url || '/', `http://127.0.0.1:${this.port}`)
    const pathname = url.pathname

    try {
      // 路由处理
      if (pathname === '/health' || pathname === '/api/v1/health') {
        this.sendJson(res, { status: 'ok' })
      } else if (pathname === '/api/v1/messages') {
        await this.handleMessages(url, res)
      } else if (pathname === '/api/v1/official-messages') {
        await this.handleOfficialMessages(url, res)
      } else if (pathname === '/api/v1/session-summaries') {
        await this.handleSessionSummaries(url, res)
      } else if (pathname === '/api/v1/wechat-pay-assistant') {
        await this.handleWechatPayAssistant(url, res)
      } else if (pathname === '/api/v1/wechat-pay-assistant/messages') {
        await this.handleWechatPayAssistantMessages(url, res)
      } else if (pathname === '/api/v1/wechat-pay-assistant/verify') {
        await this.handleWechatPayAssistantVerify(req, url, res)
      } else if (pathname === '/api/v1/wechat-pay-assistant/events') {
        await this.handleWechatPayAssistantEvents(req, url, res)
      } else if (pathname === '/api/v1/wechat-pay-assistant/sync') {
        await this.handleWechatPayAssistantSync(req, url, res)
      } else if (pathname === '/api/v1/sessions') {
        await this.handleSessions(url, res)
      } else if (pathname === '/api/v1/contacts') {
        await this.handleContacts(url, res)
      } else if (pathname === '/api/v1/group-members') {
        await this.handleGroupMembers(url, res)
      } else if (pathname.startsWith('/api/v1/media/')) {
        this.handleMediaRequest(pathname, res)
      } else {
        this.sendError(res, 404, 'Not Found')
      }
    } catch (error) {
      console.error('[HttpService] Request error:', error)
      this.sendError(res, 500, String(error))
    }
  }

  private handleMediaRequest(pathname: string, res: http.ServerResponse): void {
    const mediaBasePath = this.getApiMediaExportPath()
    const relativePath = pathname.replace('/api/v1/media/', '')
    const fullPath = path.join(mediaBasePath, relativePath)

    if (!fs.existsSync(fullPath)) {
      this.sendError(res, 404, 'Media not found')
      return
    }

    const ext = path.extname(fullPath).toLowerCase()
    const mimeTypes: Record<string, string> = {
      '.png': 'image/png',
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.gif': 'image/gif',
      '.webp': 'image/webp',
      '.wav': 'audio/wav',
      '.mp3': 'audio/mpeg',
      '.mp4': 'video/mp4'
    }
    const contentType = mimeTypes[ext] || 'application/octet-stream'

    try {
      const fileBuffer = fs.readFileSync(fullPath)
      res.setHeader('Content-Type', contentType)
      res.setHeader('Content-Length', fileBuffer.length)
      res.writeHead(200)
      res.end(fileBuffer)
    } catch (e) {
      this.sendError(res, 500, 'Failed to read media file')
    }
  }

  /**
   * 批量获取消息（循环游标直到满足 limit）
   * 绕过 chatService 的单 batch 限制，直接操作 wcdbService 游标
   */
  private async fetchMessagesBatch(
    talker: string,
    offset: number,
    limit: number,
    startTime: number,
    endTime: number,
    ascending: boolean
  ): Promise<{ success: boolean; messages?: Message[]; hasMore?: boolean; error?: string }> {
    try {
      // 使用固定 batch 大小（与 limit 相同或最多 500）来减少循环次数
      const batchSize = Math.min(limit, 500)
      const beginTimestamp = startTime > 10000000000 ? Math.floor(startTime / 1000) : startTime
      const endTimestamp = endTime > 10000000000 ? Math.floor(endTime / 1000) : endTime

      const cursorResult = await wcdbService.openMessageCursor(talker, batchSize, ascending, beginTimestamp, endTimestamp)
      if (!cursorResult.success || !cursorResult.cursor) {
        return { success: false, error: cursorResult.error || '打开消息游标失败' }
      }

      const cursor = cursorResult.cursor
      try {
        const allRows: Record<string, any>[] = []
        let hasMore = true
        let skipped = 0

        // 循环获取消息，处理 offset 跳过 + limit 累积
        while (allRows.length < limit && hasMore) {
          const batch = await wcdbService.fetchMessageBatch(cursor)
          if (!batch.success || !batch.rows || batch.rows.length === 0) {
            hasMore = false
            break
          }

          let rows = batch.rows
          hasMore = batch.hasMore === true

          // 处理 offset：跳过前 N 条
          if (skipped < offset) {
            const remaining = offset - skipped
            if (remaining >= rows.length) {
              skipped += rows.length
              continue
            }
            rows = rows.slice(remaining)
            skipped = offset
          }

          allRows.push(...rows)
        }

        const trimmedRows = allRows.slice(0, limit)
        const finalHasMore = hasMore || allRows.length > limit
        const messages = chatService.mapRowsToMessagesForApi(trimmedRows)
        await this.backfillMissingSenderUsernames(talker, messages)
        return { success: true, messages, hasMore: finalHasMore }
      } finally {
        await wcdbService.closeMessageCursor(cursor)
      }
    } catch (e) {
      console.error('[HttpService] fetchMessagesBatch error:', e)
      return { success: false, error: String(e) }
    }
  }

  /**
   * Query param helpers.
   */
  private parseIntParam(value: string | null, defaultValue: number, min: number, max: number): number {
    const parsed = parseInt(value || '', 10)
    if (!Number.isFinite(parsed)) return defaultValue
    return Math.min(Math.max(parsed, min), max)
  }

  private async parseJsonBody(req: http.IncomingMessage): Promise<{ rawBody: string; json: Record<string, any> }> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = []
      let totalLength = 0
      const maxBytes = 1024 * 1024

      req.on('data', (chunk: Buffer | string) => {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
        totalLength += buffer.length
        if (totalLength > maxBytes) {
          reject(new Error('Request body too large'))
          req.destroy()
          return
        }
        chunks.push(buffer)
      })

      req.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8').trim()
        if (!raw) {
          resolve({ rawBody: '', json: {} })
          return
        }

        try {
          const parsed = JSON.parse(raw)
          if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            reject(new Error('Request body must be a JSON object'))
            return
          }
          resolve({
            rawBody: raw,
            json: parsed as Record<string, any>
          })
        } catch {
          reject(new Error('Invalid JSON body'))
        }
      })

      req.on('error', (error) => reject(error))
    })
  }

  private async backfillMissingSenderUsernames(talker: string, messages: Message[]): Promise<void> {
    if (!talker.endsWith('@chatroom')) return

    const targets = messages.filter((msg) => !String(msg.senderUsername || '').trim())
    if (targets.length === 0) return

    const myWxid = (this.configService.get('myWxid') || '').trim()
    for (const msg of targets) {
      const localId = Number(msg.localId || 0)
      if (Number.isFinite(localId) && localId > 0) {
        try {
          const detail = await wcdbService.getMessageById(talker, localId)
          if (detail.success && detail.message) {
            const hydrated = chatService.mapRowsToMessagesForApi([detail.message])[0]
            if (hydrated?.senderUsername) {
              msg.senderUsername = hydrated.senderUsername
            }
            if ((msg.isSend === null || msg.isSend === undefined) && hydrated?.isSend !== undefined) {
              msg.isSend = hydrated.isSend
            }
            if (!msg.rawContent && hydrated?.rawContent) {
              msg.rawContent = hydrated.rawContent
            }
          }
        } catch (error) {
          console.warn('[HttpService] backfill sender failed:', error)
        }
      }

      if (!msg.senderUsername && msg.isSend === 1 && myWxid) {
        msg.senderUsername = myWxid
      }
    }
  }

  private parseBooleanParam(url: URL, keys: string[], defaultValue: boolean = false): boolean {
    for (const key of keys) {
      const raw = url.searchParams.get(key)
      if (raw === null) continue
      const normalized = raw.trim().toLowerCase()
      if (['1', 'true', 'yes', 'on'].includes(normalized)) return true
      if (['0', 'false', 'no', 'off'].includes(normalized)) return false
    }
    return defaultValue
  }

  private parseMediaOptions(url: URL): ApiMediaOptions {
    const mediaEnabled = this.parseBooleanParam(url, ['media', 'meiti'], false)
    if (!mediaEnabled) {
      return {
        enabled: false,
        exportImages: false,
        exportVoices: false,
        exportVideos: false,
        exportEmojis: false
      }
    }

    return {
      enabled: true,
      exportImages: this.parseBooleanParam(url, ['image', 'tupian'], true),
      exportVoices: this.parseBooleanParam(url, ['voice', 'vioce'], true),
      exportVideos: this.parseBooleanParam(url, ['video'], true),
      exportEmojis: this.parseBooleanParam(url, ['emoji'], true)
    }
  }

  private async handleMessages(url: URL, res: http.ServerResponse): Promise<void> {
    const talker = (url.searchParams.get('talker') || '').trim()
    const limit = this.parseIntParam(url.searchParams.get('limit'), 100, 1, 10000)
    const offset = this.parseIntParam(url.searchParams.get('offset'), 0, 0, Number.MAX_SAFE_INTEGER)
    const keyword = (url.searchParams.get('keyword') || '').trim().toLowerCase()
    const startParam = url.searchParams.get('start')
    const endParam = url.searchParams.get('end')
    const chatlab = this.parseBooleanParam(url, ['chatlab'], false)
    const formatParam = (url.searchParams.get('format') || '').trim().toLowerCase()
    const format = formatParam || (chatlab ? 'chatlab' : 'json')
    const mediaOptions = this.parseMediaOptions(url)

    if (!talker) {
      this.sendError(res, 400, 'Missing required parameter: talker')
      return
    }

    if (format !== 'json' && format !== 'chatlab') {
      this.sendError(res, 400, 'Invalid format, supported: json/chatlab')
      return
    }

    const startTime = this.parseTimeParam(startParam)
    const endTime = this.parseTimeParam(endParam, true)
    const queryOffset = keyword ? 0 : offset
    const queryLimit = keyword ? 10000 : limit

    const result = await this.fetchMessagesBatch(talker, queryOffset, queryLimit, startTime, endTime, false)
    if (!result.success || !result.messages) {
      this.sendError(res, 500, result.error || 'Failed to get messages')
      return
    }

    let messages = result.messages
    let hasMore = result.hasMore === true

    if (keyword) {
      const filtered = messages.filter((msg) => {
        const content = (msg.parsedContent || msg.rawContent || '').toLowerCase()
        return content.includes(keyword)
      })
      const endIndex = offset + limit
      hasMore = filtered.length > endIndex
      messages = filtered.slice(offset, endIndex)
    }

    const mediaMap = mediaOptions.enabled
      ? await this.exportMediaForMessages(messages, talker, mediaOptions)
      : new Map<number, ApiExportedMedia>()

    const displayNames = await this.getDisplayNames([talker])
    const talkerName = displayNames[talker] || talker

    if (format === 'chatlab') {
      const chatLabData = await this.convertToChatLab(messages, talker, talkerName, mediaMap)
      this.sendJson(res, {
        ...chatLabData,
        media: {
          enabled: mediaOptions.enabled,
          exportPath: this.getApiMediaExportPath(),
          count: mediaMap.size
        }
      })
      return
    }

    const apiMessages = messages.map((msg) => this.toApiMessage(msg, mediaMap.get(msg.localId)))
    this.sendJson(res, {
      success: true,
      talker,
      count: apiMessages.length,
      hasMore,
      media: {
        enabled: mediaOptions.enabled,
        exportPath: this.getApiMediaExportPath(),
        count: mediaMap.size
      },
      messages: apiMessages
    })
  }

  private async handleOfficialMessages(url: URL, res: http.ServerResponse): Promise<void> {
    const username = (
      url.searchParams.get('username') ||
      url.searchParams.get('talker') ||
      ''
    ).trim()
    const name = (
      url.searchParams.get('name') ||
      url.searchParams.get('officialName') ||
      ''
    ).trim()

    if (!username && !name) {
      this.sendError(res, 400, 'Missing required parameter: username or name')
      return
    }

    const contactsResult = await chatService.getContacts()
    if (!contactsResult.success || !contactsResult.contacts) {
      this.sendError(res, 500, contactsResult.error || 'Failed to get contacts')
      return
    }

    const officialContacts = contactsResult.contacts.filter((contact) => contact.type === 'official')
    let resolved = null as typeof officialContacts[number] | null

    if (username) {
      resolved = officialContacts.find((contact) => contact.username === username) || null
      if (!resolved) {
        this.sendError(res, 404, `Official account not found: ${username}`)
        return
      }
    } else {
      const normalized = name.toLowerCase()
      const exactMatches = officialContacts.filter((contact) => (
        String(contact.username || '').toLowerCase() === normalized ||
        String(contact.displayName || '').toLowerCase() === normalized ||
        String(contact.nickname || '').toLowerCase() === normalized ||
        String(contact.remark || '').toLowerCase() === normalized ||
        String(contact.alias || '').toLowerCase() === normalized
      ))

      const fuzzyMatches = exactMatches.length > 0
        ? exactMatches
        : officialContacts.filter((contact) => (
          String(contact.username || '').toLowerCase().includes(normalized) ||
          String(contact.displayName || '').toLowerCase().includes(normalized) ||
          String(contact.nickname || '').toLowerCase().includes(normalized) ||
          String(contact.remark || '').toLowerCase().includes(normalized) ||
          String(contact.alias || '').toLowerCase().includes(normalized)
        ))

      if (fuzzyMatches.length === 0) {
        this.sendError(res, 404, `Official account not found: ${name}`)
        return
      }

      if (fuzzyMatches.length > 1) {
        this.sendJson(res, {
          success: false,
          error: `Multiple official accounts matched: ${name}`,
          count: fuzzyMatches.length,
          candidates: fuzzyMatches.slice(0, 20).map((contact) => ({
            username: contact.username,
            displayName: contact.displayName,
            remark: contact.remark,
            nickname: contact.nickname,
            alias: contact.alias
          }))
        }, 409)
        return
      }

      resolved = fuzzyMatches[0]
    }

    url.searchParams.set('talker', resolved.username)
    await this.handleMessages(url, res)
  }

  private getRawSessionUsername(row: Record<string, any>): string {
    return String(
      row.username ||
      row.user_name ||
      row.userName ||
      row.usrName ||
      row.UsrName ||
      row.talker ||
      row.talker_id ||
      row.talkerId ||
      ''
    ).trim()
  }

  private classifyHiddenSession(username: string): {
    hidden: boolean
    category?: 'official' | 'system'
    reason?: string
  } {
    const normalized = String(username || '').trim().toLowerCase()
    if (!normalized || normalized.includes('@placeholder')) {
      return { hidden: false }
    }

    if (normalized.startsWith('gh_')) {
      return { hidden: true, category: 'official', reason: 'official-account' }
    }

    const excludedPrefixes = [
      'weixin',
      'qqmail',
      'fmessage',
      'medianote',
      'floatbottle',
      'newsapp',
      'brandsessionholder',
      'brandservicesessionholder',
      'notifymessage',
      'opencustomerservicemsg',
      'notification_messages',
      'userexperience_alarm',
      'helper_folders',
      '@helper_folders'
    ]

    for (const prefix of excludedPrefixes) {
      if (normalized === prefix || normalized.startsWith(prefix)) {
        return { hidden: true, category: 'system', reason: prefix }
      }
    }

    if (normalized.includes('@kefu.openim') || normalized.includes('@openim')) {
      return { hidden: true, category: 'system', reason: 'openim' }
    }

    if (normalized.includes('service_')) {
      return { hidden: true, category: 'system', reason: 'service' }
    }

    return { hidden: false }
  }

  private async collectHiddenSessionSummaries(): Promise<{
    success: boolean
    summaries?: HiddenSessionSummaryItem[]
    error?: string
  }> {
    const connectResult = await chatService.connect()
    if (!connectResult.success) {
      return { success: false, error: connectResult.error || 'Failed to connect chat service' }
    }

    const sessionsResult = await wcdbService.getSessions()
    if (!sessionsResult.success || !sessionsResult.sessions) {
      return { success: false, error: sessionsResult.error || 'Failed to get raw sessions' }
    }

    const rawRows = sessionsResult.sessions as Record<string, any>[]
    const hiddenRows = rawRows.filter((row) => this.classifyHiddenSession(this.getRawSessionUsername(row)).hidden)

    const usernames = Array.from(
      new Set(
        hiddenRows
          .map((row) => this.getRawSessionUsername(row))
          .filter(Boolean)
      )
    )

    const [displayNamesResult, contactsResult] = await Promise.all([
      usernames.length > 0
        ? wcdbService.getDisplayNames(usernames)
        : Promise.resolve({ success: true, map: {} as Record<string, string> }),
      chatService.getContacts()
    ])

    const displayNameMap = displayNamesResult.success && displayNamesResult.map
      ? displayNamesResult.map
      : {}
    const contactMap = new Map<string, { displayName?: string; type?: string; remark?: string; nickname?: string; alias?: string }>()
    if (contactsResult.success && contactsResult.contacts) {
      for (const contact of contactsResult.contacts) {
        contactMap.set(contact.username, {
          displayName: contact.displayName,
          type: contact.type,
          remark: contact.remark,
          nickname: contact.nickname,
          alias: contact.alias
        })
      }
    }

    const paymentKeywords = ['收款', '支付', '到账', 'pay', 'payment', 'transfer']
    const summaries = hiddenRows.map((row) => {
      const talker = this.getRawSessionUsername(row)
      const hiddenInfo = this.classifyHiddenSession(talker)
      const summary = String(row.summary || row.digest || row.last_msg || row.lastMsg || '').trim()
      const contact = contactMap.get(talker)
      const displayName = String(
        contact?.displayName ||
        displayNameMap[talker] ||
        talker
      ).trim()
      const haystack = [
        talker,
        displayName,
        contact?.remark,
        contact?.nickname,
        contact?.alias,
        summary
      ]
        .map((item) => String(item || '').toLowerCase())
        .join(' ')

      return {
        username: talker,
        talker,
        displayName,
        summary,
        category: (hiddenInfo.category || 'system') as 'official' | 'system',
        reason: hiddenInfo.reason || '',
        contactType: contact?.type || null,
        type: Number.parseInt(String(row.type || '0'), 10) || 0,
        unreadCount: Number.parseInt(String(row.unread_count || row.unreadCount || row.unreadcount || '0'), 10) || 0,
        lastTimestamp: Number.parseInt(String(
          row.last_timestamp ||
          row.lastTimestamp ||
          row.last_msg_time ||
          row.lastMsgTime ||
          row.sort_timestamp ||
          row.sortTimestamp ||
          '0'
        ), 10) || 0,
        payLike: paymentKeywords.some((item) => haystack.includes(item)),
        hasSummary: Boolean(summary),
        matchText: haystack
      }
    })

    return { success: true, summaries }
  }

  private async handleSessionSummaries(url: URL, res: http.ServerResponse): Promise<void> {
    const keyword = (url.searchParams.get('keyword') || '').trim().toLowerCase()
    const username = (url.searchParams.get('username') || '').trim().toLowerCase()
    const scope = (url.searchParams.get('scope') || 'all').trim().toLowerCase()
    const payOnly = this.parseBooleanParam(url, ['payOnly', 'paymentOnly'], false)
    const limit = this.parseIntParam(url.searchParams.get('limit'), 100, 1, 10000)

    if (!['all', 'official', 'system'].includes(scope)) {
      this.sendError(res, 400, 'Invalid scope, supported: all/official/system')
      return
    }

    try {
      const collected = await this.collectHiddenSessionSummaries()
      if (!collected.success || !collected.summaries) {
        this.sendError(res, 500, collected.error || 'Failed to collect hidden session summaries')
        return
      }

      let summaries = [...collected.summaries]

      if (scope !== 'all') {
        summaries = summaries.filter((item) => item.category === scope)
      }

      if (username) {
        summaries = summaries.filter((item) => item.username.toLowerCase().includes(username))
      }

      if (keyword) {
        summaries = summaries.filter((item) => item.matchText.includes(keyword))
      }

      if (payOnly) {
        summaries = summaries.filter((item) => item.payLike)
      }

      summaries.sort((a, b) => b.lastTimestamp - a.lastTimestamp)

      const limited = summaries.slice(0, limit).map(({ matchText, ...item }) => item)
      const categoryCounts = summaries.reduce((acc, item) => {
        acc[item.category] = (acc[item.category] || 0) + 1
        return acc
      }, {} as Record<string, number>)

      this.sendJson(res, {
        success: true,
        count: limited.length,
        totalMatched: summaries.length,
        scope,
        payOnly,
        categoryCounts,
        sessions: limited
      })
    } catch (error) {
      this.sendError(res, 500, String(error))
    }
  }

  private cleanWxidDirName(value: string): string {
    const trimmed = String(value || '').trim()
    if (!trimmed) return ''
    if (trimmed.toLowerCase().startsWith('wxid_')) {
      const match = trimmed.match(/^(wxid_[^_]+)/i)
      return match?.[1] || trimmed
    }
    const suffixMatch = trimmed.match(/^(.+)_([a-zA-Z0-9]{4})$/)
    return suffixMatch ? suffixMatch[1] : trimmed
  }

  private resolveBizMessageDbPath(): { success: boolean; dbPath?: string; accountDir?: string; error?: string } {
    const dbRoot = String(this.configService.get('dbPath') || '').trim()
    const myWxid = String(this.configService.get('myWxid') || '').trim()
    if (!dbRoot || !myWxid) {
      return { success: false, error: 'Missing dbPath or myWxid in config' }
    }

    const directPath = path.join(dbRoot, myWxid, 'db_storage', 'message', 'biz_message_0.db')
    if (fs.existsSync(directPath)) {
      return { success: true, dbPath: directPath, accountDir: myWxid }
    }

    const cleanedWxid = this.cleanWxidDirName(myWxid)
    const cleanedPath = path.join(dbRoot, cleanedWxid, 'db_storage', 'message', 'biz_message_0.db')
    if (fs.existsSync(cleanedPath)) {
      return { success: true, dbPath: cleanedPath, accountDir: cleanedWxid }
    }

    try {
      const matchedDir = fs.readdirSync(dbRoot, { withFileTypes: true })
        .filter((entry) => entry.isDirectory())
        .map((entry) => entry.name)
        .find((name) => name === cleanedWxid || name.startsWith(`${cleanedWxid}_`))

      if (matchedDir) {
        const matchedPath = path.join(dbRoot, matchedDir, 'db_storage', 'message', 'biz_message_0.db')
        if (fs.existsSync(matchedPath)) {
          return { success: true, dbPath: matchedPath, accountDir: matchedDir }
        }
      }
    } catch {}

    return { success: false, error: 'biz_message_0.db not found under configured dbPath' }
  }

  private decodeBizMessagePayload(raw: any): string {
    if (!raw) return ''

    let data: Buffer
    if (Buffer.isBuffer(raw) || raw instanceof Uint8Array) {
      data = Buffer.from(raw)
    } else if (typeof raw === 'string') {
      const trimmed = raw.trim()
      if (trimmed.length > 16 && trimmed.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(trimmed)) {
        data = Buffer.from(trimmed, 'hex')
      } else {
        data = Buffer.from(trimmed, 'utf8')
      }
    } else {
      data = Buffer.from(String(raw || ''), 'utf8')
    }

    if (data.length >= 4) {
      const magicLE = data.readUInt32LE(0)
      const magicBE = data.readUInt32BE(0)
      if (magicLE === 0xFD2FB528 || magicBE === 0xFD2FB528) {
        try {
          return Buffer.from(fzstd.decompress(data)).toString('utf8')
        } catch {}
      }
    }

    return data.toString('utf8')
  }

  private async ensureBizMessageKeysLoaded(): Promise<{ success: boolean; error?: string }> {
    const currentKeys = this.configService.get('wcdbKeys') as Record<string, string> | undefined
    if (currentKeys && Object.keys(currentKeys).length > 0) {
      wcdbService.setWcdbKeys(currentKeys)
    }

    const keyService = new KeyService()
    const result = await keyService.autoGetDbKey(30_000)
    if (!result.success || !result.wcdbKeys || Object.keys(result.wcdbKeys).length === 0) {
      return { success: false, error: result.error || 'Failed to load WCDB keys for biz_message_0.db' }
    }

    wcdbService.setWcdbKeys(result.wcdbKeys)
    this.configService.set('wcdbKeys', result.wcdbKeys)
    await wcdbService.shutdown().catch(() => {})
    const reconnectResult = await chatService.connect()
    if (!reconnectResult.success) {
      return { success: false, error: reconnectResult.error || 'Failed to reconnect WCDB with refreshed keys' }
    }
    return { success: true }
  }

  private extractXmlValue(xml: string, tag: string): string {
    const patterns = [
      new RegExp(`<${tag}><!\\[CDATA\\[([\\s\\S]*?)\\]\\]><\\/${tag}>`, 'i'),
      new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, 'i')
    ]

    for (const pattern of patterns) {
      const match = xml.match(pattern)
      if (match?.[1]) return match[1].trim()
    }
    return ''
  }

  private extractWechatPaySourceName(xml: string): string {
    const patterns = [
      /<category\b[^>]*>\s*<name><!\[CDATA\[([\s\S]*?)\]\]><\/name>/i,
      /<source>\s*<name><!\[CDATA\[([\s\S]*?)\]\]><\/name>/i
    ]

    for (const pattern of patterns) {
      const match = xml.match(pattern)
      if (match?.[1]) return match[1].trim()
    }
    return ''
  }

  private buildWechatPayBizRecord(row: Record<string, any>, username: string) {
    const rawXml = this.decodeBizMessagePayload(row.message_content)
    const rawSourceXml = this.decodeBizMessagePayload(row.source)
    const title = this.extractXmlValue(rawXml, 'title')
    const description = this.extractXmlValue(rawXml, 'des')
    const digest = this.extractXmlValue(rawXml, 'digest')
    const url = this.extractXmlValue(rawXml, 'url')
    const sourceName = this.extractWechatPaySourceName(rawXml)
    const pubTime = Number.parseInt(this.extractXmlValue(rawXml, 'pub_time') || '0', 10) || 0
    const mergedText = [title, description, digest, sourceName, rawXml].join('\n')
    const amount = this.extractAmountFromText(mergedText)

    return {
      username,
      localId: Number.parseInt(String(row.local_id || row.localId || '0'), 10) || 0,
      serverId: String(row.server_id || row.serverId || ''),
      localType: Number.parseInt(String(row.local_type || row.localType || '0'), 10) || 0,
      createTime: Number.parseInt(String(row.create_time || row.createTime || '0'), 10) || 0,
      publishedAt: pubTime || null,
      sourceName,
      title,
      description,
      digest,
      amount,
      url,
      rawXml,
      rawSourceXml
    }
  }

  private async queryWechatPayBizMessages(username: string, limit: number) {
    const resolved = this.resolveBizMessageDbPath()
    if (!resolved.success || !resolved.dbPath) {
      return { success: false, error: resolved.error || 'Failed to resolve biz_message_0.db path' }
    }

    const wcdbKeys = this.configService.get('wcdbKeys') as Record<string, string> | undefined
    if (!(wcdbKeys && Object.keys(wcdbKeys).length > 0)) {
      const reloadResult = await this.ensureBizMessageKeysLoaded()
      if (!reloadResult.success) {
        return { success: false, error: reloadResult.error || 'Failed to refresh WCDB keys' }
      }
    }

    const effectiveKeys = this.configService.get('wcdbKeys') as Record<string, string> | undefined
    if (!(effectiveKeys && Object.keys(effectiveKeys).length > 0)) {
      return { success: false, error: 'WCDB keys are still unavailable after refresh' }
    }

    const tableName = `Msg_${crypto.createHash('md5').update(username).digest('hex')}`
    const dbStoragePath = path.dirname(path.dirname(resolved.dbPath))
    const decryptOutDir = path.join(process.env.TEMP || process.env.TMP || path.dirname(resolved.dbPath), 'weflow_http_api_biz', resolved.accountDir || 'default')
    const decryptResult = await nativeSqlcipherService.decryptDbDir(
      effectiveKeys,
      dbStoragePath,
      decryptOutDir
    )
    if (!decryptResult.success) {
      return { success: false, error: decryptResult.error || 'Failed to decrypt biz_message_0.db' }
    }

    const decryptedBizPath = path.join(decryptOutDir, 'message', 'de_biz_message_0.db')
    if (!fs.existsSync(decryptedBizPath)) {
      return { success: false, error: 'de_biz_message_0.db was not produced by native decrypt' }
    }

    const BetterSqlite3 = require('better-sqlite3')
    const db = new BetterSqlite3(decryptedBizPath, { readonly: true, fileMustExist: true })
    try {
      const safeTableName = tableName.replace(/'/g, "''")
      const tableCheck = db.prepare(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = '${safeTableName}' LIMIT 1`).all()
      if (!tableCheck || tableCheck.length === 0) {
        return {
          success: true,
          dbPath: resolved.dbPath,
          accountDir: resolved.accountDir,
          tableName,
          records: []
        }
      }

      const rowLimit = Math.max(1, Math.min(limit, 1000))
      const rows = db.prepare(`
        SELECT local_id, server_id, local_type, create_time, source, message_content
        FROM ${tableName}
        ORDER BY create_time DESC, local_id DESC
        LIMIT ${rowLimit}
      `).all()

      return {
        success: true,
        dbPath: resolved.dbPath,
        accountDir: resolved.accountDir,
        tableName,
        records: rows.map((row: Record<string, any>) => this.buildWechatPayBizRecord(row, username))
      }
    } finally {
      try { db.close() } catch {}
    }
  }

  private parseAmountKeyword(raw: string): number | null {
    const text = String(raw || '').trim()
    if (!text) return null
    const normalized = text.replace(/[^\d.]/g, '')
    if (!normalized) return null
    const parsed = Number.parseFloat(normalized)
    return Number.isFinite(parsed) ? parsed : null
  }

  private extractAmountFromText(raw: string): number | null {
    const text = String(raw || '')
    const match = text.match(/(\d+(?:\.\d{1,2})?)\s*元?/)
    if (!match) return null
    const parsed = Number.parseFloat(match[1])
    return Number.isFinite(parsed) ? parsed : null
  }

  private isWechatPayAssistantSession(item: HiddenSessionSummaryItem): boolean {
    const text = `${item.username} ${item.displayName} ${item.summary}`.toLowerCase()
    return (
      text.includes('gh_f0a92aa7146c') ||
      text.includes('gh_3dfda90e39d6') ||
      text.includes('brandservicesessionholder') ||
      text.includes('微信收款助手') ||
      text.includes('微信支付') ||
      item.payLike
    )
  }

  private async handleWechatPayAssistant(url: URL, res: http.ServerResponse): Promise<void> {
    const amountParam = (url.searchParams.get('amount') || '').trim()
    const merchant = (url.searchParams.get('merchant') || url.searchParams.get('shop') || '').trim().toLowerCase()
    const limit = this.parseIntParam(url.searchParams.get('limit'), 100, 1, 10000)
    const targetAmount = this.parseAmountKeyword(amountParam)

    try {
      const collected = await this.collectHiddenSessionSummaries()
      if (!collected.success || !collected.summaries) {
        this.sendError(res, 500, collected.error || 'Failed to collect hidden session summaries')
        return
      }

      const officialContactsResult = await chatService.getContacts()
      const officialContacts = (officialContactsResult.success && officialContactsResult.contacts
        ? officialContactsResult.contacts.filter((contact) => (
          contact.type === 'official' &&
          ['gh_f0a92aa7146c', 'gh_3dfda90e39d6'].includes(contact.username)
        ))
        : []
      ).map((contact) => ({
        username: contact.username,
        displayName: contact.displayName,
        remark: contact.remark,
        nickname: contact.nickname,
        alias: contact.alias
      }))

      let records = collected.summaries
        .filter((item) => this.isWechatPayAssistantSession(item))
        .map((item) => {
          const summaryAmount = this.extractAmountFromText(item.summary)
          const merchantMatched = merchant
            ? item.matchText.includes(merchant)
            : null

          return {
            username: item.username,
            displayName: item.displayName,
            summary: item.summary,
            category: item.category,
            reason: item.reason,
            contactType: item.contactType,
            unreadCount: item.unreadCount,
            lastTimestamp: item.lastTimestamp,
            parsedAmount: summaryAmount,
            amountMatched: targetAmount === null
              ? null
              : summaryAmount !== null && Math.abs(summaryAmount - targetAmount) < 0.0001,
            merchantMatched,
            messageHistoryAvailable: false,
            source: 'hidden-session-summary'
          }
        })

      if (targetAmount !== null) {
        records = records.filter((item) => item.amountMatched === true)
      }

      if (merchant) {
        records = records.filter((item) => item.merchantMatched === true)
      }

      records.sort((a, b) => b.lastTimestamp - a.lastTimestamp)
      const limited = records.slice(0, limit)

      this.sendJson(res, {
        success: true,
        recoveredFrom: 'hidden-session-summary',
        amountFilter: targetAmount,
        merchantFilter: merchant || null,
        count: limited.length,
        officialAccounts: officialContacts,
        fullMessagesApi: '/api/v1/wechat-pay-assistant/messages',
        records: limited,
        notes: [
          'Current local data exposes hidden session summaries for WeChat Pay Assistant related sessions.',
          'Full biz-message recovery is now available through /api/v1/wechat-pay-assistant/messages when biz_message_0.db is readable.',
          'When merchantFilter is provided here, only summary-layer text is searched.'
        ]
      })
    } catch (error) {
      this.sendError(res, 500, String(error))
    }
  }

  private async handleWechatPayAssistantMessages(url: URL, res: http.ServerResponse): Promise<void> {
    const usernameParam = (url.searchParams.get('username') || '').trim()
    const scope = (url.searchParams.get('scope') || 'all').trim().toLowerCase()
    const amountParam = (url.searchParams.get('amount') || '').trim()
    const merchant = (url.searchParams.get('merchant') || url.searchParams.get('shop') || '').trim().toLowerCase()
    const keyword = (url.searchParams.get('keyword') || '').trim().toLowerCase()
    const limit = this.parseIntParam(url.searchParams.get('limit'), 100, 1, 1000)
    const includeRaw = this.parseBooleanParam(url, ['includeRaw', 'raw'], false)
    const targetAmount = this.parseAmountKeyword(amountParam)

    const usernames = usernameParam
      ? usernameParam.split(',').map((item) => item.trim()).filter(Boolean)
      : scope === 'assistant'
        ? ['gh_f0a92aa7146c']
        : scope === 'pay'
          ? ['gh_3dfda90e39d6']
          : ['gh_f0a92aa7146c', 'gh_3dfda90e39d6']

    if (usernames.length === 0) {
      this.sendError(res, 400, 'Missing username')
      return
    }

    try {
      const connectResult = await chatService.connect()
      if (!connectResult.success) {
        this.sendError(res, 500, connectResult.error || 'Failed to connect chat service')
        return
      }

      const perUserLimit = Math.max(limit, 200)
      const collected = await Promise.all(
        usernames.map((item) => this.queryWechatPayBizMessages(item, perUserLimit))
      )

      const failed = collected.find((item) => !item.success)
      if (failed) {
        this.sendError(res, 500, failed.error || 'Failed to query biz messages')
        return
      }

      let records = collected.flatMap((item: any) => item.records || [])
      if (targetAmount !== null) {
        records = records.filter((item) => item.amount !== null && Math.abs((item.amount || 0) - targetAmount) < 0.0001)
      }
      if (merchant) {
        records = records.filter((item) => `${item.title}\n${item.description}\n${item.digest}\n${item.rawXml}`.toLowerCase().includes(merchant))
      }
      if (keyword) {
        records = records.filter((item) => `${item.title}\n${item.description}\n${item.digest}\n${item.rawXml}`.toLowerCase().includes(keyword))
      }

      records.sort((a, b) => {
        if (b.createTime !== a.createTime) return b.createTime - a.createTime
        return b.localId - a.localId
      })

      const limited = records.slice(0, limit).map((item) => includeRaw ? item : ({
        username: item.username,
        localId: item.localId,
        serverId: item.serverId,
        localType: item.localType,
        createTime: item.createTime,
        publishedAt: item.publishedAt,
        sourceName: item.sourceName,
        title: item.title,
        description: item.description,
        digest: item.digest,
        amount: item.amount,
        url: item.url
      }))

      this.sendJson(res, {
        success: true,
        recoveredFrom: 'biz_message_0.db',
        scope,
        usernames,
        amountFilter: targetAmount,
        merchantFilter: merchant || null,
        keyword: keyword || null,
        includeRaw,
        count: limited.length,
        totalMatched: records.length,
        db: collected.map((item: any) => ({
          username: usernames[collected.indexOf(item)] || null,
          tableName: item.tableName,
          accountDir: item.accountDir,
          dbPath: item.dbPath
        })),
        records: limited
      })
    } catch (error) {
      this.sendError(res, 500, String(error))
    }
  }

  private async handleWechatPayAssistantVerify(
    req: http.IncomingMessage,
    url: URL,
    res: http.ServerResponse
  ): Promise<void> {
    const requestId = crypto.randomUUID()
    const method = String(req.method || 'GET').toUpperCase()
    if (method !== 'GET' && method !== 'POST') {
      this.sendPayApiError(res, requestId, 405, 'METHOD_NOT_ALLOWED', 'Method Not Allowed')
      return
    }

    let body: Record<string, any> = {}
    let rawBody = ''
    if (method === 'POST') {
      try {
        const parsed = await this.parseJsonBody(req)
        body = parsed.json
        rawBody = parsed.rawBody
      } catch (error) {
        this.sendPayApiError(res, requestId, 400, 'INVALID_ARGUMENT', String(error))
        return
      }
    }

    const authError = this.verifyPayApiAuthorization(req, url, rawBody)
    if (authError) {
      this.sendPayApiError(res, requestId, authError.statusCode, authError.code, authError.message)
      return
    }

    const amount = this.parseAmountKeyword(String(
      body.amount ??
      url.searchParams.get('amount') ??
      ''
    ))
    if (amount === null || amount <= 0) {
      this.sendPayApiError(res, requestId, 400, 'INVALID_ARGUMENT', 'Missing or invalid required parameter: amount')
      return
    }

    const windowMinutes = this.parseIntParam(
      this.firstDefinedString(
        body.windowMinutes,
        body.window,
        url.searchParams.get('windowMinutes'),
        url.searchParams.get('window')
      ),
      5,
      1,
      30 * 24 * 60
    )

    const merchant = this.cleanOptionalString(
      body.merchant,
      body.shop,
      url.searchParams.get('merchant'),
      url.searchParams.get('shop')
    )
    const keyword = this.cleanOptionalString(
      body.keyword,
      body.packageName,
      body.package_name,
      url.searchParams.get('keyword'),
      url.searchParams.get('packageName'),
      url.searchParams.get('package_name')
    )
    const payerName = this.cleanOptionalString(
      body.payerName,
      body.name,
      url.searchParams.get('payerName'),
      url.searchParams.get('name')
    )
    const payerPhone = this.cleanOptionalString(
      body.payerPhone,
      body.phone,
      url.searchParams.get('payerPhone'),
      url.searchParams.get('phone')
    )
    const orderNo = this.cleanOptionalString(
      body.orderNo,
      body.order_id,
      url.searchParams.get('orderNo'),
      url.searchParams.get('order_id')
    )
    const username = (
      this.cleanOptionalString(body.username, url.searchParams.get('username'))
      || 'gh_f0a92aa7146c'
    ).toLowerCase()

    const result = await wechatPayVerifierService.verifyPayment({
      amount,
      windowMinutes,
      merchant: merchant || undefined,
      keyword: keyword || undefined,
      payerName: payerName || undefined,
      payerPhone: payerPhone || undefined,
      orderNo: orderNo || undefined,
      username
    })

    const payload = {
      ...result,
      source: 'biz_message_0.db + local-cache',
      criteria: {
        amount,
        windowMinutes,
        merchant: merchant || null,
        keyword: keyword || null,
        payerName: payerName || null,
        payerPhone: payerPhone || null,
        orderNo: orderNo || null,
        username
      },
      record: result.record || null
    }

    if (!result.success) {
      const statusCode = result.message?.startsWith('Unsupported username') ? 400 : 500
      const code = result.message?.startsWith('Unsupported username') ? 'INVALID_ARGUMENT' : 'INTERNAL_ERROR'
      this.sendPayApiError(res, requestId, statusCode, code, result.message || 'Verification failed', payload)
      return
    }

    if (result.verified) {
      this.sendPayApiResponse(res, requestId, 200, 'OK', result.idempotent ? 'Payment already claimed by this order' : 'Payment verified', payload)
      return
    }

    if (result.matched) {
      this.sendPayApiResponse(res, requestId, 409, 'PAYMENT_ALREADY_CLAIMED', result.message || 'Matching payment was already claimed', payload)
      return
    }

    this.sendPayApiResponse(res, requestId, 200, 'PAYMENT_NOT_FOUND', result.message || 'No matching payment found', payload)
  }

  private async handleWechatPayAssistantEvents(
    req: http.IncomingMessage,
    url: URL,
    res: http.ServerResponse
  ): Promise<void> {
    const requestId = crypto.randomUUID()
    if (String(req.method || 'GET').toUpperCase() !== 'GET') {
      this.sendPayApiError(res, requestId, 405, 'METHOD_NOT_ALLOWED', 'Method Not Allowed')
      return
    }

    const authError = this.verifyPayApiAuthorization(req, url, '')
    if (authError) {
      this.sendPayApiError(res, requestId, authError.statusCode, authError.code, authError.message)
      return
    }

    const claimedRaw = url.searchParams.get('claimed')
    const claimed = claimedRaw === null
      ? undefined
      : ['1', 'true', 'yes', 'on'].includes(claimedRaw.trim().toLowerCase())

    const page = await wechatPayVerifierService.listReceiptEvents({
      cursor: url.searchParams.get('cursor') || undefined,
      limit: this.parseIntParam(url.searchParams.get('limit'), 50, 1, 200),
      username: (url.searchParams.get('username') || '').trim() || undefined,
      claimed
    })

    this.sendPayApiResponse(res, requestId, 200, 'OK', 'Events fetched', page)
  }

  private async handleWechatPayAssistantSync(
    req: http.IncomingMessage,
    url: URL,
    res: http.ServerResponse
  ): Promise<void> {
    const requestId = crypto.randomUUID()
    const method = String(req.method || 'GET').toUpperCase()
    if (method !== 'GET' && method !== 'POST') {
      this.sendPayApiError(res, requestId, 405, 'METHOD_NOT_ALLOWED', 'Method Not Allowed')
      return
    }

    let body: Record<string, any> = {}
    let rawBody = ''
    if (method === 'POST') {
      try {
        const parsed = await this.parseJsonBody(req)
        body = parsed.json
        rawBody = parsed.rawBody
      } catch (error) {
        this.sendPayApiError(res, requestId, 400, 'INVALID_ARGUMENT', String(error))
        return
      }
    }

    const authError = this.verifyPayApiAuthorization(req, url, rawBody)
    if (authError) {
      this.sendPayApiError(res, requestId, authError.statusCode, authError.code, authError.message)
      return
    }

    const force = this.parseBooleanLoose(
      body.force,
      body.full,
      url.searchParams.get('force'),
      url.searchParams.get('full')
    )

    const syncResult = await wechatPayVerifierService.syncNow(force)
    await wechatPayVerifierService.flushWebhookDeliveries().catch((error) => {
      console.error('[HttpService] flush webhook deliveries failed:', error)
    })

    if (!syncResult.success) {
      this.sendPayApiError(res, requestId, 500, 'INTERNAL_ERROR', syncResult.error || 'Sync failed', syncResult)
      return
    }

    this.sendPayApiResponse(res, requestId, 200, 'OK', 'Sync completed', {
      ...syncResult,
      force
    })
  }

  /**
   * 处理会话列表查询
   * GET /api/v1/sessions?keyword=xxx&limit=100
   */
  private async handleSessions(url: URL, res: http.ServerResponse): Promise<void> {
    const keyword = (url.searchParams.get('keyword') || '').trim()
    const limit = this.parseIntParam(url.searchParams.get('limit'), 100, 1, 10000)

    try {
      const sessions = await chatService.getSessions()
      if (!sessions.success || !sessions.sessions) {
        this.sendError(res, 500, sessions.error || 'Failed to get sessions')
        return
      }

      let filteredSessions = sessions.sessions
      if (keyword) {
        const lowerKeyword = keyword.toLowerCase()
        filteredSessions = sessions.sessions.filter(s => 
          s.username.toLowerCase().includes(lowerKeyword) ||
          (s.displayName && s.displayName.toLowerCase().includes(lowerKeyword))
        )
      }

      // 应用 limit
      const limitedSessions = filteredSessions.slice(0, limit)

      this.sendJson(res, {
        success: true,
        count: limitedSessions.length,
        sessions: limitedSessions.map(s => ({
          username: s.username,
          displayName: s.displayName,
          type: s.type,
          lastTimestamp: s.lastTimestamp,
          unreadCount: s.unreadCount
        }))
      })
    } catch (error) {
      this.sendError(res, 500, String(error))
    }
  }

  /**
   * 处理联系人查询
   * GET /api/v1/contacts?keyword=xxx&limit=100
   */
  private async handleContacts(url: URL, res: http.ServerResponse): Promise<void> {
    const keyword = (url.searchParams.get('keyword') || '').trim()
    const limit = this.parseIntParam(url.searchParams.get('limit'), 100, 1, 10000)

    try {
      const contacts = await chatService.getContacts()
      if (!contacts.success || !contacts.contacts) {
        this.sendError(res, 500, contacts.error || 'Failed to get contacts')
        return
      }

      let filteredContacts = contacts.contacts
      if (keyword) {
        const lowerKeyword = keyword.toLowerCase()
        filteredContacts = contacts.contacts.filter(c =>
          c.username.toLowerCase().includes(lowerKeyword) ||
          (c.nickname && c.nickname.toLowerCase().includes(lowerKeyword)) ||
          (c.remark && c.remark.toLowerCase().includes(lowerKeyword)) ||
          (c.displayName && c.displayName.toLowerCase().includes(lowerKeyword))
        )
      }

      const limited = filteredContacts.slice(0, limit)

      this.sendJson(res, {
        success: true,
        count: limited.length,
        contacts: limited
      })
    } catch (error) {
      this.sendError(res, 500, String(error))
    }
  }

  /**
   * 处理群成员查询
   * GET /api/v1/group-members?chatroomId=xxx@chatroom&includeMessageCounts=1&forceRefresh=0
   */
  private async handleGroupMembers(url: URL, res: http.ServerResponse): Promise<void> {
    const chatroomId = (url.searchParams.get('chatroomId') || url.searchParams.get('talker') || '').trim()
    const includeMessageCounts = this.parseBooleanParam(url, ['includeMessageCounts', 'withCounts'], false)
    const forceRefresh = this.parseBooleanParam(url, ['forceRefresh'], false)

    if (!chatroomId) {
      this.sendError(res, 400, 'Missing chatroomId')
      return
    }

    try {
      const result = await groupAnalyticsService.getGroupMembersPanelData(chatroomId, {
        forceRefresh,
        includeMessageCounts
      })
      if (!result.success || !result.data) {
        this.sendError(res, 500, result.error || 'Failed to get group members')
        return
      }

      this.sendJson(res, {
        success: true,
        chatroomId,
        count: result.data.length,
        fromCache: result.fromCache,
        updatedAt: result.updatedAt,
        members: result.data.map((member) => ({
          wxid: member.username,
          displayName: member.displayName,
          nickname: member.nickname || '',
          remark: member.remark || '',
          alias: member.alias || '',
          groupNickname: member.groupNickname || '',
          avatarUrl: member.avatarUrl,
          isOwner: Boolean(member.isOwner),
          isFriend: Boolean(member.isFriend),
          messageCount: Number.isFinite(member.messageCount) ? member.messageCount : 0
        }))
      })
    } catch (error) {
      this.sendError(res, 500, String(error))
    }
  }

  private getApiMediaExportPath(): string {
    return path.join(this.configService.getCacheBasePath(), 'api-media')
  }

  private sanitizeFileName(value: string, fallback: string): string {
    const safe = (value || '')
      .trim()
      .replace(/[<>:"/\\|?*\x00-\x1f]/g, '_')
      .replace(/\.+$/g, '')
    return safe || fallback
  }

  private ensureDir(dirPath: string): void {
    if (!fs.existsSync(dirPath)) {
      fs.mkdirSync(dirPath, { recursive: true })
    }
  }

  private detectImageExt(buffer: Buffer): string {
    if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return '.jpg'
    if (buffer.length >= 8 && buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return '.png'
    if (buffer.length >= 6) {
      const sig6 = buffer.subarray(0, 6).toString('ascii')
      if (sig6 === 'GIF87a' || sig6 === 'GIF89a') return '.gif'
    }
    if (buffer.length >= 12 && buffer.subarray(0, 4).toString('ascii') === 'RIFF' && buffer.subarray(8, 12).toString('ascii') === 'WEBP') return '.webp'
    if (buffer.length >= 2 && buffer[0] === 0x42 && buffer[1] === 0x4d) return '.bmp'
    return '.jpg'
  }

  private async exportMediaForMessages(
    messages: Message[],
    talker: string,
    options: ApiMediaOptions
  ): Promise<Map<number, ApiExportedMedia>> {
    const mediaMap = new Map<number, ApiExportedMedia>()
    if (!options.enabled || messages.length === 0) {
      return mediaMap
    }

    const sessionDir = path.join(this.getApiMediaExportPath(), this.sanitizeFileName(talker, 'session'))
    this.ensureDir(sessionDir)

    for (const msg of messages) {
      const exported = await this.exportMediaForMessage(msg, talker, sessionDir, options)
      if (exported) {
        mediaMap.set(msg.localId, exported)
      }
    }

    return mediaMap
  }

  private async exportMediaForMessage(
    msg: Message,
    talker: string,
    sessionDir: string,
    options: ApiMediaOptions
  ): Promise<ApiExportedMedia | null> {
    try {
      if (msg.localType === 3 && options.exportImages) {
        const result = await imageDecryptService.decryptImage({
          sessionId: talker,
          imageMd5: msg.imageMd5,
          imageDatName: msg.imageDatName,
          force: true
        })
        if (result.success && result.localPath) {
          let imagePath = result.localPath
          if (imagePath.startsWith('data:')) {
            const base64Match = imagePath.match(/^data:[^;]+;base64,(.+)$/)
            if (base64Match) {
              const imageBuffer = Buffer.from(base64Match[1], 'base64')
              const ext = this.detectImageExt(imageBuffer)
              const fileBase = this.sanitizeFileName(msg.imageMd5 || msg.imageDatName || `image_${msg.localId}`, `image_${msg.localId}`)
              const fileName = `${fileBase}${ext}`
              const targetDir = path.join(sessionDir, 'images')
              const fullPath = path.join(targetDir, fileName)
              this.ensureDir(targetDir)
              if (!fs.existsSync(fullPath)) {
                fs.writeFileSync(fullPath, imageBuffer)
              }
              const relativePath = `${this.sanitizeFileName(talker, 'session')}/images/${fileName}`
              return { kind: 'image', fileName, fullPath, relativePath }
            }
          } else if (fs.existsSync(imagePath)) {
            const imageBuffer = fs.readFileSync(imagePath)
            const ext = this.detectImageExt(imageBuffer)
            const fileBase = this.sanitizeFileName(msg.imageMd5 || msg.imageDatName || `image_${msg.localId}`, `image_${msg.localId}`)
            const fileName = `${fileBase}${ext}`
            const targetDir = path.join(sessionDir, 'images')
            const fullPath = path.join(targetDir, fileName)
            this.ensureDir(targetDir)
            if (!fs.existsSync(fullPath)) {
              fs.copyFileSync(imagePath, fullPath)
            }
            const relativePath = `${this.sanitizeFileName(talker, 'session')}/images/${fileName}`
            return { kind: 'image', fileName, fullPath, relativePath }
          }
        }
      }

      if (msg.localType === 34 && options.exportVoices) {
        const result = await chatService.getVoiceData(
          talker,
          String(msg.localId),
          msg.createTime || undefined,
          msg.serverId || undefined
        )
        if (result.success && result.data) {
          const fileName = `voice_${msg.localId}.wav`
          const targetDir = path.join(sessionDir, 'voices')
          const fullPath = path.join(targetDir, fileName)
          this.ensureDir(targetDir)
          if (!fs.existsSync(fullPath)) {
            fs.writeFileSync(fullPath, Buffer.from(result.data, 'base64'))
          }
          const relativePath = `${this.sanitizeFileName(talker, 'session')}/voices/${fileName}`
          return { kind: 'voice', fileName, fullPath, relativePath }
        }
      }

      if (msg.localType === 43 && options.exportVideos && msg.videoMd5) {
        const info = await videoService.getVideoInfo(msg.videoMd5)
        if (info.exists && info.videoUrl && fs.existsSync(info.videoUrl)) {
          const ext = path.extname(info.videoUrl) || '.mp4'
          const fileName = `${this.sanitizeFileName(msg.videoMd5, `video_${msg.localId}`)}${ext}`
          const targetDir = path.join(sessionDir, 'videos')
          const fullPath = path.join(targetDir, fileName)
          this.ensureDir(targetDir)
          if (!fs.existsSync(fullPath)) {
            fs.copyFileSync(info.videoUrl, fullPath)
          }
          const relativePath = `${this.sanitizeFileName(talker, 'session')}/videos/${fileName}`
          return { kind: 'video', fileName, fullPath, relativePath }
        }
      }

      if (msg.localType === 47 && options.exportEmojis && msg.emojiCdnUrl) {
        const result = await chatService.downloadEmoji(msg.emojiCdnUrl, msg.emojiMd5)
        if (result.success && result.localPath && fs.existsSync(result.localPath)) {
          const sourceExt = path.extname(result.localPath) || '.gif'
          const fileName = `${this.sanitizeFileName(msg.emojiMd5 || `emoji_${msg.localId}`, `emoji_${msg.localId}`)}${sourceExt}`
          const targetDir = path.join(sessionDir, 'emojis')
          const fullPath = path.join(targetDir, fileName)
          this.ensureDir(targetDir)
          if (!fs.existsSync(fullPath)) {
            fs.copyFileSync(result.localPath, fullPath)
          }
          const relativePath = `${this.sanitizeFileName(talker, 'session')}/emojis/${fileName}`
          return { kind: 'emoji', fileName, fullPath, relativePath }
        }
      }
    } catch (e) {
      console.warn('[HttpService] exportMediaForMessage failed:', e)
    }

    return null
  }

  private toApiMessage(msg: Message, media?: ApiExportedMedia): Record<string, any> {
    return {
      localId: msg.localId,
      serverId: msg.serverId,
      localType: msg.localType,
      createTime: msg.createTime,
      sortSeq: msg.sortSeq,
      isSend: msg.isSend,
      senderUsername: msg.senderUsername,
      content: this.getMessageContent(msg),
      rawContent: msg.rawContent,
      parsedContent: msg.parsedContent,
      mediaType: media?.kind,
      mediaFileName: media?.fileName,
      mediaUrl: media ? `http://127.0.0.1:${this.port}/api/v1/media/${media.relativePath}` : undefined,
      mediaLocalPath: media?.fullPath
    }
  }

  /**
   * 解析时间参数
   * 支持 YYYYMMDD 格式，返回秒级时间戳
   */
  private parseTimeParam(param: string | null, isEnd: boolean = false): number {
    if (!param) return 0

    // 纯数字且长度为 8，视为 YYYYMMDD
    if (/^\d{8}$/.test(param)) {
      const year = parseInt(param.slice(0, 4), 10)
      const month = parseInt(param.slice(4, 6), 10) - 1
      const day = parseInt(param.slice(6, 8), 10)
      const date = new Date(year, month, day)
      if (isEnd) {
        // 结束时间设为当天 23:59:59
        date.setHours(23, 59, 59, 999)
      }
      return Math.floor(date.getTime() / 1000)
    }

    // 纯数字，视为时间戳
    if (/^\d+$/.test(param)) {
      const ts = parseInt(param, 10)
      // 如果是毫秒级时间戳，转为秒级
      return ts > 10000000000 ? Math.floor(ts / 1000) : ts
    }

    return 0
  }

  private normalizeAccountId(value: string): string {
    const trimmed = String(value || '').trim()
    if (!trimmed) return trimmed

    if (trimmed.toLowerCase().startsWith('wxid_')) {
      const match = trimmed.match(/^(wxid_[^_]+)/i)
      if (match) return match[1]
      return trimmed
    }

    const suffixMatch = trimmed.match(/^(.+)_([a-zA-Z0-9]{4})$/)
    return suffixMatch ? suffixMatch[1] : trimmed
  }

  /**
   * 获取显示名称
   */
  private async getDisplayNames(usernames: string[]): Promise<Record<string, string>> {
    try {
      const result = await wcdbService.getDisplayNames(usernames)
      if (result.success && result.map) {
        return result.map
      }
    } catch (e) {
      console.error('[HttpService] Failed to get display names:', e)
    }
    // 返回空对象，调用方会使用 username 作为备用
    return {}
  }

  private async getAvatarUrls(usernames: string[]): Promise<Record<string, string>> {
    const lookupUsernames = Array.from(new Set(
      usernames.flatMap((username) => {
        const normalized = String(username || '').trim()
        if (!normalized) return []
        const cleaned = this.normalizeAccountId(normalized)
        return cleaned && cleaned !== normalized ? [normalized, cleaned] : [normalized]
      })
    ))

    if (lookupUsernames.length === 0) return {}

    try {
      const result = await wcdbService.getAvatarUrls(lookupUsernames)
      if (result.success && result.map) {
        const avatarMap: Record<string, string> = {}
        for (const [username, avatarUrl] of Object.entries(result.map)) {
          const normalizedUsername = String(username || '').trim()
          const normalizedAvatarUrl = String(avatarUrl || '').trim()
          if (!normalizedUsername || !normalizedAvatarUrl) continue

          avatarMap[normalizedUsername] = normalizedAvatarUrl
          avatarMap[normalizedUsername.toLowerCase()] = normalizedAvatarUrl

          const cleaned = this.normalizeAccountId(normalizedUsername)
          if (cleaned) {
            avatarMap[cleaned] = normalizedAvatarUrl
            avatarMap[cleaned.toLowerCase()] = normalizedAvatarUrl
          }
        }
        return avatarMap
      }
    } catch (e) {
      console.error('[HttpService] Failed to get avatar urls:', e)
    }

    return {}
  }

  private resolveAvatarUrl(avatarMap: Record<string, string>, candidates: Array<string | undefined | null>): string | undefined {
    for (const candidate of candidates) {
      const normalized = String(candidate || '').trim()
      if (!normalized) continue

      const cleaned = this.normalizeAccountId(normalized)
      const avatarUrl = avatarMap[normalized]
        || avatarMap[normalized.toLowerCase()]
        || avatarMap[cleaned]
        || avatarMap[cleaned.toLowerCase()]

      if (avatarUrl) return avatarUrl
    }

    return undefined
  }

  private lookupGroupNickname(groupNicknamesMap: Map<string, string>, sender: string): string {
    if (!sender) return ''
    const cleaned = this.normalizeAccountId(sender)
    return groupNicknamesMap.get(sender)
      || groupNicknamesMap.get(sender.toLowerCase())
      || groupNicknamesMap.get(cleaned)
      || groupNicknamesMap.get(cleaned.toLowerCase())
      || ''
  }

  private resolveChatLabSenderInfo(
    msg: Message,
    talkerId: string,
    talkerName: string,
    myWxid: string,
    isGroup: boolean,
    senderNames: Record<string, string>,
    groupNicknamesMap: Map<string, string>
  ): { sender: string; accountName: string; groupNickname?: string } {
    let sender = String(msg.senderUsername || '').trim()
    let usedUnknownPlaceholder = false
    const sameAsMe = sender && myWxid && sender.toLowerCase() === myWxid.toLowerCase()
    const isSelf = msg.isSend === 1 || sameAsMe

    if (!sender && isSelf && myWxid) {
      sender = myWxid
    }

    if (!sender) {
      if (msg.localType === 10000 || msg.localType === 266287972401) {
        sender = talkerId
      } else {
        sender = `unknown_sender_${msg.localId || msg.createTime || 0}`
        usedUnknownPlaceholder = true
      }
    }

    const groupNickname = isGroup ? this.lookupGroupNickname(groupNicknamesMap, sender) : ''
    const displayName = senderNames[sender] || groupNickname || (usedUnknownPlaceholder ? '' : sender)
    const accountName = isSelf ? '我' : (displayName || '未知发送者')

    return {
      sender,
      accountName,
      groupNickname: groupNickname || undefined
    }
  }

  /**
   * 转换为 ChatLab 格式
   */
  private async convertToChatLab(
    messages: Message[],
    talkerId: string,
    talkerName: string,
    mediaMap: Map<number, ApiExportedMedia> = new Map()
  ): Promise<ChatLabData> {
    const isGroup = talkerId.endsWith('@chatroom')
    const myWxid = this.configService.get('myWxid') || ''
    const normalizedMyWxid = this.normalizeAccountId(myWxid).toLowerCase()

    // 收集所有发送者
    const senderSet = new Set<string>()
    for (const msg of messages) {
      if (msg.senderUsername) {
        senderSet.add(msg.senderUsername)
      }
    }

    // 获取发送者显示名
    const senderNames = await this.getDisplayNames(Array.from(senderSet))

    // 获取群昵称（如果是群聊）
    let groupNicknamesMap = new Map<string, string>()
    if (isGroup) {
      try {
        const result = await wcdbService.getGroupNicknames(talkerId)
        if (result.success && result.nicknames) {
          groupNicknamesMap = new Map()
          for (const [memberIdRaw, nicknameRaw] of Object.entries(result.nicknames)) {
            const memberId = String(memberIdRaw || '').trim()
            const nickname = String(nicknameRaw || '').trim()
            if (!memberId || !nickname) continue

            groupNicknamesMap.set(memberId, nickname)
            groupNicknamesMap.set(memberId.toLowerCase(), nickname)

            const cleaned = this.normalizeAccountId(memberId)
            if (cleaned) {
              groupNicknamesMap.set(cleaned, nickname)
              groupNicknamesMap.set(cleaned.toLowerCase(), nickname)
            }
          }
        }
      } catch (e) {
        console.error('[HttpService] Failed to get group nicknames:', e)
      }
    }

    // 构建成员列表
    const memberMap = new Map<string, ChatLabMember>()
    for (const msg of messages) {
      const senderInfo = this.resolveChatLabSenderInfo(msg, talkerId, talkerName, myWxid, isGroup, senderNames, groupNicknamesMap)
      if (!memberMap.has(senderInfo.sender)) {
        memberMap.set(senderInfo.sender, {
          platformId: senderInfo.sender,
          accountName: senderInfo.accountName,
          groupNickname: senderInfo.groupNickname
        })
      }
    }

    const [memberAvatarMap, myAvatarResult, sessionAvatarInfo] = await Promise.all([
      this.getAvatarUrls(Array.from(memberMap.keys()).filter((sender) => !sender.startsWith('unknown_sender_'))),
      myWxid
        ? chatService.getMyAvatarUrl()
        : Promise.resolve<{ success: boolean; avatarUrl?: string }>({ success: true }),
      isGroup ? chatService.getContactAvatar(talkerId) : Promise.resolve(null)
    ])

    for (const [sender, member] of memberMap.entries()) {
      if (sender.startsWith('unknown_sender_')) continue

      const normalizedSender = this.normalizeAccountId(sender).toLowerCase()
      const isSelfMember = Boolean(normalizedMyWxid && normalizedSender && normalizedSender === normalizedMyWxid)
      const avatarUrl = (isSelfMember ? myAvatarResult.avatarUrl : undefined)
        || this.resolveAvatarUrl(memberAvatarMap, isSelfMember ? [sender, myWxid] : [sender])

      if (avatarUrl) {
        member.avatar = avatarUrl
      }
    }

    // 转换消息
    const chatLabMessages: ChatLabMessage[] = messages.map(msg => {
      const senderInfo = this.resolveChatLabSenderInfo(msg, talkerId, talkerName, myWxid, isGroup, senderNames, groupNicknamesMap)

      return {
        sender: senderInfo.sender,
        accountName: senderInfo.accountName,
        groupNickname: senderInfo.groupNickname,
        timestamp: msg.createTime,
        type: this.mapMessageType(msg.localType, msg),
        content: this.getMessageContent(msg),
        platformMessageId: msg.serverId ? String(msg.serverId) : undefined,
        mediaPath: mediaMap.get(msg.localId) ? `http://127.0.0.1:${this.port}/api/v1/media/${mediaMap.get(msg.localId)!.relativePath}` : undefined
      }
    })

    return {
      chatlab: {
        version: '0.0.2',
        exportedAt: Math.floor(Date.now() / 1000),
        generator: 'WeFlow'
      },
      meta: {
        name: talkerName,
        platform: 'wechat',
        type: isGroup ? 'group' : 'private',
        groupId: isGroup ? talkerId : undefined,
        groupAvatar: isGroup ? sessionAvatarInfo?.avatarUrl : undefined,
        ownerId: myWxid || undefined
      },
      members: Array.from(memberMap.values()),
      messages: chatLabMessages
    }
  }

  /**
   * 映射 WeChat 消息类型到 ChatLab 类型
   */
  private mapMessageType(localType: number, msg: Message): number {
    switch (localType) {
      case 1: // 文本
        return ChatLabType.TEXT
      case 3: // 图片
        return ChatLabType.IMAGE
      case 34: // 语音
        return ChatLabType.VOICE
      case 43: // 视频
        return ChatLabType.VIDEO
      case 47: // 动画表情
        return ChatLabType.EMOJI
      case 48: // 位置
        return ChatLabType.LOCATION
      case 42: // 名片
        return ChatLabType.CONTACT
      case 50: // 语音/视频通话
        return ChatLabType.CALL
      case 10000: // 系统消息
        return ChatLabType.SYSTEM
      case 49: // 复合消息
        return this.mapType49(msg)
      case 244813135921: // 引用消息
        return ChatLabType.REPLY
      case 266287972401: // 拍一拍
        return ChatLabType.POKE
      case 8594229559345: // 红包
        return ChatLabType.RED_PACKET
      case 8589934592049: // 转账
        return ChatLabType.TRANSFER
      default:
        return ChatLabType.OTHER
    }
  }

  /**
   * 映射 Type 49 子类型
   */
  private mapType49(msg: Message): number {
    const xmlType = msg.xmlType

    switch (xmlType) {
      case '5': // 链接
      case '49':
        return ChatLabType.LINK
      case '6': // 文件
        return ChatLabType.FILE
      case '19': // 聊天记录
        return ChatLabType.FORWARD
      case '33': // 小程序
      case '36':
        return ChatLabType.SHARE
      case '57': // 引用消息
        return ChatLabType.REPLY
      case '2000': // 转账
        return ChatLabType.TRANSFER
      case '2001': // 红包
        return ChatLabType.RED_PACKET
      default:
        return ChatLabType.OTHER
    }
  }

  /**
   * 获取消息内容
   */
  private getMessageContent(msg: Message): string | null {
    // 优先使用已解析的内容
    if (msg.parsedContent) {
      return msg.parsedContent
    }

    // 根据类型返回占位符
    switch (msg.localType) {
      case 1:
        return msg.rawContent || null
      case 3:
        return '[图片]'
      case 34:
        return '[语音]'
      case 43:
        return '[视频]'
      case 47:
        return '[表情]'
      case 42:
        return msg.cardNickname || '[名片]'
      case 48:
        return '[位置]'
      case 49:
        return msg.linkTitle || msg.fileName || '[消息]'
      default:
        return msg.rawContent || null
    }
  }

  /**
   * 发送 JSON 响应
   */
  private sendJson(res: http.ServerResponse, data: any, statusCode: number = 200): void {
    res.setHeader('Content-Type', 'application/json; charset=utf-8')
    res.writeHead(statusCode)
    res.end(JSON.stringify(data, null, 2))
  }

  private firstDefinedString(...values: unknown[]): string | null {
    for (const value of values) {
      if (value === null || value === undefined) {
        continue
      }
      return String(value)
    }
    return null
  }

  private cleanOptionalString(...values: unknown[]): string {
    for (const value of values) {
      if (value === null || value === undefined) {
        continue
      }
      const text = String(value).trim()
      if (text) {
        return text
      }
    }
    return ''
  }

  private parseBooleanLoose(...values: unknown[]): boolean {
    for (const value of values) {
      if (value === null || value === undefined) {
        continue
      }

      const normalized = String(value).trim().toLowerCase()
      if (['1', 'true', 'yes', 'on'].includes(normalized)) {
        return true
      }
      if (['0', 'false', 'no', 'off'].includes(normalized)) {
        return false
      }
    }
    return false
  }

  private getPayApiSecret(): string {
    return String(process.env.WEFLOW_PAY_API_SECRET || '').trim()
  }

  private verifyPayApiAuthorization(
    req: http.IncomingMessage,
    url: URL,
    rawBody: string
  ): { statusCode: number; code: string; message: string } | null {
    const secret = this.getPayApiSecret()
    if (!secret) {
      return null
    }

    const timestamp = String(req.headers['x-weflow-timestamp'] || '').trim()
    const nonce = String(req.headers['x-weflow-nonce'] || '').trim()
    const signature = String(req.headers['x-weflow-signature'] || '').trim().toLowerCase()
    if (!timestamp || !nonce || !signature) {
      return {
        statusCode: 401,
        code: 'UNAUTHORIZED',
        message: 'Missing required signature headers'
      }
    }

    const timestampSeconds = Number.parseInt(timestamp, 10)
    const nowSeconds = Math.floor(Date.now() / 1000)
    if (!Number.isFinite(timestampSeconds) || Math.abs(nowSeconds - timestampSeconds) > 300) {
      return {
        statusCode: 401,
        code: 'UNAUTHORIZED',
        message: 'Signature timestamp expired'
      }
    }

    this.prunePayApiNonceCache(nowSeconds)
    if (this.payApiNonceCache.has(nonce)) {
      return {
        statusCode: 409,
        code: 'NONCE_REPLAY',
        message: 'Nonce has already been used'
      }
    }

    const bodyHash = crypto.createHash('sha256').update(rawBody || '').digest('hex')
    const method = String(req.method || 'GET').toUpperCase()
    const canonical = [method, `${url.pathname}${url.search}`, timestamp, nonce, bodyHash].join('\n')
    const expectedSignature = crypto.createHmac('sha256', secret).update(canonical).digest('hex')

    if (!this.safeCompare(signature, expectedSignature)) {
      return {
        statusCode: 403,
        code: 'FORBIDDEN',
        message: 'Invalid signature'
      }
    }

    this.payApiNonceCache.set(nonce, nowSeconds + 600)
    return null
  }

  private prunePayApiNonceCache(nowSeconds: number): void {
    for (const [nonce, expiresAt] of this.payApiNonceCache.entries()) {
      if (expiresAt <= nowSeconds) {
        this.payApiNonceCache.delete(nonce)
      }
    }
  }

  private safeCompare(left: string, right: string): boolean {
    const leftBuffer = Buffer.from(left)
    const rightBuffer = Buffer.from(right)
    if (leftBuffer.length !== rightBuffer.length) {
      return false
    }
    return crypto.timingSafeEqual(leftBuffer, rightBuffer)
  }

  private sendPayApiResponse<T>(
    res: http.ServerResponse,
    requestId: string,
    statusCode: number,
    code: string,
    message: string,
    data: T | null
  ): void {
    const body: PayApiEnvelope<T> = {
      requestId,
      success: statusCode < 400,
      code,
      message,
      timestamp: Math.floor(Date.now() / 1000),
      data
    }
    this.sendJson(res, body, statusCode)
  }

  private sendPayApiError(
    res: http.ServerResponse,
    requestId: string,
    statusCode: number,
    code: string,
    message: string,
    data: any = null
  ): void {
    this.sendPayApiResponse(res, requestId, statusCode, code, message, data)
  }

  /**
   * 发送错误响应
   */
  private sendError(res: http.ServerResponse, code: number, message: string): void {
    res.setHeader('Content-Type', 'application/json; charset=utf-8')
    res.writeHead(code)
    res.end(JSON.stringify({ error: message }))
  }
}

export const httpService = new HttpService()

