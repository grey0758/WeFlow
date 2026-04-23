import { app } from 'electron'
import * as crypto from 'crypto'
import * as fs from 'fs'
import * as http from 'http'
import * as https from 'https'
import * as path from 'path'
import * as fzstd from 'fzstd'
import { URL } from 'url'
import { ConfigService } from './config'
import { KeyService } from './keyService'
import { nativeSqlcipherService } from './nativeSqlcipherService'

type BetterSqlite3Module = typeof import('better-sqlite3')
type SqliteDatabase = import('better-sqlite3').Database
type SqliteRow = Record<string, unknown>

type SupportedWechatPayUsername = 'gh_f0a92aa7146c' | 'gh_3dfda90e39d6'
type WechatPayMessageKind =
  | 'receipt'
  | 'refund_initiated'
  | 'refund_success'
  | 'payment'
  | 'refund_received'
  | 'unknown'

export type WechatPayVerifyParams = {
  amount: number
  windowMinutes?: number
  payerName?: string
  payerPhone?: string
  merchant?: string
  keyword?: string
  orderNo?: string
  username?: string
}

export type WechatPayVerifyRecord = {
  username: string
  messageKey: string
  localId: number
  serverId: string
  kind: WechatPayMessageKind
  sourceName: string
  title: string
  description: string
  digest: string
  amount: number | null
  merchant: string
  payerName: string
  payerPhone: string
  payerRemark: string
  createTime: number
  publishedAt: number | null
  url: string
}

export type WechatPayVerifyResult = {
  success: boolean
  verified: boolean
  matched: boolean
  claimed: boolean
  idempotent: boolean
  message?: string
  matchedCount: number
  record?: WechatPayVerifyRecord
}

export type WechatPayReceiptEvent = {
  cursor: string
  eventId: string
  type: 'wechat.pay.receipt'
  occurredAt: number
  syncedAt: number
  record: WechatPayVerifyRecord
  claim: {
    claimed: boolean
    orderNo: string | null
    claimedAt: number | null
  }
}

export type WechatPayReceiptEventsPage = {
  success: boolean
  count: number
  nextCursor: string | null
  hasMore: boolean
  events: WechatPayReceiptEvent[]
}

type NormalizedWechatPayRecord = {
  username: SupportedWechatPayUsername
  messageKey: string
  localId: number
  serverId: string
  localType: number
  createTime: number
  publishedAt: number | null
  sourceName: string
  kind: WechatPayMessageKind
  title: string
  description: string
  digest: string
  amount: number | null
  merchant: string
  payerName: string
  payerPhone: string
  payerRemark: string
  url: string
  rawXml: string
  rawSourceXml: string
}

type SyncResult = {
  success: boolean
  synced: number
  skipped?: boolean
  error?: string
}

const SUPPORTED_USERNAMES: SupportedWechatPayUsername[] = ['gh_f0a92aa7146c', 'gh_3dfda90e39d6']
const DEFAULT_SYNC_INTERVAL_MS = 60_000
const DEFAULT_WINDOW_MINUTES = 5
const MAX_WINDOW_MINUTES = 30 * 24 * 60
const CACHE_PARSER_VERSION = '2026-04-22-verify-v1'

class WechatPayVerifierService {
  private readonly configService = ConfigService.getInstance()
  private cacheDb: SqliteDatabase | null = null
  private syncTimer: NodeJS.Timeout | null = null
  private syncPromise: Promise<SyncResult> | null = null
  private webhookPromise: Promise<void> | null = null
  private lastSourceVersion = ''

  async start(): Promise<void> {
    this.ensureCacheSchema()

    if (!this.syncTimer) {
      this.syncTimer = setInterval(() => {
        this.syncNow().catch((error) => {
          console.error('[WechatPayVerifierService] background sync failed:', error)
        })
      }, DEFAULT_SYNC_INTERVAL_MS)
      this.syncTimer.unref?.()
    }

    this.syncNow().catch((error) => {
      console.error('[WechatPayVerifierService] initial sync failed:', error)
    })
  }

  async stop(): Promise<void> {
    if (this.syncTimer) {
      clearInterval(this.syncTimer)
      this.syncTimer = null
    }

    if (this.cacheDb) {
      try {
        this.cacheDb.close()
      } catch {}
      this.cacheDb = null
    }
  }

  async syncNow(force = false): Promise<SyncResult> {
    if (this.syncPromise) {
      return this.syncPromise
    }

    this.syncPromise = this.doSyncNow(force).finally(() => {
      this.syncPromise = null
    })

    return this.syncPromise
  }

  async flushWebhookDeliveries(): Promise<void> {
    const webhookTarget = this.getWebhookTarget()
    if (webhookTarget) {
      this.backfillWebhookDeliveries(webhookTarget)
    }
    await this.processWebhookQueue()
  }

  async listReceiptEvents(params?: {
    cursor?: string
    limit?: number
    username?: string
    claimed?: boolean
  }): Promise<WechatPayReceiptEventsPage> {
    await this.syncNow()

    const db = this.getCacheDb()
    const cursor = Number.parseInt(String(params?.cursor || ''), 10)
    const limit = this.clampInteger(params?.limit, 50, 1, 200)
    const username = String(params?.username || '').trim().toLowerCase()
    const claimedFilter = typeof params?.claimed === 'boolean' ? params.claimed : null
    const effectiveCursor = Number.isFinite(cursor) && cursor > 0 ? cursor : 0
    const usernameFilter = username && SUPPORTED_USERNAMES.includes(username as SupportedWechatPayUsername)
      ? username
      : null

    const rows = db.prepare(`
      SELECT
        m.id,
        m.*,
        c.order_no AS claim_order_no,
        c.claimed_at AS claim_claimed_at
      FROM pay_messages m
      LEFT JOIN pay_message_claims c ON c.message_key = m.message_key
      WHERE m.kind = 'receipt'
        AND m.id > ?
        ${usernameFilter ? 'AND m.username = ?' : ''}
        ${claimedFilter === true ? 'AND c.order_no IS NOT NULL' : ''}
        ${claimedFilter === false ? 'AND c.order_no IS NULL' : ''}
      ORDER BY m.id ASC
      LIMIT ?
    `).all(
      ...(usernameFilter ? [effectiveCursor, usernameFilter, limit + 1] : [effectiveCursor, limit + 1])
    ) as SqliteRow[]

    const hasMore = rows.length > limit
    const slicedRows = hasMore ? rows.slice(0, limit) : rows
    const events = slicedRows.map((row) => this.mapRowToReceiptEvent(row))
    const nextCursor = events.length > 0 ? events[events.length - 1].cursor : null

    return {
      success: true,
      count: events.length,
      nextCursor,
      hasMore,
      events
    }
  }

  async verifyPayment(params: WechatPayVerifyParams): Promise<WechatPayVerifyResult> {
    const amount = Number(params.amount)
    if (!Number.isFinite(amount) || amount <= 0) {
      return this.buildFailedVerifyResult('Invalid amount')
    }

    const username = String(params.username || '').trim().toLowerCase()
    if (username && !SUPPORTED_USERNAMES.includes(username as SupportedWechatPayUsername)) {
      return this.buildFailedVerifyResult(`Unsupported username: ${username}`)
    }

    const syncResult = await this.syncNow()
    if (!syncResult.success) {
      return this.buildFailedVerifyResult(syncResult.error || 'Failed to sync payment messages')
    }

    const db = this.getCacheDb()
    const normalizedMerchant = this.normalizeText(params.merchant || '')
    const normalizedKeyword = this.normalizeText(params.keyword || '')
    const normalizedPayerName = this.normalizeText(params.payerName || '')
    const normalizedPayerPhone = this.normalizePhone(params.payerPhone || '')
    const normalizedOrderNo = String(params.orderNo || '').trim()
    const windowMinutes = this.clampInteger(
      params.windowMinutes,
      DEFAULT_WINDOW_MINUTES,
      1,
      MAX_WINDOW_MINUTES
    )
    const cutoffTime = Math.floor(Date.now() / 1000) - windowMinutes * 60
    const usernameFilter = username || null

    if (normalizedOrderNo) {
      const existingClaim = db.prepare(`
        SELECT m.*
        FROM pay_message_claims c
        JOIN pay_messages m ON m.message_key = c.message_key
        WHERE c.order_no = ?
        LIMIT 1
      `).get(normalizedOrderNo) as SqliteRow | undefined

      if (existingClaim) {
        return {
          success: true,
          verified: true,
          matched: true,
          claimed: true,
          idempotent: true,
          matchedCount: 1,
          record: this.mapRowToVerifyRecord(existingClaim)
        }
      }
    }

    const candidateRows = db.prepare(`
      SELECT *
      FROM pay_messages
      WHERE kind = 'receipt'
        AND create_time >= ?
        AND amount IS NOT NULL
        AND ABS(amount - ?) < 0.0001
        ${usernameFilter ? 'AND username = ?' : ''}
      ORDER BY create_time DESC, local_id DESC
      LIMIT 200
    `).all(
      ...(usernameFilter ? [cutoffTime, amount, usernameFilter] : [cutoffTime, amount])
    ) as SqliteRow[]

    const filteredRows = candidateRows.filter((row) => {
      if (normalizedMerchant) {
        const merchantHaystack = this.normalizeText([
          row.merchant,
          row.title,
          row.description,
          row.digest,
          row.raw_xml,
          row.raw_source_xml
        ].join('\n'))
        if (!merchantHaystack.includes(normalizedMerchant)) {
          return false
        }
      }

      if (normalizedKeyword) {
        const keywordHaystack = this.normalizeText([
          row.title,
          row.description,
          row.digest,
          row.raw_xml,
          row.raw_source_xml,
          row.payer_remark
        ].join('\n'))
        if (!keywordHaystack.includes(normalizedKeyword)) {
          return false
        }
      }

      if (normalizedPayerName) {
        const payerName = this.normalizeText(row.payer_name)
        if (!payerName || payerName !== normalizedPayerName) {
          return false
        }
      }

      if (normalizedPayerPhone) {
        const payerPhone = this.normalizePhone(row.payer_phone)
        if (!payerPhone || payerPhone !== normalizedPayerPhone) {
          return false
        }
      }

      return true
    })

    if (filteredRows.length === 0) {
      return {
        success: true,
        verified: false,
        matched: false,
        claimed: false,
        idempotent: false,
        matchedCount: 0,
        message: 'No matching payment message found in the requested time window'
      }
    }

    if (!normalizedOrderNo) {
      return {
        success: true,
        verified: true,
        matched: true,
        claimed: false,
        idempotent: false,
        matchedCount: filteredRows.length,
        record: this.mapRowToVerifyRecord(filteredRows[0])
      }
    }

    const claimByOrder = db.prepare(`
      SELECT m.*
      FROM pay_message_claims c
      JOIN pay_messages m ON m.message_key = c.message_key
      WHERE c.order_no = ?
      LIMIT 1
    `)
    const claimByMessage = db.prepare(`
      SELECT order_no AS orderNo
      FROM pay_message_claims
      WHERE message_key = ?
      LIMIT 1
    `)
    const claimInsert = db.prepare(`
      INSERT INTO pay_message_claims(order_no, message_key, username, claimed_at)
      VALUES (?, ?, ?, ?)
    `)

    const claimResult = db.transaction((rows: SqliteRow[]) => {
      const existingOrderClaim = claimByOrder.get(normalizedOrderNo) as SqliteRow | undefined
      if (existingOrderClaim) {
        return {
          type: 'idempotent' as const,
          row: existingOrderClaim
        }
      }

      for (const row of rows) {
        const messageKey = String(row.message_key || '')
        const existingMessageClaim = claimByMessage.get(messageKey) as { orderNo?: string } | undefined

        if (existingMessageClaim?.orderNo === normalizedOrderNo) {
          return {
            type: 'idempotent' as const,
            row
          }
        }

        if (existingMessageClaim) {
          continue
        }

        claimInsert.run(
          normalizedOrderNo,
          messageKey,
          String(row.username || ''),
          Math.floor(Date.now() / 1000)
        )

        return {
          type: 'claimed' as const,
          row
        }
      }

      return {
        type: 'exhausted' as const
      }
    })(filteredRows)

    if (claimResult.type === 'claimed') {
      return {
        success: true,
        verified: true,
        matched: true,
        claimed: true,
        idempotent: false,
        matchedCount: filteredRows.length,
        record: this.mapRowToVerifyRecord(claimResult.row)
      }
    }

    if (claimResult.type === 'idempotent') {
      return {
        success: true,
        verified: true,
        matched: true,
        claimed: true,
        idempotent: true,
        matchedCount: filteredRows.length,
        record: this.mapRowToVerifyRecord(claimResult.row)
      }
    }

    return {
      success: true,
      verified: false,
      matched: true,
      claimed: false,
      idempotent: false,
      matchedCount: filteredRows.length,
      message: 'Matching payment messages were found, but all matching records have already been claimed by other orders'
    }
  }

  private buildFailedVerifyResult(message: string): WechatPayVerifyResult {
    return {
      success: false,
      verified: false,
      matched: false,
      claimed: false,
      idempotent: false,
      matchedCount: 0,
      message
    }
  }

  private async doSyncNow(force = false): Promise<SyncResult> {
    try {
      const resolved = this.resolveBizMessageDbPath()
      if (!resolved.success || !resolved.dbPath) {
        return { success: false, synced: 0, error: resolved.error || 'biz_message_0.db not found' }
      }

      const sourceStat = fs.statSync(resolved.dbPath)
      const currentVersion = `${sourceStat.mtimeMs}:${sourceStat.size}`
      const parserVersionChanged = this.getMetaValue('parser_version') !== CACHE_PARSER_VERSION
      if (!force && !parserVersionChanged && currentVersion === this.lastSourceVersion) {
        return { success: true, synced: 0, skipped: true }
      }

      const keyResult = await this.ensureKeysLoaded()
      if (!keyResult.success || !keyResult.wcdbKeys) {
        return { success: false, synced: 0, error: keyResult.error || 'Failed to load WCDB keys' }
      }

      const dbStoragePath = path.dirname(path.dirname(resolved.dbPath))
      const decryptOutDir = this.getDecryptOutDir(resolved.accountDir || 'default')
      const decryptResult = await nativeSqlcipherService.decryptDbDir(
        keyResult.wcdbKeys,
        dbStoragePath,
        decryptOutDir
      )
      if (!decryptResult.success) {
        return { success: false, synced: 0, error: decryptResult.error || 'Failed to decrypt biz_message_0.db' }
      }

      const decryptedBizPath = path.join(decryptOutDir, 'message', 'de_biz_message_0.db')
      if (!fs.existsSync(decryptedBizPath)) {
        return { success: false, synced: 0, error: 'de_biz_message_0.db was not produced during decrypt' }
      }

      const bizDb = this.openSqliteDatabase(decryptedBizPath, { readonly: true, fileMustExist: true })
      let synced = 0
      const syncedReceiptMessageKeys: string[] = []

      try {
        const cacheDb = this.getCacheDb()
        const forceFullResync = force || parserVersionChanged
        const upsert = cacheDb.prepare(`
          INSERT INTO pay_messages (
            message_key, username, local_id, server_id, local_type, create_time, published_at,
            source_name, kind, title, description, digest, amount, merchant,
            payer_name, payer_phone, payer_remark, url, raw_xml, raw_source_xml, synced_at
          ) VALUES (
            @messageKey, @username, @localId, @serverId, @localType, @createTime, @publishedAt,
            @sourceName, @kind, @title, @description, @digest, @amount, @merchant,
            @payerName, @payerPhone, @payerRemark, @url, @rawXml, @rawSourceXml, @syncedAt
          )
          ON CONFLICT(message_key) DO UPDATE SET
            local_id = excluded.local_id,
            server_id = excluded.server_id,
            local_type = excluded.local_type,
            create_time = excluded.create_time,
            published_at = excluded.published_at,
            source_name = excluded.source_name,
            kind = excluded.kind,
            title = excluded.title,
            description = excluded.description,
            digest = excluded.digest,
            amount = excluded.amount,
            merchant = excluded.merchant,
            payer_name = excluded.payer_name,
            payer_phone = excluded.payer_phone,
            payer_remark = excluded.payer_remark,
            url = excluded.url,
            raw_xml = excluded.raw_xml,
            raw_source_xml = excluded.raw_source_xml,
            synced_at = excluded.synced_at
        `)

        const selectState = cacheDb.prepare(`
          SELECT create_time AS createTime, local_id AS localId
          FROM pay_messages
          WHERE username = ?
          ORDER BY create_time DESC, local_id DESC
          LIMIT 1
        `)

        for (const username of SUPPORTED_USERNAMES) {
          const tableName = `Msg_${crypto.createHash('md5').update(username).digest('hex')}`
          if (!this.sqliteTableExists(bizDb, tableName)) {
            continue
          }

          const state = selectState.get(username) as { createTime?: number; localId?: number } | undefined
          const maxCreateTime = forceFullResync ? 0 : Number(state?.createTime || 0)
          const maxLocalId = forceFullResync ? 0 : Number(state?.localId || 0)

          const rows = bizDb.prepare(`
            SELECT local_id, server_id, local_type, create_time, source, message_content
            FROM ${tableName}
            WHERE create_time > ? OR (create_time = ? AND local_id > ?)
            ORDER BY create_time ASC, local_id ASC
          `).all(maxCreateTime, maxCreateTime, maxLocalId) as SqliteRow[]

          for (const row of rows) {
            const record = this.buildNormalizedRecord(row, username)
            upsert.run({
              ...record,
              syncedAt: Math.floor(Date.now() / 1000)
            })
            synced += 1
            if (record.kind === 'receipt') {
              syncedReceiptMessageKeys.push(record.messageKey)
            }
          }
        }
      } finally {
        try {
          bizDb.close()
        } catch {}
      }

      this.setMetaValue('parser_version', CACHE_PARSER_VERSION)
      this.lastSourceVersion = currentVersion
      void this.enqueueAndProcessWebhooks(syncedReceiptMessageKeys).catch((error) => {
        console.error('[WechatPayVerifierService] webhook queue processing failed:', error)
      })
      return { success: true, synced }
    } catch (error) {
      return { success: false, synced: 0, error: String(error) }
    }
  }

  private getCacheDb(): SqliteDatabase {
    if (this.cacheDb) {
      return this.cacheDb
    }

    const dbPath = this.getCacheDbPath()
    fs.mkdirSync(path.dirname(dbPath), { recursive: true })

    this.cacheDb = this.openSqliteDatabase(dbPath)
    this.cacheDb.pragma('journal_mode = WAL')
    this.cacheDb.pragma('synchronous = NORMAL')
    return this.cacheDb
  }

  private openSqliteDatabase(
    filePath: string,
    options?: ConstructorParameters<BetterSqlite3Module>[1]
  ): SqliteDatabase {
    // better-sqlite3 is used lazily so the main process only loads it when needed.
    const BetterSqlite3 = require('better-sqlite3') as BetterSqlite3Module
    return new BetterSqlite3(filePath, options)
  }

  private sqliteTableExists(db: SqliteDatabase, tableName: string): boolean {
    const safeTableName = tableName.replace(/'/g, "''")
    const row = db.prepare(`
      SELECT name
      FROM sqlite_master
      WHERE type = 'table' AND name = '${safeTableName}'
      LIMIT 1
    `).get() as SqliteRow | undefined

    return Boolean(row?.name)
  }

  private getCacheDbPath(): string {
    return path.join(app.getPath('userData'), 'wechat-pay-verify.db')
  }

  private getDecryptOutDir(accountDir: string): string {
    return path.join(app.getPath('userData'), 'wechat-pay-sync-cache', accountDir)
  }

  private ensureCacheSchema(): void {
    const db = this.getCacheDb()
    db.exec(`
      CREATE TABLE IF NOT EXISTS pay_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_key TEXT NOT NULL UNIQUE,
        username TEXT NOT NULL,
        local_id INTEGER NOT NULL,
        server_id TEXT NOT NULL DEFAULT '',
        local_type INTEGER NOT NULL DEFAULT 0,
        create_time INTEGER NOT NULL DEFAULT 0,
        published_at INTEGER,
        source_name TEXT NOT NULL DEFAULT '',
        kind TEXT NOT NULL DEFAULT 'unknown',
        title TEXT NOT NULL DEFAULT '',
        description TEXT NOT NULL DEFAULT '',
        digest TEXT NOT NULL DEFAULT '',
        amount REAL,
        merchant TEXT NOT NULL DEFAULT '',
        payer_name TEXT NOT NULL DEFAULT '',
        payer_phone TEXT NOT NULL DEFAULT '',
        payer_remark TEXT NOT NULL DEFAULT '',
        url TEXT NOT NULL DEFAULT '',
        raw_xml TEXT NOT NULL DEFAULT '',
        raw_source_xml TEXT NOT NULL DEFAULT '',
        synced_at INTEGER NOT NULL DEFAULT 0
      );

      CREATE INDEX IF NOT EXISTS idx_pay_messages_lookup
      ON pay_messages(username, kind, create_time DESC, local_id DESC);

      CREATE INDEX IF NOT EXISTS idx_pay_messages_amount
      ON pay_messages(amount, create_time DESC, local_id DESC);

      CREATE TABLE IF NOT EXISTS pay_message_claims (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_no TEXT NOT NULL UNIQUE,
        message_key TEXT NOT NULL UNIQUE,
        username TEXT NOT NULL,
        claimed_at INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY(message_key) REFERENCES pay_messages(message_key)
      );

      CREATE TABLE IF NOT EXISTS pay_verify_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL DEFAULT ''
      );

      CREATE TABLE IF NOT EXISTS pay_webhook_deliveries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_key TEXT NOT NULL,
        webhook_target TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        attempts INTEGER NOT NULL DEFAULT 0,
        next_retry_at INTEGER NOT NULL DEFAULT 0,
        last_attempt_at INTEGER,
        last_success_at INTEGER,
        last_error TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL DEFAULT 0,
        updated_at INTEGER NOT NULL DEFAULT 0,
        UNIQUE(message_key, webhook_target),
        FOREIGN KEY(message_key) REFERENCES pay_messages(message_key)
      );

      CREATE INDEX IF NOT EXISTS idx_pay_webhook_deliveries_pending
      ON pay_webhook_deliveries(status, next_retry_at, id);
    `)
  }

  private getMetaValue(key: string): string {
    const row = this.getCacheDb().prepare(`
      SELECT value
      FROM pay_verify_meta
      WHERE key = ?
      LIMIT 1
    `).get(key) as { value?: string } | undefined

    return String(row?.value || '')
  }

  private setMetaValue(key: string, value: string): void {
    this.getCacheDb().prepare(`
      INSERT INTO pay_verify_meta(key, value)
      VALUES (?, ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value
    `).run(key, value)
  }

  private resolveBizMessageDbPath(): {
    success: boolean
    dbPath?: string
    accountDir?: string
    error?: string
  } {
    const dbRoot = String(this.configService.get('dbPath') || '').trim()
    const myWxid = String(this.configService.get('myWxid') || '').trim()

    if (!dbRoot || !myWxid) {
      return { success: false, error: 'Missing dbPath or myWxid in config' }
    }

    const candidates = [myWxid, this.cleanWxidDirName(myWxid)]
    for (const candidate of candidates) {
      if (!candidate) {
        continue
      }

      const directPath = path.join(dbRoot, candidate, 'db_storage', 'message', 'biz_message_0.db')
      if (fs.existsSync(directPath)) {
        return { success: true, dbPath: directPath, accountDir: candidate }
      }
    }

    try {
      const cleanedWxid = this.cleanWxidDirName(myWxid)
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

  private cleanWxidDirName(value: string): string {
    const trimmed = String(value || '').trim()
    if (!trimmed) {
      return ''
    }

    if (trimmed.toLowerCase().startsWith('wxid_')) {
      const match = trimmed.match(/^(wxid_[^_]+)/i)
      return match?.[1] || trimmed
    }

    const suffixMatch = trimmed.match(/^(.+)_([a-zA-Z0-9]{4})$/)
    return suffixMatch ? suffixMatch[1] : trimmed
  }

  private async ensureKeysLoaded(): Promise<{
    success: boolean
    wcdbKeys?: Record<string, string>
    error?: string
  }> {
    const cachedKeys = this.configService.get('wcdbKeys') as Record<string, string> | undefined
    if (cachedKeys && Object.keys(cachedKeys).length > 0) {
      return { success: true, wcdbKeys: cachedKeys }
    }

    const keyService = new KeyService()
    const result = await keyService.autoGetDbKey(30_000)
    if (!result.success || !result.wcdbKeys || Object.keys(result.wcdbKeys).length === 0) {
      return { success: false, error: result.error || 'Failed to get WCDB keys' }
    }

    this.configService.set('wcdbKeys', result.wcdbKeys)
    return { success: true, wcdbKeys: result.wcdbKeys }
  }

  private buildNormalizedRecord(row: SqliteRow, username: SupportedWechatPayUsername): NormalizedWechatPayRecord {
    const rawXml = this.decodeBizMessagePayload(row.message_content)
    const rawSourceXml = this.decodeBizMessagePayload(row.source)
    const title = this.extractXmlValue(rawXml, 'title')
    const description = this.extractXmlValue(rawXml, 'des')
    const digest = this.extractXmlValue(rawXml, 'digest')
    const url = this.extractXmlValue(rawXml, 'url')
    const sourceName = this.extractSourceName(rawXml)
    const publishedAt = Number.parseInt(this.extractXmlValue(rawXml, 'pub_time') || '0', 10) || null
    const mergedText = [title, description, digest, sourceName, rawXml, rawSourceXml].join('\n')
    const amount = this.extractAmountFromText(mergedText)
    const merchant = this.trimByMarkers(this.extractFirstMatch(mergedText, [
      /(?:\u6536\u6b3e\u5e97\u94fa|\u7ecf\u8425\u540d\u79f0|\u5546\u6237\u540d\u79f0|\u5546\u6237\u5168\u79f0)[\uff1a:]?\s*([^\n]*?)(?=\s*(?:\u6536\u6b3e\u8bf4\u660e|\u6536\u6b3e\u9879|\u4ed8\u6b3e\u65b9\u4fe1\u606f|\u4ed8\u6b3e\u5907\u6ce8|\u8bf4\u660e\u5df2\u5b58\u5165|$))/i
    ]), [
      '\u6536\u6b3e\u8bf4\u660e',
      '\u6536\u6b3e\u9879',
      '\u4ed8\u6b3e\u65b9\u4fe1\u606f',
      '\u4ed8\u6b3e\u5907\u6ce8',
      '\u8bf4\u660e\u5df2\u5b58\u5165'
    ])
    const payerName = this.extractFirstMatch(mergedText, [
      /(?:\u4ed8\u6b3e\u65b9\u4fe1\u606f\s*)?\u59d3\u540d[\uff1a:]?\s*([^\n;；]+)/i,
      /(?:\u4ed8\u6b3e\u65b9\u59d3\u540d|\u987e\u5ba2\u59d3\u540d)[\uff1a:]?\s*([^\n;；]+)/i
    ])
    const payerPhone = this.extractFirstMatch(mergedText, [
      /(?:\u7535\u8bdd|\u624b\u673a(?:\u53f7)?|\u8054\u7cfb\u65b9\u5f0f)[\uff1a:]?\s*([0-9*+\-\s]{6,})/i
    ])
    const payerRemark = this.trimByMarkers(this.extractFirstMatch(mergedText, [
      /(?:\u4ed8\u6b3e\u5907\u6ce8|\u5907\u6ce8)(?:\u8d26\u53f7)?[\uff1a:]?\s*([^\n]*?)(?=\s*(?:\u8bf4\u660e\u5df2\u5b58\u5165|$))/i
    ]), [
      '\u8bf4\u660e\u5df2\u5b58\u5165'
    ])
    const kind = this.detectMessageKind(username, title, description, digest, sourceName, rawXml)
    const localId = Number.parseInt(String(row.local_id || row.localId || '0'), 10) || 0
    const serverId = String(row.server_id || row.serverId || '')
    const messageKey = `${username}:${serverId || localId}`

    return {
      username,
      messageKey,
      localId,
      serverId,
      localType: Number.parseInt(String(row.local_type || row.localType || '0'), 10) || 0,
      createTime: Number.parseInt(String(row.create_time || row.createTime || '0'), 10) || 0,
      publishedAt,
      sourceName,
      kind,
      title,
      description,
      digest,
      amount,
      merchant,
      payerName,
      payerPhone,
      payerRemark,
      url,
      rawXml,
      rawSourceXml
    }
  }

  private decodeBizMessagePayload(raw: unknown): string {
    if (!raw) {
      return ''
    }

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
      data = Buffer.from(String(raw), 'utf8')
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

  private extractXmlValue(xml: string, tag: string): string {
    const patterns = [
      new RegExp(`<${tag}><!\\[CDATA\\[([\\s\\S]*?)\\]\\]><\\/${tag}>`, 'i'),
      new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, 'i')
    ]

    for (const pattern of patterns) {
      const match = xml.match(pattern)
      if (match?.[1]) {
        return this.cleanExtractedText(match[1])
      }
    }

    return ''
  }

  private extractSourceName(xml: string): string {
    const patterns = [
      /<category\b[^>]*>\s*<name><!\[CDATA\[([\s\S]*?)\]\]><\/name>/i,
      /<source>\s*<name><!\[CDATA\[([\s\S]*?)\]\]><\/name>/i,
      /<nickname><!\[CDATA\[([\s\S]*?)\]\]><\/nickname>/i
    ]

    for (const pattern of patterns) {
      const match = xml.match(pattern)
      if (match?.[1]) {
        return this.cleanExtractedText(match[1])
      }
    }

    return ''
  }

  private extractAmountFromText(raw: string): number | null {
    const text = String(raw || '').replace(/\u00a0/g, ' ')
    const patterns = [
      /(?:\u6536\u6b3e\u91d1\u989d|\u4ed8\u6b3e\u91d1\u989d|\u5230\u8d26\u91d1\u989d)[^\d]{0,8}([0-9]+(?:\.[0-9]{1,2})?)/i,
      /[\u00a5\uffe5]\s*([0-9]+(?:\.[0-9]{1,2})?)/,
      /([0-9]+(?:\.[0-9]{1,2})?)\s*\u5143/
    ]

    for (const pattern of patterns) {
      const match = text.match(pattern)
      if (!match?.[1]) {
        continue
      }

      const parsed = Number.parseFloat(match[1].trim())
      if (Number.isFinite(parsed)) {
        return parsed
      }
    }

    return null
  }

  private extractFirstMatch(text: string, patterns: RegExp[]): string {
    for (const pattern of patterns) {
      const match = text.match(pattern)
      if (match?.[1]) {
        return this.cleanExtractedText(match[1])
      }
    }

    return ''
  }

  private detectMessageKind(
    username: SupportedWechatPayUsername,
    title: string,
    description: string,
    digest: string,
    sourceName: string,
    rawXml: string
  ): WechatPayMessageKind {
    const haystack = this.normalizeText([title, description, digest, sourceName, rawXml].join('\n'))

    if (username === 'gh_f0a92aa7146c') {
      if (
        haystack.includes(this.normalizeText('\u6536\u6b3e\u5230\u8d26')) ||
        haystack.includes(this.normalizeText('\u6536\u6b3e\u91d1\u989d'))
      ) {
        return 'receipt'
      }

      if (haystack.includes(this.normalizeText('\u9000\u6b3e\u6210\u529f'))) {
        return 'refund_success'
      }

      if (
        haystack.includes(this.normalizeText('\u9000\u6b3e\u53d1\u8d77')) ||
        haystack.includes(this.normalizeText('\u53d1\u8d77\u9000\u6b3e'))
      ) {
        return 'refund_initiated'
      }
    }

    if (username === 'gh_3dfda90e39d6') {
      if (haystack.includes(this.normalizeText('\u9000\u6b3e\u5230\u8d26'))) {
        return 'refund_received'
      }

      if (
        haystack.includes(this.normalizeText('\u5df2\u652f\u4ed8')) ||
        haystack.includes(this.normalizeText('\u652f\u4ed8\u6210\u529f'))
      ) {
        return 'payment'
      }
    }

    return 'unknown'
  }

  private cleanExtractedText(value: unknown): string {
    return String(value || '')
      .replace(/<!\[CDATA\[|\]\]>/g, '')
      .replace(/\s+/g, ' ')
      .trim()
  }

  private trimByMarkers(value: string, markers: string[]): string {
    let output = this.cleanExtractedText(value)
    for (const marker of markers) {
      const index = output.indexOf(marker)
      if (index >= 0) {
        output = output.slice(0, index).trim()
      }
    }
    return output
  }

  private normalizeText(value: unknown): string {
    return String(value || '').trim().toLowerCase()
  }

  private normalizePhone(value: unknown): string {
    return String(value || '').replace(/\D/g, '')
  }

  private clampInteger(value: unknown, fallback: number, min: number, max: number): number {
    const parsed = Number.parseInt(String(value ?? ''), 10)
    if (!Number.isFinite(parsed)) {
      return fallback
    }

    return Math.max(min, Math.min(max, parsed))
  }

  private mapRowToVerifyRecord(row: SqliteRow): WechatPayVerifyRecord {
    return {
      username: String(row.username || ''),
      messageKey: String(row.message_key || row.messageKey || ''),
      localId: Number.parseInt(String(row.local_id || row.localId || '0'), 10) || 0,
      serverId: String(row.server_id || row.serverId || ''),
      kind: String(row.kind || 'unknown') as WechatPayMessageKind,
      sourceName: String(row.source_name || row.sourceName || ''),
      title: String(row.title || ''),
      description: String(row.description || ''),
      digest: String(row.digest || ''),
      amount: row.amount === null || row.amount === undefined ? null : Number(row.amount),
      merchant: String(row.merchant || ''),
      payerName: String(row.payer_name || row.payerName || ''),
      payerPhone: String(row.payer_phone || row.payerPhone || ''),
      payerRemark: String(row.payer_remark || row.payerRemark || ''),
      createTime: Number.parseInt(String(row.create_time || row.createTime || '0'), 10) || 0,
      publishedAt: row.published_at === null || row.published_at === undefined
        ? null
        : Number.parseInt(String(row.published_at), 10) || null,
      url: String(row.url || '')
    }
  }

  private mapRowToReceiptEvent(row: SqliteRow): WechatPayReceiptEvent {
    const cursor = String(row.id || '')
    return {
      cursor,
      eventId: `wechat-pay-receipt:${row.message_key || row.messageKey || cursor}`,
      type: 'wechat.pay.receipt',
      occurredAt: Number.parseInt(String(row.published_at || row.create_time || 0), 10) || 0,
      syncedAt: Number.parseInt(String(row.synced_at || 0), 10) || 0,
      record: this.mapRowToVerifyRecord(row),
      claim: {
        claimed: Boolean(row.claim_order_no),
        orderNo: row.claim_order_no ? String(row.claim_order_no) : null,
        claimedAt: row.claim_claimed_at === null || row.claim_claimed_at === undefined
          ? null
          : Number.parseInt(String(row.claim_claimed_at), 10) || null
      }
    }
  }

  private getWebhookTarget(): string {
    return String(
      process.env.WEFLOW_PAY_SYNC_URL ||
      process.env.WEFLOW_PAY_WEBHOOK_URL ||
      ''
    ).trim()
  }

  private getWebhookSecret(): string {
    return String(
      process.env.WEFLOW_PAY_SYNC_SECRET ||
      process.env.WEFLOW_PAY_WEBHOOK_SECRET ||
      process.env.WEFLOW_PAY_API_SECRET ||
      ''
    ).trim()
  }

  private async enqueueAndProcessWebhooks(messageKeys: string[]): Promise<void> {
    const webhookTarget = this.getWebhookTarget()
    if (!webhookTarget) {
      return
    }

    this.enqueueWebhookDeliveries(webhookTarget, messageKeys)
    this.backfillWebhookDeliveries(webhookTarget)
    await this.processWebhookQueue()
  }

  private enqueueWebhookDeliveries(webhookTarget: string, messageKeys: string[]): void {
    if (!webhookTarget || messageKeys.length === 0) {
      return
    }

    const db = this.getCacheDb()
    const insert = db.prepare(`
      INSERT OR IGNORE INTO pay_webhook_deliveries(
        message_key,
        webhook_target,
        status,
        attempts,
        next_retry_at,
        created_at,
        updated_at
      ) VALUES (?, ?, 'pending', 0, 0, ?, ?)
    `)
    const now = Math.floor(Date.now() / 1000)
    const runInsert = db.transaction((keys: string[]) => {
      for (const messageKey of keys) {
        insert.run(messageKey, webhookTarget, now, now)
      }
    })
    runInsert(Array.from(new Set(messageKeys)))
  }

  private backfillWebhookDeliveries(webhookTarget: string): void {
    if (!webhookTarget) {
      return
    }

    const now = Math.floor(Date.now() / 1000)
    this.getCacheDb().prepare(`
      INSERT OR IGNORE INTO pay_webhook_deliveries(
        message_key,
        webhook_target,
        status,
        attempts,
        next_retry_at,
        created_at,
        updated_at
      )
      SELECT m.message_key, ?, 'pending', 0, 0, ?, ?
      FROM pay_messages m
      WHERE m.kind = 'receipt'
    `).run(webhookTarget, now, now)
  }

  private async processWebhookQueue(): Promise<void> {
    if (this.webhookPromise) {
      return this.webhookPromise
    }

    this.webhookPromise = this.doProcessWebhookQueue().finally(() => {
      this.webhookPromise = null
    })

    return this.webhookPromise
  }

  private async doProcessWebhookQueue(): Promise<void> {
    const webhookTarget = this.getWebhookTarget()
    if (!webhookTarget) {
      return
    }

    const db = this.getCacheDb()
    const now = Math.floor(Date.now() / 1000)
    const rows = db.prepare(`
      SELECT
        d.id AS delivery_id,
        d.webhook_target,
        d.attempts,
        d.message_key,
        m.id,
        m.*,
        c.order_no AS claim_order_no,
        c.claimed_at AS claim_claimed_at
      FROM pay_webhook_deliveries d
      JOIN pay_messages m ON m.message_key = d.message_key
      LEFT JOIN pay_message_claims c ON c.message_key = m.message_key
      WHERE d.webhook_target = ?
        AND d.status != 'delivered'
        AND d.next_retry_at <= ?
      ORDER BY d.id ASC
      LIMIT 20
    `).all(webhookTarget, now) as SqliteRow[]

    if (rows.length === 0) {
      return
    }

    const markSuccess = db.prepare(`
      UPDATE pay_webhook_deliveries
      SET status = 'delivered',
          attempts = ?,
          last_attempt_at = ?,
          last_success_at = ?,
          next_retry_at = ?,
          last_error = '',
          updated_at = ?
      WHERE id = ?
    `)
    const markFailure = db.prepare(`
      UPDATE pay_webhook_deliveries
      SET status = 'pending',
          attempts = ?,
          last_attempt_at = ?,
          next_retry_at = ?,
          last_error = ?,
          updated_at = ?
      WHERE id = ?
    `)

    for (const row of rows) {
      const deliveryId = Number(row.delivery_id || 0)
      const attempts = Number(row.attempts || 0) + 1
      const attemptedAt = Math.floor(Date.now() / 1000)
      const event = this.mapRowToReceiptEvent(row)

      try {
        await this.postWebhookEvent(webhookTarget, event)
        markSuccess.run(
          attempts,
          attemptedAt,
          attemptedAt,
          attemptedAt,
          attemptedAt,
          deliveryId
        )
      } catch (error) {
        const retryDelaySeconds = Math.min(300, Math.max(15, 15 * Math.pow(2, Math.min(attempts - 1, 4))))
        markFailure.run(
          attempts,
          attemptedAt,
          attemptedAt + retryDelaySeconds,
          String(error),
          attemptedAt,
          deliveryId
        )
      }
    }

    const remaining = db.prepare(`
      SELECT COUNT(1) AS count
      FROM pay_webhook_deliveries
      WHERE webhook_target = ?
        AND status != 'delivered'
        AND next_retry_at <= ?
    `).get(webhookTarget, Math.floor(Date.now() / 1000)) as { count?: number } | undefined

    if (Number(remaining?.count || 0) > 0) {
      await this.doProcessWebhookQueue()
    }
  }

  private async postWebhookEvent(webhookTarget: string, event: WechatPayReceiptEvent): Promise<void> {
    const requestBody = JSON.stringify(event)
    const timestamp = String(Math.floor(Date.now() / 1000))
    const bodyHash = crypto.createHash('sha256').update(requestBody).digest('hex')
    const secret = this.getWebhookSecret()
    const signature = secret
      ? crypto.createHmac('sha256', secret).update(`${timestamp}\n${bodyHash}`).digest('hex')
      : ''

    const targetUrl = new URL(webhookTarget)
    const requestModule = targetUrl.protocol === 'https:' ? https : http

    await new Promise<void>((resolve, reject) => {
      const req = requestModule.request({
        protocol: targetUrl.protocol,
        hostname: targetUrl.hostname,
        port: targetUrl.port || undefined,
        path: `${targetUrl.pathname}${targetUrl.search}`,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(requestBody),
          'X-WeFlow-Event': event.type,
          'X-WeFlow-Delivery-Id': event.eventId,
          'X-WeFlow-Timestamp': timestamp,
          'X-WeFlow-Body-SHA256': bodyHash,
          ...(signature ? { 'X-WeFlow-Signature': signature } : {})
        }
      }, (res) => {
        const chunks: Buffer[] = []
        res.on('data', (chunk) => {
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))
        })
        res.on('end', () => {
          const statusCode = Number(res.statusCode || 0)
          if (statusCode >= 200 && statusCode < 300) {
            resolve()
            return
          }

          reject(new Error(`Webhook responded with status ${statusCode}: ${Buffer.concat(chunks).toString('utf8').slice(0, 500)}`))
        })
      })

      req.on('error', reject)
      req.write(requestBody)
      req.end()
    })
  }
}

export const wechatPayVerifierService = new WechatPayVerifierService()
