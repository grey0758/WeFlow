import { app } from 'electron'
import { join } from 'path'
import { copyFileSync, existsSync, mkdirSync } from 'fs'
import os from 'os'

export type DllCompatDbKeyResult = {
  success: boolean
  key?: string
  wcdbKeys?: Record<string, string>
  error?: string
  logs?: string[]
  source?: 'dll'
}

type WxKeyDllCompatApi = {
  initHook: (pid: number) => boolean
  pollKeyData: (buffer: Buffer, bufferSize: number) => boolean
  getStatusMessage: (buffer: Buffer, bufferSize: number, outLevel: Buffer) => boolean
  cleanupHook: () => boolean
  getLastErrorMsg: (() => Buffer | string | null | undefined) | null
}

type KeyServiceDllCompatDeps = {
  ensureKernel32: () => boolean
  findWeChatPid: () => Promise<number | null>
  detectWeChatLoginRequired: (pid: number) => Promise<boolean>
  waitForWeChatWindowComponents: (pid: number, timeoutMs?: number) => Promise<boolean>
  normalizeWcdbKeys: (value: unknown) => Record<string, string> | undefined
}

export class KeyServiceDllCompat {
  private koffi: any = null
  private api: WxKeyDllCompatApi | null = null

  constructor(private readonly deps: KeyServiceDllCompatDeps) {}

  private getDllPath(): string {
    const isPackaged = typeof app !== 'undefined' && app ? app.isPackaged : process.env.NODE_ENV === 'production'
    const archDir = process.arch === 'arm64' ? 'arm64' : 'x64'
    const candidates: string[] = []

    if (process.env.WX_KEY_DLL_PATH) {
      candidates.push(process.env.WX_KEY_DLL_PATH)
    }

    if (isPackaged) {
      candidates.push(join(process.resourcesPath, 'resources', 'key', 'win32', archDir, 'wx_key.dll'))
      candidates.push(join(process.resourcesPath, 'resources', 'key', 'win32', 'x64', 'wx_key.dll'))
      candidates.push(join(process.resourcesPath, 'resources', 'key', 'win32', 'wx_key.dll'))
      candidates.push(join(process.resourcesPath, 'resources', 'wx_key.dll'))
      candidates.push(join(process.resourcesPath, 'wx_key.dll'))
    } else {
      const cwd = process.cwd()
      candidates.push(join(cwd, 'resources', 'key', 'win32', archDir, 'wx_key.dll'))
      candidates.push(join(cwd, 'resources', 'key', 'win32', 'x64', 'wx_key.dll'))
      candidates.push(join(cwd, 'resources', 'key', 'win32', 'wx_key.dll'))
      candidates.push(join(cwd, 'resources', 'wx_key.dll'))
      candidates.push(join(app.getAppPath(), 'resources', 'key', 'win32', archDir, 'wx_key.dll'))
      candidates.push(join(app.getAppPath(), 'resources', 'key', 'win32', 'x64', 'wx_key.dll'))
      candidates.push(join(app.getAppPath(), 'resources', 'key', 'win32', 'wx_key.dll'))
      candidates.push(join(app.getAppPath(), 'resources', 'wx_key.dll'))
    }

    for (const candidate of candidates) {
      if (existsSync(candidate)) return candidate
    }

    return candidates[0]
  }

  private localizeNetworkDll(originalPath: string): string {
    try {
      const tempDir = join(os.tmpdir(), 'weflow_dll_cache')
      if (!existsSync(tempDir)) {
        mkdirSync(tempDir, { recursive: true })
      }
      const localPath = join(tempDir, 'wx_key.dll')
      if (existsSync(localPath)) return localPath
      copyFileSync(originalPath, localPath)
      return localPath
    } catch (error) {
      console.error('DLL compatibility localization failed:', error)
      return originalPath
    }
  }

  private ensureLoaded(): boolean {
    if (this.api) return true

    let dllPath = ''
    try {
      this.koffi = require('koffi')
      dllPath = this.getDllPath()
      if (!dllPath || !existsSync(dllPath)) return false

      if (dllPath.startsWith('\\\\')) {
        dllPath = this.localizeNetworkDll(dllPath)
      }

      const lib = this.koffi.load(dllPath)
      this.api = {
        initHook: lib.func('bool InitializeHook(uint32 targetPid)'),
        pollKeyData: lib.func('bool PollKeyData(_Out_ char *keyBuffer, int bufferSize)'),
        getStatusMessage: lib.func('bool GetStatusMessage(_Out_ char *msgBuffer, int bufferSize, _Out_ int *outLevel)'),
        cleanupHook: lib.func('bool CleanupHook()'),
        getLastErrorMsg: lib.func('const char* GetLastErrorMsg()')
      }
      return true
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error)
      console.error(`DLL compatibility load failed\n  Path: ${dllPath}\n  Error: ${errorMsg}`)
      return false
    }
  }

  private decodeUtf8(buf: Buffer): string {
    const nullIdx = buf.indexOf(0)
    return buf.toString('utf8', 0, nullIdx > -1 ? nullIdx : undefined).trim()
  }

  private decodeCString(ptr: any): string {
    try {
      if (typeof ptr === 'string') return ptr
      return this.koffi.decode(ptr, 'char', -1)
    } catch {
      return ''
    }
  }

  private isHexKey(value: unknown): value is string {
    return typeof value === 'string' && /^[0-9a-fA-F]{64}$/.test(value.trim())
  }

  private parseDbKeyPayload(raw: string): DllCompatDbKeyResult | null {
    const trimmed = String(raw || '').trim()
    if (!trimmed) return null

    if (this.isHexKey(trimmed)) {
      return { success: true, key: trimmed.toLowerCase(), source: 'dll' }
    }

    let parsed: any = null
    try {
      parsed = JSON.parse(trimmed)
    } catch {
      return null
    }

    const directWcdbKeys = this.deps.normalizeWcdbKeys(parsed?.wcdb_keys ?? parsed?.wcdbKeys)
    if (directWcdbKeys) {
      return { success: true, wcdbKeys: directWcdbKeys, source: 'dll' }
    }

    if (this.isHexKey(parsed?.key)) {
      return { success: true, key: String(parsed.key).trim().toLowerCase(), source: 'dll' }
    }

    const accounts = Array.isArray(parsed?.accounts) ? parsed.accounts : []
    for (const account of accounts) {
      const wcdbKeys = this.deps.normalizeWcdbKeys(account?.wcdb_keys ?? account?.wcdbKeys)
      if (wcdbKeys) {
        return { success: true, wcdbKeys, source: 'dll' }
      }
      if (this.isHexKey(account?.key)) {
        return { success: true, key: String(account.key).trim().toLowerCase(), source: 'dll' }
      }
    }

    return null
  }

  async getDbKey(timeoutMs: number, onStatus?: (message: string, level: number) => void): Promise<DllCompatDbKeyResult> {
    if (!this.ensureLoaded()) return { success: false, error: 'wx_key.dll compatibility layer unavailable' }
    if (!this.deps.ensureKernel32()) return { success: false, error: 'Kernel32 init failed' }

    const pid = await this.deps.findWeChatPid()
    if (!pid) {
      return { success: false, error: '未找到微信进程，请先启动微信' }
    }

    onStatus?.(`DLL fallback: attaching to pid ${pid}`, 0)
    const loginRequiredBefore = await this.deps.detectWeChatLoginRequired(pid)
    const readyBefore = await this.deps.waitForWeChatWindowComponents(pid, 1500)

    const compat = this.api
    if (!compat) return { success: false, error: 'wx_key.dll compatibility layer unavailable' }

    const initOk = compat.initHook(pid)
    if (!initOk) {
      const dllError = compat.getLastErrorMsg ? this.decodeCString(compat.getLastErrorMsg()) : ''
      if (dllError.includes('0xC0000022') || dllError.includes('ACCESS_DENIED')) {
        return { success: false, error: '权限不足：无法访问微信进程，请尝试以管理员权限运行 WeFlow' }
      }
      return { success: false, error: dllError || '初始化微信取钥 Hook 失败' }
    }

    const logs: string[] = []
    const seenStatus = new Set<string>()
    const pushStatus = (message: string, level: number) => {
      const normalized = String(message || '').trim()
      if (!normalized) return
      const marker = `${level}:${normalized}`
      if (seenStatus.has(marker)) return
      seenStatus.add(marker)
      logs.push(normalized)
      onStatus?.(normalized, level)
    }

    try {
      const deadline = Date.now() + Math.max(timeoutMs, 5000)
      while (Date.now() < deadline) {
        if (compat.getStatusMessage) {
          for (let i = 0; i < 5; i++) {
            const statusBuffer = Buffer.alloc(4096)
            const levelBuffer = Buffer.alloc(4)
            const hasStatus = compat.getStatusMessage(statusBuffer, statusBuffer.length, levelBuffer)
            if (!hasStatus) break
            pushStatus(this.decodeUtf8(statusBuffer), levelBuffer.readInt32LE(0))
          }
        }

        if (compat.pollKeyData) {
          const keyBuffer = Buffer.alloc(65536)
          const ok = compat.pollKeyData(keyBuffer, keyBuffer.length)
          if (ok) {
            const parsed = this.parseDbKeyPayload(this.decodeUtf8(keyBuffer))
            if (parsed?.success) {
              return { ...parsed, logs, source: 'dll' }
            }
            return { success: false, error: 'wx_key.dll 返回了无法识别的密钥格式', logs }
          }
        }

        await new Promise((resolve) => setTimeout(resolve, 150))
      }
    } finally {
      try {
        compat.cleanupHook()
      } catch {}
    }

    const loginRequiredAfter = await this.deps.detectWeChatLoginRequired(pid)
    if (!loginRequiredBefore && !loginRequiredAfter && readyBefore) {
      return {
        success: false,
        error: '当前微信已处于登录后的运行态，DLL 取钥需要在登录过程中抓取。请退出并重新登录微信后再试。',
        logs
      }
    }

    if (loginRequiredBefore || loginRequiredAfter) {
      return {
        success: false,
        error: '微信尚未完成登录，请先完成登录后重试自动取钥。',
        logs
      }
    }

    return {
      success: false,
      error: '等待微信返回数据库密钥超时，请在微信登录过程中重试。',
      logs
    }
  }
}
