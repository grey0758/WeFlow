import { app } from 'electron'
import { join, dirname, basename } from 'path'
import { existsSync, copyFileSync, mkdirSync, readdirSync, statSync } from 'fs'
import { execFile, spawn } from 'child_process'
import { promisify } from 'util'
import os from 'os'
import crypto from 'crypto'
import { pyWxDumpService } from './pyWxDumpService'
import { dbPathService } from './dbPathService'

const execFileAsync = promisify(execFile)

type DbKeyResult = {
  success: boolean
  key?: string
  wcdbKeys?: Record<string, string>
  error?: string
  logs?: string[]
  source?: 'pywxdump' | 'native' | 'dll'
}
type ImageKeyResult = { success: boolean; xorKey?: number; aesKey?: string; verified?: boolean; error?: string }
type DbVerificationTarget = { name: string; path: string; saltHex: string; markers: string[] }
type WxKeyDllCompatApi = {
  initHook: (pid: number) => boolean
  pollKeyData: (buffer: Buffer, bufferSize: number) => boolean
  getStatusMessage: (buffer: Buffer, bufferSize: number, outLevel: Buffer) => boolean
  cleanupHook: () => boolean
  getLastErrorMsg: (() => Buffer | string | null | undefined) | null
}

export class KeyService {
  private readonly isMac = process.platform === 'darwin'
  private koffi: any = null
  private dllCompatApi: WxKeyDllCompatApi | null = null

  // Win32 APIs
  private kernel32: any = null
  private user32: any = null
  private advapi32: any = null

  // Kernel32
  private OpenProcess: any = null
  private CloseHandle: any = null
  private TerminateProcess: any = null
  private QueryFullProcessImageNameW: any = null

  // User32
  private EnumWindows: any = null
  private GetWindowTextW: any = null
  private GetWindowTextLengthW: any = null
  private GetClassNameW: any = null
  private GetWindowThreadProcessId: any = null
  private IsWindowVisible: any = null
  private EnumChildWindows: any = null
  private PostMessageW: any = null
  private WNDENUMPROC_PTR: any = null

  // Advapi32
  private RegOpenKeyExW: any = null
  private RegQueryValueExW: any = null
  private RegCloseKey: any = null

  // Constants
  private readonly PROCESS_ALL_ACCESS = 0x1F0FFF
  private readonly PROCESS_TERMINATE = 0x0001
  private readonly KEY_READ = 0x20019
  private readonly HKEY_LOCAL_MACHINE = 0x80000002
  private readonly HKEY_CURRENT_USER = 0x80000001
  private readonly ERROR_SUCCESS = 0
  private readonly WM_CLOSE = 0x0010

  // Optional wx_key.dll compatibility layer. The default DB/image flows do not depend on it.
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

    for (const path of candidates) {
      if (existsSync(path)) return path
    }

    return candidates[0]
  }

  private isNetworkPath(path: string): boolean {
    if (path.startsWith('\\\\')) return true
    return false
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
    } catch (e) {
      console.error('DLL 本地化失败:', e)
      return originalPath
    }
  }

  private ensureDllCompatLoaded(): boolean {
    if (this.dllCompatApi) return true

    let dllPath = ''
    try {
      this.koffi = require('koffi')
      dllPath = this.getDllPath()
      if (!existsSync(dllPath)) {
        return false
      }

      if (this.isNetworkPath(dllPath)) {
        dllPath = this.localizeNetworkDll(dllPath)
      }

      const lib = this.koffi.load(dllPath)
      this.dllCompatApi = {
        initHook: lib.func('bool InitializeHook(uint32 targetPid)'),
        pollKeyData: lib.func('bool PollKeyData(_Out_ char *keyBuffer, int bufferSize)'),
        getStatusMessage: lib.func('bool GetStatusMessage(_Out_ char *msgBuffer, int bufferSize, _Out_ int *outLevel)'),
        cleanupHook: lib.func('bool CleanupHook()'),
        getLastErrorMsg: lib.func('const char* GetLastErrorMsg()')
      }

      return true
    } catch (e) {
      const errorMsg = e instanceof Error ? e.message : String(e)
      console.error(`加载 wx_key.dll 失败\n  路径: ${dllPath}\n  错误: ${errorMsg}`)
      return false
    }
  }

  private ensureWin32(): boolean {
    return process.platform === 'win32'
  }

  private ensureKernel32(): boolean {
    if (this.kernel32) return true
    try {
      this.koffi = require('koffi')
      this.kernel32 = this.koffi.load('kernel32.dll')
      this.OpenProcess = this.kernel32.func('OpenProcess', 'void*', ['uint32', 'bool', 'uint32'])
      this.CloseHandle = this.kernel32.func('CloseHandle', 'bool', ['void*'])
      this.TerminateProcess = this.kernel32.func('TerminateProcess', 'bool', ['void*', 'uint32'])
      this.QueryFullProcessImageNameW = this.kernel32.func('QueryFullProcessImageNameW', 'bool', ['void*', 'uint32', this.koffi.out('uint16*'), this.koffi.out('uint32*')])

      return true
    } catch (e) {
      console.error('初始化 kernel32 失败:', e)
      return false
    }
  }

  private decodeUtf8(buf: Buffer): string {
    const nullIdx = buf.indexOf(0)
    return buf.toString('utf8', 0, nullIdx > -1 ? nullIdx : undefined).trim()
  }

  private ensureUser32(): boolean {
    if (this.user32) return true
    try {
      this.koffi = require('koffi')
      this.user32 = this.koffi.load('user32.dll')

      const WNDENUMPROC = this.koffi.proto('bool __stdcall (void *hWnd, intptr_t lParam)')
      this.WNDENUMPROC_PTR = this.koffi.pointer(WNDENUMPROC)

      this.EnumWindows = this.user32.func('EnumWindows', 'bool', [this.WNDENUMPROC_PTR, 'intptr_t'])
      this.EnumChildWindows = this.user32.func('EnumChildWindows', 'bool', ['void*', this.WNDENUMPROC_PTR, 'intptr_t'])
      this.PostMessageW = this.user32.func('PostMessageW', 'bool', ['void*', 'uint32', 'uintptr_t', 'intptr_t'])
      this.GetWindowTextW = this.user32.func('GetWindowTextW', 'int', ['void*', this.koffi.out('uint16*'), 'int'])
      this.GetWindowTextLengthW = this.user32.func('GetWindowTextLengthW', 'int', ['void*'])
      this.GetClassNameW = this.user32.func('GetClassNameW', 'int', ['void*', this.koffi.out('uint16*'), 'int'])
      this.GetWindowThreadProcessId = this.user32.func('GetWindowThreadProcessId', 'uint32', ['void*', this.koffi.out('uint32*')])
      this.IsWindowVisible = this.user32.func('IsWindowVisible', 'bool', ['void*'])

      return true
    } catch (e) {
      console.error('初始化 user32 失败:', e)
      return false
    }
  }

  private ensureAdvapi32(): boolean {
    if (this.advapi32) return true
    try {
      this.koffi = require('koffi')
      this.advapi32 = this.koffi.load('advapi32.dll')

      const HKEY = this.koffi.alias('HKEY', 'intptr_t')
      const HKEY_PTR = this.koffi.pointer(HKEY)

      this.RegOpenKeyExW = this.advapi32.func('RegOpenKeyExW', 'long', [HKEY, 'uint16*', 'uint32', 'uint32', this.koffi.out(HKEY_PTR)])
      this.RegQueryValueExW = this.advapi32.func('RegQueryValueExW', 'long', [HKEY, 'uint16*', 'uint32*', this.koffi.out('uint32*'), this.koffi.out('uint8*'), this.koffi.out('uint32*')])
      this.RegCloseKey = this.advapi32.func('RegCloseKey', 'long', [HKEY])

      return true
    } catch (e) {
      console.error('初始化 advapi32 失败:', e)
      return false
    }
  }

  private decodeCString(ptr: any): string {
    try {
      if (typeof ptr === 'string') return ptr
      return this.koffi.decode(ptr, 'char', -1)
    } catch {
      return ''
    }
  }

  // --- WeChat Process & Path Finding ---

  private readRegistryString(rootKey: number, subKey: string, valueName: string): string | null {
    if (!this.ensureAdvapi32()) return null
    const subKeyBuf = Buffer.from(subKey + '\0', 'ucs2')
    const valueNameBuf = valueName ? Buffer.from(valueName + '\0', 'ucs2') : null
    const phkResult = Buffer.alloc(8)

    if (this.RegOpenKeyExW(rootKey, subKeyBuf, 0, this.KEY_READ, phkResult) !== this.ERROR_SUCCESS) return null

    const hKey = this.koffi.decode(phkResult, 'uintptr_t')

    try {
      const lpcbData = Buffer.alloc(4)
      lpcbData.writeUInt32LE(0, 0)

      let ret = this.RegQueryValueExW(hKey, valueNameBuf, null, null, null, lpcbData)
      if (ret !== this.ERROR_SUCCESS) return null

      const size = lpcbData.readUInt32LE(0)
      if (size === 0) return null

      const dataBuf = Buffer.alloc(size)
      ret = this.RegQueryValueExW(hKey, valueNameBuf, null, null, dataBuf, lpcbData)
      if (ret !== this.ERROR_SUCCESS) return null

      let str = dataBuf.toString('ucs2')
      if (str.endsWith('\0')) str = str.slice(0, -1)
      return str
    } finally {
      this.RegCloseKey(hKey)
    }
  }

  private async getProcessExecutablePath(pid: number): Promise<string | null> {
    if (!this.ensureKernel32()) return null
    const hProcess = this.OpenProcess(0x1000, false, pid)
    if (!hProcess) return null

    try {
      const sizeBuf = Buffer.alloc(4)
      sizeBuf.writeUInt32LE(1024, 0)
      const pathBuf = Buffer.alloc(1024 * 2)

      const ret = this.QueryFullProcessImageNameW(hProcess, 0, pathBuf, sizeBuf)
      if (ret) {
        const len = sizeBuf.readUInt32LE(0)
        return pathBuf.toString('ucs2', 0, len * 2)
      }
      return null
    } catch (e) {
      console.error('获取进程路径失败:', e)
      return null
    } finally {
      this.CloseHandle(hProcess)
    }
  }

  private async findWeChatInstallPath(): Promise<string | null> {
    try {
      const pid = await this.findWeChatPid()
      if (pid) {
        const runPath = await this.getProcessExecutablePath(pid)
        if (runPath && existsSync(runPath)) return runPath
      }
    } catch (e) {
      console.error('尝试获取运行中微信路径失败:', e)
    }

    const uninstallKeys = [
      'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
      'SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
    ]
    const roots = [this.HKEY_LOCAL_MACHINE, this.HKEY_CURRENT_USER]
    const tencentKeys = [
      'Software\\Tencent\\WeChat',
      'Software\\WOW6432Node\\Tencent\\WeChat',
      'Software\\Tencent\\Weixin',
    ]

    for (const root of roots) {
      for (const key of tencentKeys) {
        const path = this.readRegistryString(root, key, 'InstallPath')
        if (path && existsSync(join(path, 'Weixin.exe'))) return join(path, 'Weixin.exe')
        if (path && existsSync(join(path, 'WeChat.exe'))) return join(path, 'WeChat.exe')
      }
    }

    for (const root of roots) {
      for (const parent of uninstallKeys) {
        const path = this.readRegistryString(root, parent + '\\WeChat', 'InstallLocation')
        if (path && existsSync(join(path, 'Weixin.exe'))) return join(path, 'Weixin.exe')
      }
    }

    const drives = ['C', 'D', 'E', 'F']
    const commonPaths = [
      'Program Files\\Tencent\\WeChat\\WeChat.exe',
      'Program Files (x86)\\Tencent\\WeChat\\WeChat.exe',
      'Program Files\\Tencent\\Weixin\\Weixin.exe',
      'Program Files (x86)\\Tencent\\Weixin\\Weixin.exe'
    ]

    for (const drive of drives) {
      for (const p of commonPaths) {
        const full = join(drive + ':\\', p)
        if (existsSync(full)) return full
      }
    }

    return null
  }

  private async findPidByImageName(imageName: string): Promise<number | null> {
    try {
      const { stdout } = await execFileAsync('tasklist', ['/FI', `IMAGENAME eq ${imageName}`, '/FO', 'CSV', '/NH'])
      const lines = stdout.split(/\r?\n/).map((line) => line.trim()).filter(Boolean)
      for (const line of lines) {
        if (line.startsWith('INFO:')) continue
        const parts = line.split('","').map((p) => p.replace(/^"|"$/g, ''))
        if (parts[0]?.toLowerCase() === imageName.toLowerCase()) {
          const pid = Number(parts[1])
          if (!Number.isNaN(pid)) return pid
        }
      }
      return null
    } catch (e) {
      return null
    }
  }

  private async findWeChatPid(): Promise<number | null> {
    const names = ['Weixin.exe', 'WeChat.exe']
    for (const name of names) {
      const pid = await this.findPidByImageName(name)
      if (pid) return pid
    }
    const fallbackPid = await this.waitForWeChatWindow(5000)
    return fallbackPid ?? null
  }

  private async waitForWeChatExit(timeoutMs = 8000): Promise<boolean> {
    const start = Date.now()
    while (Date.now() - start < timeoutMs) {
      const weixinPid = await this.findPidByImageName('Weixin.exe')
      const wechatPid = await this.findPidByImageName('WeChat.exe')
      if (!weixinPid && !wechatPid) return true
      await new Promise(r => setTimeout(r, 400))
    }
    return false
  }

  private async closeWeChatWindows(): Promise<boolean> {
    if (!this.ensureUser32()) return false
    let requested = false

    const enumWindowsCallback = this.koffi.register((hWnd: any, lParam: any) => {
      if (!this.IsWindowVisible(hWnd)) return true
      const title = this.getWindowTitle(hWnd)
      const className = this.getClassName(hWnd)
      const classLower = (className || '').toLowerCase()
      const isWeChatWindow = this.isWeChatWindowTitle(title) || classLower.includes('wechat') || classLower.includes('weixin')
      if (!isWeChatWindow) return true

      requested = true
      try {
        this.PostMessageW?.(hWnd, this.WM_CLOSE, 0, 0)
      } catch { }
      return true
    }, this.WNDENUMPROC_PTR)

    this.EnumWindows(enumWindowsCallback, 0)
    this.koffi.unregister(enumWindowsCallback)

    return requested
  }

  private async killWeChatProcesses(): Promise<boolean> {
    const requested = await this.closeWeChatWindows()
    if (requested) {
      const gracefulOk = await this.waitForWeChatExit(1500)
      if (gracefulOk) return true
    }

    try {
      await execFileAsync('taskkill', ['/F', '/T', '/IM', 'Weixin.exe'])
      await execFileAsync('taskkill', ['/F', '/T', '/IM', 'WeChat.exe'])
    } catch (e) { }

    return await this.waitForWeChatExit(5000)
  }

  // --- Window Detection ---

  private getWindowTitle(hWnd: any): string {
    const len = this.GetWindowTextLengthW(hWnd)
    if (len === 0) return ''
    const buf = Buffer.alloc((len + 1) * 2)
    this.GetWindowTextW(hWnd, buf, len + 1)
    return buf.toString('ucs2', 0, len * 2)
  }

  private getClassName(hWnd: any): string {
    const buf = Buffer.alloc(512)
    const len = this.GetClassNameW(hWnd, buf, 256)
    return buf.toString('ucs2', 0, len * 2)
  }

  private isWeChatWindowTitle(title: string): boolean {
    const normalized = title.trim()
    if (!normalized) return false
    const lower = normalized.toLowerCase()
    return normalized === '微信' || lower === 'wechat' || lower === 'weixin'
  }

  private async waitForWeChatWindow(timeoutMs = 25000): Promise<number | null> {
    if (!this.ensureUser32()) return null
    const startTime = Date.now()
    while (Date.now() - startTime < timeoutMs) {
      let foundPid: number | null = null

      const enumWindowsCallback = this.koffi.register((hWnd: any, lParam: any) => {
        if (!this.IsWindowVisible(hWnd)) return true
        const title = this.getWindowTitle(hWnd)
        if (!this.isWeChatWindowTitle(title)) return true

        const pidBuf = Buffer.alloc(4)
        this.GetWindowThreadProcessId(hWnd, pidBuf)
        const pid = pidBuf.readUInt32LE(0)
        if (pid) {
          foundPid = pid
          return false
        }
        return true
      }, this.WNDENUMPROC_PTR)

      this.EnumWindows(enumWindowsCallback, 0)
      this.koffi.unregister(enumWindowsCallback)

      if (foundPid) return foundPid
      await new Promise(r => setTimeout(r, 500))
    }
    return null
  }

  private collectChildWindowInfos(parent: any): Array<{ title: string; className: string }> {
    const children: Array<{ title: string; className: string }> = []
    const enumChildCallback = this.koffi.register((hChild: any, lp: any) => {
      const title = this.getWindowTitle(hChild).trim()
      const className = this.getClassName(hChild).trim()
      children.push({ title, className })
      return true
    }, this.WNDENUMPROC_PTR)
    this.EnumChildWindows(parent, enumChildCallback, 0)
    this.koffi.unregister(enumChildCallback)
    return children
  }

  private hasReadyComponents(children: Array<{ title: string; className: string }>): boolean {
    if (children.length === 0) return false

    const readyTexts = ['聊天', '登录', '账号']
    const readyClassMarkers = ['WeChat', 'Weixin', 'TXGuiFoundation', 'Qt5', 'ChatList', 'MainWnd', 'BrowserWnd', 'ListView']
    const readyChildCountThreshold = 14

    let classMatchCount = 0
    let titleMatchCount = 0
    let hasValidClassName = false

    for (const child of children) {
      const normalizedTitle = child.title.replace(/\s+/g, '')
      if (normalizedTitle) {
        if (readyTexts.some(marker => normalizedTitle.includes(marker))) return true
        titleMatchCount += 1
      }
      const className = child.className
      if (className) {
        if (readyClassMarkers.some(marker => className.includes(marker))) return true
        if (className.length > 5) {
          classMatchCount += 1
          hasValidClassName = true
        }
      }
    }

    if (classMatchCount >= 3 || titleMatchCount >= 2) return true
    if (children.length >= readyChildCountThreshold) return true
    if (hasValidClassName && children.length >= 5) return true
    return false
  }

  private isLoginRelatedText(value: string): boolean {
    const normalized = String(value || '').replace(/\s+/g, '').toLowerCase()
    if (!normalized) return false
    const keywords = [
      '登录',
      '扫码',
      '二维码',
      '请在手机上确认',
      '手机确认',
      '切换账号',
      'wechatlogin',
      'qrcode',
      'scan'
    ]
    return keywords.some((keyword) => normalized.includes(keyword))
  }

  private async detectWeChatLoginRequired(pid: number): Promise<boolean> {
    if (!this.ensureUser32()) return false
    let loginRequired = false

    const enumWindowsCallback = this.koffi.register((hWnd: any, _lParam: any) => {
      if (!this.IsWindowVisible(hWnd)) return true
      const title = this.getWindowTitle(hWnd)
      if (!this.isWeChatWindowTitle(title)) return true

      const pidBuf = Buffer.alloc(4)
      this.GetWindowThreadProcessId(hWnd, pidBuf)
      const windowPid = pidBuf.readUInt32LE(0)
      if (windowPid !== pid) return true

      if (this.isLoginRelatedText(title)) {
        loginRequired = true
        return false
      }

      const children = this.collectChildWindowInfos(hWnd)
      for (const child of children) {
        if (this.isLoginRelatedText(child.title) || this.isLoginRelatedText(child.className)) {
          loginRequired = true
          return false
        }
      }
      return true
    }, this.WNDENUMPROC_PTR)

    this.EnumWindows(enumWindowsCallback, 0)
    this.koffi.unregister(enumWindowsCallback)

    return loginRequired
  }

  private async waitForWeChatWindowComponents(pid: number, timeoutMs = 15000): Promise<boolean> {
    if (!this.ensureUser32()) return true
    const startTime = Date.now()
    while (Date.now() - startTime < timeoutMs) {
      let ready = false
      const enumWindowsCallback = this.koffi.register((hWnd: any, lParam: any) => {
        if (!this.IsWindowVisible(hWnd)) return true
        const title = this.getWindowTitle(hWnd)
        if (!this.isWeChatWindowTitle(title)) return true

        const pidBuf = Buffer.alloc(4)
        this.GetWindowThreadProcessId(hWnd, pidBuf)
        const windowPid = pidBuf.readUInt32LE(0)
        if (windowPid !== pid) return true

        const children = this.collectChildWindowInfos(hWnd)
        if (this.hasReadyComponents(children)) {
          ready = true
          return false
        }
        return true
      }, this.WNDENUMPROC_PTR)

      this.EnumWindows(enumWindowsCallback, 0)
      this.koffi.unregister(enumWindowsCallback)

      if (ready) return true
      await new Promise(r => setTimeout(r, 500))
    }
    return true
  }

  // --- DB Key Logic (Unchanged core flow) ---

  async autoGetDbKey(
      timeoutMs = 60_000,
      onStatus?: (message: string, level: number) => void
  ): Promise<DbKeyResult> {
    return this._autoGetDbKeyChain(timeoutMs, onStatus)
  }

  private isHexKey(value: unknown): value is string {
    return typeof value === 'string' && /^[0-9a-fA-F]{64}$/.test(value.trim())
  }

  private normalizeWcdbKeys(value: unknown): Record<string, string> | undefined {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined
    const result: Record<string, string> = {}
    for (const [salt, key] of Object.entries(value as Record<string, unknown>)) {
      const normalizedSalt = String(salt || '').trim().toLowerCase()
      const normalizedKey = String(key || '').trim().toLowerCase()
      if (!/^[0-9a-f]{32}$/.test(normalizedSalt)) continue
      if (!/^[0-9a-f]{64}$/.test(normalizedKey)) continue
      result[normalizedSalt] = normalizedKey
    }
    return Object.keys(result).length > 0 ? result : undefined
  }

  private parseDbKeyPayload(raw: string): DbKeyResult | null {
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

    const directWcdbKeys = this.normalizeWcdbKeys(parsed?.wcdb_keys ?? parsed?.wcdbKeys)
    if (directWcdbKeys) {
      return { success: true, wcdbKeys: directWcdbKeys, source: 'dll' }
    }

    if (this.isHexKey(parsed?.key)) {
      return { success: true, key: String(parsed.key).trim().toLowerCase(), source: 'dll' }
    }

    const accounts = Array.isArray(parsed?.accounts) ? parsed.accounts : []
    for (const account of accounts) {
      const wcdbKeys = this.normalizeWcdbKeys(account?.wcdb_keys ?? account?.wcdbKeys)
      if (wcdbKeys) {
        return { success: true, wcdbKeys, source: 'dll' }
      }
      if (this.isHexKey(account?.key)) {
        return { success: true, key: String(account.key).trim().toLowerCase(), source: 'dll' }
      }
    }

    return null
  }

  private verifyLegacyDbKeyHex(keyHex: string, dbPath: string): boolean {
    const verifier = this.createLegacyDbKeyVerifier(dbPath)
    return verifier ? verifier(keyHex) : false
  }

  private verifySqlcipher4RawKeyHex(keyHex: string, dbPath: string): boolean {
    const verifier = this.createSqlcipher4RawKeyVerifier(dbPath)
    return verifier ? verifier(keyHex) : false
  }

  private createBestDbKeyVerifier(dbPath: string): ((keyHex: string) => boolean) | null {
    return this.createSqlcipher4RawKeyVerifier(dbPath) ?? this.createLegacyDbKeyVerifier(dbPath)
  }

  private createLegacyDbKeyVerifier(dbPath: string): ((keyHex: string) => boolean) | null {
    try {
      if (!existsSync(dbPath)) return null
      const { readFileSync } = require('fs') as typeof import('fs')
      const fileBuffer = readFileSync(dbPath)
      if (fileBuffer.length < 4096) return null

      const salt = fileBuffer.subarray(0, 16)
      const firstPage = fileBuffer.subarray(16, 4096)
      const macSalt = Buffer.alloc(salt.length)
      for (let i = 0; i < salt.length; i++) macSalt[i] = salt[i] ^ 58

      return (keyHex: string): boolean => {
        try {
          if (!this.isHexKey(keyHex)) return false
          const password = Buffer.from(keyHex.trim(), 'hex')
          const derivedKey = crypto.pbkdf2Sync(password, salt, 64000, 32, 'sha1')
          const macKey = crypto.pbkdf2Sync(derivedKey, macSalt, 2, 32, 'sha1')
          const hashMac = crypto.createHmac('sha1', macKey)
          hashMac.update(firstPage.subarray(0, firstPage.length - 32))
          hashMac.update(Buffer.from([0x01, 0x00, 0x00, 0x00]))
          const digest = hashMac.digest()
          return digest.equals(firstPage.subarray(firstPage.length - 32, firstPage.length - 12))
        } catch {
          return false
        }
      }
    } catch {
      return null
    }
  }

  private createSqlcipher4RawKeyVerifier(dbPath: string): ((keyHex: string) => boolean) | null {
    try {
      if (!existsSync(dbPath)) return null
      const { readFileSync } = require('fs') as typeof import('fs')
      const fileBuffer = readFileSync(dbPath)
      if (fileBuffer.length < 4096) return null

      const salt = fileBuffer.subarray(0, 16)
      const firstPage = fileBuffer.subarray(16, 4096)
      if (salt.length < 16 || firstPage.length < 64) return null

      const macSalt = Buffer.alloc(salt.length)
      for (let i = 0; i < salt.length; i++) macSalt[i] = salt[i] ^ 0x3a
      const pageBody = firstPage.subarray(0, firstPage.length - 64)
      const pageMac = firstPage.subarray(firstPage.length - 64)
      const pageNumber = Buffer.from([0x01, 0x00, 0x00, 0x00])

      return (keyHex: string): boolean => {
        try {
          if (!this.isHexKey(keyHex)) return false
          const rawKey = Buffer.from(keyHex.trim(), 'hex')
          if (rawKey.length !== 32) return false
          const macKey = crypto.pbkdf2Sync(rawKey, macSalt, 2, 32, 'sha512')
          const digest = crypto.createHmac('sha512', macKey)
            .update(pageBody)
            .update(pageNumber)
            .digest()
          return digest.equals(pageMac)
        } catch {
          return false
        }
      }
    } catch {
      return null
    }
  }

  private collectDbMarkerTexts(fullPath: string, relativePath: string): string[] {
    const normalizedFullPath = fullPath.replace(/\//g, '\\')
    const ntPrefixedFullPath = `\\\\??\\\\${normalizedFullPath}`
    const markers = new Set<string>([
      normalizedFullPath,
      ntPrefixedFullPath,
      `${normalizedFullPath}.factory\\renew\\${basename(fullPath)}`,
      `${normalizedFullPath}.factory\\vacuum\\${basename(fullPath)}`,
      `${ntPrefixedFullPath}.factory\\renew\\${basename(fullPath)}`,
      `${ntPrefixedFullPath}.factory\\vacuum\\${basename(fullPath)}`,
      `db_storage\\${relativePath.replace(/\//g, '\\')}`,
      basename(fullPath)
    ])
    const normalizedRelativePath = relativePath.replace(/\//g, '\\')
    if (normalizedRelativePath) {
      markers.add(normalizedRelativePath)
    }
    return Array.from(markers).filter(Boolean)
  }

  private extractUtf16HexCandidates(buffer: Buffer): string[] {
    const matches = buffer.toString('latin1').match(/(?:[0-9a-fA-F]\x00){64}/g) ?? []
    const candidates = new Set<string>()
    for (const match of matches) {
      const candidate = match.replace(/\x00/g, '').toLowerCase()
      if (this.isHexKey(candidate)) {
        candidates.add(candidate)
      }
    }
    return Array.from(candidates)
  }

  private isLikelyProcessAddress(value: number): boolean {
    return Number.isFinite(value) && value >= 0x10000 && value <= 0x7fffffffffff
  }

  private collectReadableProcessRegions(
    VirtualQueryEx: any,
    hProcess: any,
    allowedProtectFlags: number,
    maxRegionSize: number
  ): Array<[number, number]> {
    const regions: Array<[number, number]> = []
    const MEM_COMMIT = 0x1000
    const PAGE_NOACCESS = 0x01
    const PAGE_GUARD = 0x100
    const MBI_SIZE = 48
    const mbi = Buffer.alloc(MBI_SIZE)
    let address = 0

    while (address < 0x7fffffffffff) {
      const ret = VirtualQueryEx(hProcess, address, mbi, MBI_SIZE)
      if (ret === 0) break

      const base = Number(mbi.readBigUInt64LE(0))
      const size = Number(mbi.readBigUInt64LE(24))
      const state = mbi.readUInt32LE(32)
      const protect = mbi.readUInt32LE(36)

      if (
        state === MEM_COMMIT &&
        protect !== PAGE_NOACCESS &&
        (protect & PAGE_GUARD) === 0 &&
        (protect & allowedProtectFlags) !== 0 &&
        size > 0 &&
        size <= maxRegionSize
      ) {
        regions.push([base, size])
      }

      const next = base + size
      if (next <= address) break
      address = next
    }

    return regions
  }

  private readProcessBuffer(
    ReadProcessMemory: any,
    hProcess: any,
    address: number,
    size: number
  ): Buffer | null {
    try {
      if (!this.isLikelyProcessAddress(address) || size <= 0) return null
      const buffer = Buffer.alloc(size)
      const bytesRead = Buffer.alloc(8)
      const ok = ReadProcessMemory(hProcess, address, buffer, size, bytesRead)
      if (!ok) return null
      const actualBytes = Number(bytesRead.readBigUInt64LE(0))
      if (actualBytes <= 0) return null
      return buffer.subarray(0, actualBytes)
    } catch {
      return null
    }
  }

  private findVerifiedCandidateInBuffer(
    buffer: Buffer,
    verifyKey: (candidate: string) => boolean,
    seenCandidates: Set<string>,
    options?: {
      rawStep?: number
      maxRawCandidates?: number
    }
  ): string | null {
    const asciiMatches = buffer.toString('latin1').match(/(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])/g) ?? []
    for (const match of asciiMatches) {
      const candidate = match.toLowerCase()
      if (seenCandidates.has(candidate)) continue
      seenCandidates.add(candidate)
      if (verifyKey(candidate)) return candidate
    }

    for (const candidate of this.extractUtf16HexCandidates(buffer)) {
      if (seenCandidates.has(candidate)) continue
      seenCandidates.add(candidate)
      if (verifyKey(candidate)) return candidate
    }

    const rawStep = Math.max(1, options?.rawStep ?? (buffer.length > 512 ? 8 : 1))
    let rawCount = 0
    for (let pos = 0; pos <= buffer.length - 32; pos += rawStep) {
      if (options?.maxRawCandidates && rawCount >= options.maxRawCandidates) break
      const candidate = buffer.subarray(pos, pos + 32).toString('hex')
      if (seenCandidates.has(candidate)) continue
      seenCandidates.add(candidate)
      rawCount++
      if (verifyKey(candidate)) return candidate
    }

    return null
  }

  private findVerifiedCandidateViaPointers(
    ReadProcessMemory: any,
    hProcess: any,
    window: Buffer,
    verifyKey: (candidate: string) => boolean,
    seenCandidates: Set<string>,
    seenPointers: Set<number>
  ): string | null {
    for (let offset = 0; offset <= window.length - 8; offset += 8) {
      const pointer = Number(window.readBigUInt64LE(offset))
      if (
        !this.isLikelyProcessAddress(pointer) ||
        this.isLikelyUtf16FragmentPointer(pointer) ||
        this.isLikelyModulePointer(pointer) ||
        seenPointers.has(pointer)
      ) {
        continue
      }
      seenPointers.add(pointer)

      const pointed = this.readProcessBuffer(ReadProcessMemory, hProcess, pointer, 160)
      if (!pointed || pointed.length < 32) continue

      const candidate = this.findVerifiedCandidateInBuffer(pointed, verifyKey, seenCandidates, {
        rawStep: 8,
        maxRawCandidates: 24
      })
      if (candidate) return candidate
    }

    return null
  }

  private isLikelyUtf16FragmentPointer(value: number): boolean {
    if (!Number.isFinite(value) || value <= 0 || value > 0x7fffffffffff) return false
    try {
      const bytes = Buffer.alloc(8)
      bytes.writeBigUInt64LE(BigInt(value))
      let asciiPairs = 0
      let zeroOddBytes = 0
      for (let index = 0; index < 6; index += 2) {
        const lo = bytes[index]
        const hi = bytes[index + 1]
        if (hi === 0) zeroOddBytes++
        if (hi === 0 && lo >= 0x20 && lo <= 0x7e) asciiPairs++
      }
      return asciiPairs >= 3 && zeroOddBytes >= 3
    } catch {
      return false
    }
  }

  private isLikelyModulePointer(value: number): boolean {
    return Number.isFinite(value) && value >= 0x7ff000000000 && value <= 0x7fffffffffff
  }

  private extractPointerValues(buffer: Buffer, limit = 64): number[] {
    const pointers: number[] = []
    const seen = new Set<number>()
    for (let offset = 0; offset <= buffer.length - 8; offset += 8) {
      const pointer = Number(buffer.readBigUInt64LE(offset))
      if (
        !this.isLikelyProcessAddress(pointer) ||
        this.isLikelyUtf16FragmentPointer(pointer) ||
        this.isLikelyModulePointer(pointer) ||
        seen.has(pointer)
      ) {
        continue
      }
      seen.add(pointer)
      pointers.push(pointer)
      if (pointers.length >= limit) break
    }
    return pointers
  }

  private formatProcessAddress(address: number): string {
    return `0x${address.toString(16)}`
  }

  private decodeUtf16FragmentValue(value: number): string {
    try {
      const bytes = Buffer.alloc(8)
      bytes.writeBigUInt64LE(BigInt(value))
      return bytes.toString('utf16le').replace(/\u0000+$/g, '')
    } catch {
      return ''
    }
  }

  private describeQwordValue(value: number): string {
    if (value === 0) return 'zero'
    if (this.isLikelyModulePointer(value)) return `module ${this.formatProcessAddress(value)}`
    if (this.isLikelyProcessAddress(value)) return `ptr ${this.formatProcessAddress(value)}`
    if (this.isLikelyUtf16FragmentPointer(value)) {
      const decoded = this.decodeUtf16FragmentValue(value)
      return decoded ? `utf16 "${decoded}"` : 'utf16-fragment'
    }
    return `raw ${this.formatProcessAddress(value)}`
  }

  private shouldTraceDetailedLayout(targetName: string, address: number): boolean {
    const exactMatches: Record<string, number[]> = {
      'contact.db': [
        0x25b539a5120, 0x25b539ad630, 0x25b539a80d0, 0x25b539acb60, 0x25b539acb90, 0x25b539ae2e0,
        0x25b539ad900, 0x25b539ad180, 0x25b539acbf0, 0x25b539acc20, 0x25b539ae760, 0x25b539adda0,
        0x25b539add70, 0x25b539ae340, 0x25b539ae190, 0x25b539ae730
      ],
      'sns.db': [0x25b5398ca30, 0x25b5398d210, 0x25b5398cd30, 0x25b539a4f10, 0x25b539a4b20, 0x25b5398d2d0, 0x25b5398d450, 0x25b539a59b0]
    }
    return (exactMatches[targetName] ?? []).includes(address)
  }

  private shouldTraceFocusedContactEntry(address: number): boolean {
    return [0x25b539ad630, 0x25b539a80d0, 0x25b539acb60, 0x25b539acb90, 0x25b539ae2e0].includes(address)
  }

  private shouldTraceFocusedContactOwner(address: number): boolean {
    return [0x25b539ad900, 0x25b539ad180, 0x25b539acbf0, 0x25b539acc20, 0x25b539ae760, 0x25b539adda0].includes(address)
  }

  private shouldCollectFocusedContactHub(address: number): boolean {
    return [0x25b539ad660, 0x25b539acbc0, 0x25b539add40, 0x25b539ae310, 0x25b539add70].includes(address)
  }

  private shouldTraceFocusedContactCore(address: number): boolean {
    return [0x25b539add70, 0x25b539ae340].includes(address)
  }

  private shouldTraceFocusedContactDeepCore(address: number): boolean {
    return [0x25b539ae190, 0x25b539ae730].includes(address)
  }

  private shouldTraceFocusedContactSingleCore(address: number): boolean {
    return address === 0x25b539ae370
  }

  private prioritizeFocusedContactSingleCoreChildren(children: number[]): number[] {
    const priority = [
      0x25b539ae160,
      0x25b539ae730,
      0x25b539ae190,
      0x25b539ac140,
      0x25b539abfc0,
      0x25b539ae820,
      0x25b539ad930,
      0x25b539adc90
    ]
    const order = new Map<number, number>(priority.map((address, index) => [address, index]))
    return [...children].sort((left, right) => {
      const leftRank = order.get(left) ?? Number.MAX_SAFE_INTEGER
      const rightRank = order.get(right) ?? Number.MAX_SAFE_INTEGER
      return leftRank - rightRank || left - right
    })
  }

  private getDetailedLayoutReadSize(targetName: string, address: number, fallbackSize: number): number {
    return this.shouldTraceDetailedLayout(targetName, address) ? Math.max(fallbackSize, 0x100) : fallbackSize
  }

  private traceDetailedLayout(
    targetName: string,
    stage: string,
    address: number,
    buffer: Buffer,
    onStatus?: (message: string, level: number) => void,
    force = false
  ) {
    if (!onStatus || (!force && !this.shouldTraceDetailedLayout(targetName, address))) return

    onStatus(`Native scan: [${targetName}] layout ${stage} ${this.formatProcessAddress(address)}`, 0)
    for (let offset = 0; offset <= Math.min(buffer.length - 8, 0xb8); offset += 8) {
      const value = Number(buffer.readBigUInt64LE(offset))
      onStatus(
        `Native scan: [${targetName}]   +0x${offset.toString(16).padStart(2, '0')} = ${this.describeQwordValue(value)}`,
        0
      )
    }
  }

  private collectFilteredChildPointers(buffer: Buffer, limit = 8): number[] {
    const pointers: number[] = []
    const seen = new Set<number>()
    for (let offset = 0; offset <= Math.min(buffer.length - 8, 0xb8); offset += 8) {
      const value = Number(buffer.readBigUInt64LE(offset))
      if (
        !this.isLikelyProcessAddress(value) ||
        this.isLikelyUtf16FragmentPointer(value) ||
        this.isLikelyModulePointer(value) ||
        seen.has(value)
      ) {
        continue
      }
      seen.add(value)
      pointers.push(value)
      if (pointers.length >= limit) break
    }
    return pointers
  }

  private summarizeNodeHead(buffer: Buffer): string {
    const summary: string[] = []
    for (let offset = 0; offset <= Math.min(buffer.length - 8, 0x38); offset += 8) {
      const value = Number(buffer.readBigUInt64LE(offset))
      summary.push(`+0x${offset.toString(16).padStart(2, '0')}=${this.describeQwordValue(value)}`)
    }
    return summary.join(' | ')
  }

  private appendContactHubGraph(
    graph: Map<number, Set<number>>,
    parent: number,
    children: number[]
  ) {
    if (!this.shouldCollectFocusedContactHub(parent) || children.length === 0) return
    const set = graph.get(parent) ?? new Set<number>()
    for (const child of children) {
      set.add(child)
    }
    graph.set(parent, set)
  }

  private computeSharedContactHubCandidates(
    graph: Map<number, Set<number>>
  ): Array<{ address: number; parents: number[] }> {
    const parentByChild = new Map<number, Set<number>>()
    for (const [parent, children] of graph.entries()) {
      for (const child of children) {
        const parents = parentByChild.get(child) ?? new Set<number>()
        parents.add(parent)
        parentByChild.set(child, parents)
      }
    }

    return Array.from(parentByChild.entries())
      .map(([address, parents]) => ({ address, parents: Array.from(parents).sort((a, b) => a - b) }))
      .filter((entry) => entry.parents.length >= 2)
      .sort((left, right) => right.parents.length - left.parents.length || left.address - right.address)
  }

  private collectCrossBackrefs(
    buffer: Buffer,
    targets: Set<number>
  ): number[] {
    const hits: number[] = []
    const seen = new Set<number>()
    for (const pointer of this.collectFilteredChildPointers(buffer, 12)) {
      if (!targets.has(pointer) || seen.has(pointer)) continue
      seen.add(pointer)
      hits.push(pointer)
    }
    return hits
  }

  private findVerifiedCandidateViaFocusedContactSingleCore(
    ReadProcessMemory: any,
    hProcess: any,
    coreAddress: number,
    coreChildren: number[],
    verifyKey: (candidate: string) => boolean,
    seenCandidates: Set<string>,
    onStatus?: (message: string, level: number) => void
  ): string | null {
    if (!this.shouldTraceFocusedContactSingleCore(coreAddress)) return null

    const queue: Array<{ address: number; depth: number; stage: string }> = [
      { address: coreAddress, depth: 0, stage: 'single-core' },
      ...this.prioritizeFocusedContactSingleCoreChildren(coreChildren).map((address) => ({
        address,
        depth: 1,
        stage: 'single-core-child'
      }))
    ]
    const visited = new Set<number>()
    const backlinkTargets = new Set<number>([coreAddress, ...coreChildren])

    while (queue.length > 0 && visited.size < 24) {
      const current = queue.shift()!
      if (!this.isLikelyProcessAddress(current.address) || visited.has(current.address)) continue
      visited.add(current.address)

      const readSize = current.depth === 0 ? 0x180 : 0x140
      const buffer = this.readProcessBuffer(ReadProcessMemory, hProcess, current.address, readSize)
      if (!buffer || buffer.length < 32) continue

      this.traceDetailedLayout('contact.db', current.stage, current.address, buffer, onStatus, current.depth <= 1)
      const directCandidate = this.findVerifiedCandidateInBuffer(buffer, verifyKey, seenCandidates, {
        rawStep: 1,
        maxRawCandidates: current.depth === 0 ? 256 : 192
      })
      if (directCandidate) {
        onStatus?.(`Native scan: [contact.db] focused single-core hit ${this.formatProcessAddress(current.address)}`, 1)
        return directCandidate
      }

      const childPointers = this.collectFilteredChildPointers(buffer, current.depth === 0 ? 12 : 8)
      const prioritizedChildren = current.depth === 0
        ? this.prioritizeFocusedContactSingleCoreChildren(childPointers)
        : childPointers

      if (current.depth <= 1 && prioritizedChildren.length > 0) {
        onStatus?.(
          `Native scan: [contact.db] ${current.stage} children ${this.formatProcessAddress(current.address)} -> ${prioritizedChildren.map((value) => this.formatProcessAddress(value)).join(', ')}`,
          0
        )
      }

      for (const child of prioritizedChildren) {
        const childBuffer = this.readProcessBuffer(ReadProcessMemory, hProcess, child, current.depth === 0 ? 0x120 : 0x100)
        if (!childBuffer || childBuffer.length < 32) continue

        if (current.depth <= 1) {
          onStatus?.(`Native scan: [contact.db] ${current.stage} child ${this.formatProcessAddress(child)} ${this.summarizeNodeHead(childBuffer)}`, 0)
          const backrefs = this.collectCrossBackrefs(childBuffer, backlinkTargets)
          if (backrefs.length > 0) {
            onStatus?.(
              `Native scan: [contact.db] ${current.stage} child backrefs ${this.formatProcessAddress(child)} -> ${backrefs.map((value) => this.formatProcessAddress(value)).join(', ')}`,
              0
            )
          }
        }

        const childCandidate = this.findVerifiedCandidateInBuffer(childBuffer, verifyKey, seenCandidates, {
          rawStep: 1,
          maxRawCandidates: 160
        })
        if (childCandidate) {
          onStatus?.(`Native scan: [contact.db] focused single-core child hit ${this.formatProcessAddress(child)}`, 1)
          return childCandidate
        }

        if (current.depth < 2 && !visited.has(child)) {
          queue.push({
            address: child,
            depth: current.depth + 1,
            stage: current.depth === 0 ? 'single-core-child' : 'single-core-grandchild'
          })
        }
      }
    }

    return null
  }

  private traceSharedContactHubCandidates(
    ReadProcessMemory: any,
    hProcess: any,
    graph: Map<number, Set<number>>,
    verifyKey: (candidate: string) => boolean,
    seenCandidates: Set<string>,
    onStatus?: (message: string, level: number) => void
  ): string | null {
    if (!onStatus || graph.size === 0) return null

    for (const [parent, children] of graph.entries()) {
      const preview = Array.from(children).slice(0, 6).map((value) => this.formatProcessAddress(value)).join(', ')
      onStatus(`Native scan: [contact.db] hub ${this.formatProcessAddress(parent)} -> ${preview}`, 0)
    }

    const sharedCandidates = this.computeSharedContactHubCandidates(graph)
    if (sharedCandidates.length === 0) {
      onStatus('Native scan: [contact.db] shared hub candidates none', 0)
      return null
    }

    const focusedCandidates = sharedCandidates.slice(0, 3)
    const preview = focusedCandidates
      .map((entry) => `${this.formatProcessAddress(entry.address)}<=${entry.parents.map((value) => this.formatProcessAddress(value)).join('/')}`)
      .join(', ')
    onStatus(`Native scan: [contact.db] shared hub candidates ${preview}`, 0)

    const backlinkTargets = new Set<number>([
      ...Array.from(graph.keys()),
      ...focusedCandidates.map((entry) => entry.address)
    ])
    const sharedNextLayer = new Map<number, Set<number>>()

    for (const entry of focusedCandidates) {
      const buffer = this.readProcessBuffer(ReadProcessMemory, hProcess, entry.address, 0x80)
      if (!buffer || buffer.length < 32) continue

      onStatus(`Native scan: [contact.db] shared candidate ${this.formatProcessAddress(entry.address)} ${this.summarizeNodeHead(buffer)}`, 0)
      const children = this.collectFilteredChildPointers(buffer, 6)
      if (children.length > 0) {
        onStatus(
          `Native scan: [contact.db] shared candidate children ${this.formatProcessAddress(entry.address)} -> ${children.map((value) => this.formatProcessAddress(value)).join(', ')}`,
          0
        )
      }

      for (const child of children) {
        const parents = sharedNextLayer.get(child) ?? new Set<number>()
        parents.add(entry.address)
        sharedNextLayer.set(child, parents)

        const childBuffer = this.readProcessBuffer(ReadProcessMemory, hProcess, child, 0x60)
        if (!childBuffer || childBuffer.length < 32) continue

        const backrefs = this.collectCrossBackrefs(childBuffer, backlinkTargets)
        if (backrefs.length > 0) {
          onStatus(
            `Native scan: [contact.db] shared child backrefs ${this.formatProcessAddress(child)} -> ${backrefs.map((value) => this.formatProcessAddress(value)).join(', ')}`,
            0
          )
        }
      }
    }

    const sharedNextLayerCandidates = Array.from(sharedNextLayer.entries())
      .map(([address, parents]) => ({ address, parents: Array.from(parents).sort((a, b) => a - b) }))
      .filter((entry) => entry.parents.length >= 2)
      .sort((left, right) => right.parents.length - left.parents.length || left.address - right.address)

      if (sharedNextLayerCandidates.length > 0) {
        const nextPreview = sharedNextLayerCandidates
          .slice(0, 8)
          .map((entry) => `${this.formatProcessAddress(entry.address)}<=${entry.parents.map((value) => this.formatProcessAddress(value)).join('/')}`)
          .join(', ')
      onStatus(`Native scan: [contact.db] shared next-layer candidates ${nextPreview}`, 0)

      const focusedCoreCandidates = sharedNextLayerCandidates.filter((entry) => this.shouldTraceFocusedContactCore(entry.address))
        if (focusedCoreCandidates.length > 0) {
          const coreBacklinkTargets = new Set<number>([
            ...Array.from(graph.keys()),
            ...focusedCandidates.map((entry) => entry.address),
            ...focusedCoreCandidates.map((entry) => entry.address)
          ])
          const processedDeepCore = new Set<number>()
          const deepCoreGraph = new Map<number, Set<number>>()

          for (const entry of focusedCoreCandidates) {
            const buffer = this.readProcessBuffer(ReadProcessMemory, hProcess, entry.address, 0x100)
            if (!buffer || buffer.length < 32) continue

          this.traceDetailedLayout('contact.db', 'core', entry.address, buffer, onStatus)
          const children = this.collectFilteredChildPointers(buffer, 8)
          if (children.length > 0) {
            onStatus(
              `Native scan: [contact.db] core children ${this.formatProcessAddress(entry.address)} -> ${children.map((value) => this.formatProcessAddress(value)).join(', ')}`,
              0
            )
          }

            for (const child of children) {
              const childBuffer = this.readProcessBuffer(ReadProcessMemory, hProcess, child, 0x60)
              if (!childBuffer || childBuffer.length < 32) continue

              onStatus(`Native scan: [contact.db] core child ${this.formatProcessAddress(child)} ${this.summarizeNodeHead(childBuffer)}`, 0)
              const backrefs = this.collectCrossBackrefs(childBuffer, coreBacklinkTargets)
              if (backrefs.length > 0) {
                onStatus(
                  `Native scan: [contact.db] core child backrefs ${this.formatProcessAddress(child)} -> ${backrefs.map((value) => this.formatProcessAddress(value)).join(', ')}`,
                  0
                )
              }

              if (this.shouldTraceFocusedContactDeepCore(child) && !processedDeepCore.has(child)) {
                processedDeepCore.add(child)

                const deepCoreBuffer = this.readProcessBuffer(ReadProcessMemory, hProcess, child, 0x100)
                if (!deepCoreBuffer || deepCoreBuffer.length < 32) continue

                this.traceDetailedLayout('contact.db', 'deep-core', child, deepCoreBuffer, onStatus)
                const deepChildren = this.collectFilteredChildPointers(deepCoreBuffer, 8)
                if (deepChildren.length > 0) {
                  onStatus(
                    `Native scan: [contact.db] deep core children ${this.formatProcessAddress(child)} -> ${deepChildren.map((value) => this.formatProcessAddress(value)).join(', ')}`,
                    0
                  )
                }
                deepCoreGraph.set(child, new Set<number>(deepChildren))

                const deepBacklinkTargets = new Set<number>([
                  ...Array.from(coreBacklinkTargets),
                  child
                ])

                for (const deepChild of deepChildren) {
                  const deepChildBuffer = this.readProcessBuffer(ReadProcessMemory, hProcess, deepChild, 0x60)
                  if (!deepChildBuffer || deepChildBuffer.length < 32) continue

                  onStatus(`Native scan: [contact.db] deep core child ${this.formatProcessAddress(deepChild)} ${this.summarizeNodeHead(deepChildBuffer)}`, 0)
                  const deepBackrefs = this.collectCrossBackrefs(deepChildBuffer, deepBacklinkTargets)
                  if (deepBackrefs.length > 0) {
                    onStatus(
                      `Native scan: [contact.db] deep core child backrefs ${this.formatProcessAddress(deepChild)} -> ${deepBackrefs.map((value) => this.formatProcessAddress(value)).join(', ')}`,
                      0
                    )
                  }
                }
              }
            }
          }

          const sharedDeepCoreCandidates = this.computeSharedContactHubCandidates(deepCoreGraph)
          if (sharedDeepCoreCandidates.length > 0) {
            const deepPreview = sharedDeepCoreCandidates
              .slice(0, 8)
              .map((entry) => `${this.formatProcessAddress(entry.address)}<=${entry.parents.map((value) => this.formatProcessAddress(value)).join('/')}`)
              .join(', ')
            onStatus(`Native scan: [contact.db] shared deep-core candidates ${deepPreview}`, 0)

            const deepSharedBacklinkTargets = new Set<number>([
              ...Array.from(coreBacklinkTargets),
              ...Array.from(deepCoreGraph.keys()),
              ...sharedDeepCoreCandidates.map((entry) => entry.address)
            ])

            for (const entry of sharedDeepCoreCandidates.slice(0, 4)) {
              const sharedBuffer = this.readProcessBuffer(ReadProcessMemory, hProcess, entry.address, 0x100)
              if (!sharedBuffer || sharedBuffer.length < 32) continue

              this.traceDetailedLayout('contact.db', 'deep-shared', entry.address, sharedBuffer, onStatus, true)
              const sharedChildren = this.collectFilteredChildPointers(sharedBuffer, 8)
              if (sharedChildren.length > 0) {
                onStatus(
                  `Native scan: [contact.db] deep shared children ${this.formatProcessAddress(entry.address)} -> ${sharedChildren.map((value) => this.formatProcessAddress(value)).join(', ')}`,
                  0
                )
              }

              for (const sharedChild of sharedChildren) {
                const sharedChildBuffer = this.readProcessBuffer(ReadProcessMemory, hProcess, sharedChild, 0x60)
                if (!sharedChildBuffer || sharedChildBuffer.length < 32) continue

                onStatus(`Native scan: [contact.db] deep shared child ${this.formatProcessAddress(sharedChild)} ${this.summarizeNodeHead(sharedChildBuffer)}`, 0)
                const sharedBackrefs = this.collectCrossBackrefs(sharedChildBuffer, deepSharedBacklinkTargets)
                if (sharedBackrefs.length > 0) {
                  onStatus(
                    `Native scan: [contact.db] deep shared child backrefs ${this.formatProcessAddress(sharedChild)} -> ${sharedBackrefs.map((value) => this.formatProcessAddress(value)).join(', ')}`,
                    0
                  )
                }
              }

              const focusedCandidate = this.findVerifiedCandidateViaFocusedContactSingleCore(
                ReadProcessMemory,
                hProcess,
                entry.address,
                sharedChildren,
                verifyKey,
                seenCandidates,
                onStatus
              )
              if (focusedCandidate) return focusedCandidate
            }
          }
        }
      }
    return null
  }

  private traceFocusedContactChildren(
    ReadProcessMemory: any,
    hProcess: any,
    address: number,
    buffer: Buffer,
    graph: Map<number, Set<number>> | null,
    onStatus?: (message: string, level: number) => void
  ) {
    if (!onStatus || !this.shouldTraceFocusedContactEntry(address)) return

    const childPointers = this.collectFilteredChildPointers(buffer, 8)
    const preview = childPointers.map((value) => this.formatProcessAddress(value)).join(', ')
    onStatus(`Native scan: [contact.db] focused children ${this.formatProcessAddress(address)} -> ${preview}`, 0)

    for (const child of childPointers.slice(0, 6)) {
      const childBuffer = this.readProcessBuffer(ReadProcessMemory, hProcess, child, 0x60)
      if (!childBuffer || childBuffer.length < 32) continue

      onStatus(`Native scan: [contact.db] child ${this.formatProcessAddress(child)} ${this.summarizeNodeHead(childBuffer)}`, 0)
      this.traceFocusedContactOwnerChildren(ReadProcessMemory, hProcess, child, childBuffer, graph, onStatus)
    }
  }

  private traceFocusedContactOwnerChildren(
    ReadProcessMemory: any,
    hProcess: any,
    address: number,
    buffer: Buffer,
    graph: Map<number, Set<number>> | null,
    onStatus?: (message: string, level: number) => void
  ) {
    if (!onStatus || !this.shouldTraceFocusedContactOwner(address)) return

    const childPointers = this.collectFilteredChildPointers(buffer, 8)
    const preview = childPointers.map((value) => this.formatProcessAddress(value)).join(', ')
    onStatus(`Native scan: [contact.db] owner children ${this.formatProcessAddress(address)} -> ${preview}`, 0)

    for (const child of childPointers.slice(0, 6)) {
      const childBuffer = this.readProcessBuffer(ReadProcessMemory, hProcess, child, 0x60)
      if (!childBuffer || childBuffer.length < 32) continue

      onStatus(`Native scan: [contact.db] owner child ${this.formatProcessAddress(child)} ${this.summarizeNodeHead(childBuffer)}`, 0)
      if (graph && this.shouldCollectFocusedContactHub(child)) {
        this.appendContactHubGraph(graph, child, this.collectFilteredChildPointers(childBuffer, 8))
      }
    }
  }

  private verifyCandidateFromSlice(
    buffer: Buffer,
    offset: number,
    verifyKey: (candidate: string) => boolean,
    seenCandidates: Set<string>
  ): string | null {
    if (offset < 0 || offset + 32 > buffer.length) return null
    const candidate = buffer.subarray(offset, offset + 32).toString('hex')
    if (seenCandidates.has(candidate)) return null
    seenCandidates.add(candidate)
    return verifyKey(candidate) ? candidate : null
  }

  private findVerifiedCandidateViaSiblingFields(
    ReadProcessMemory: any,
    hProcess: any,
    rootSeeds: number[],
    verifyKey: (candidate: string) => boolean,
    seenCandidates: Set<string>,
    targetName?: string,
    onStatus?: (message: string, level: number) => void
  ): string | null {
    const STRUCT_WINDOW_SIZE = 0x240
    const STRUCT_POINTER_LIMIT = 24
    const SECOND_HOP_POINTER_LIMIT = 12
    const focusedContactHubGraph = targetName === 'contact.db' ? new Map<number, Set<number>>() : null
    const baseCandidates = Array.from(new Set(
      rootSeeds.flatMap((seed) =>
        [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128]
          .map((delta) => seed - delta)
          .filter((addr) => this.isLikelyProcessAddress(addr))
      )
    )).slice(0, 40)
    const directOffsets = [
      0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48,
      0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80, 0x88,
      0x90, 0x98, 0xa0, 0xa8, 0xb0, 0xb8, 0xc0, 0xc8
    ]
    const pointedOffsets = [0, 8, 16, 24, 32, 40, 48, 56]
    const seenPointers = new Set<number>()
    let traceBudget = 18
    const trace = (stage: string, address: number, extra?: string) => {
      if (!targetName || !onStatus || traceBudget <= 0) return
      traceBudget--
      onStatus(`Native scan: [${targetName}] ${stage} ${this.formatProcessAddress(address)}${extra ? ` ${extra}` : ''}`, 0)
    }

    if (targetName && onStatus && baseCandidates.length > 0) {
      const preview = baseCandidates.slice(0, 6).map((value) => this.formatProcessAddress(value)).join(', ')
      onStatus(`Native scan: [${targetName}] structure seeds ${preview}${baseCandidates.length > 6 ? ' ...' : ''}`, 0)
    }

    for (const base of baseCandidates) {
      trace('base', base)
      const window = this.readProcessBuffer(ReadProcessMemory, hProcess, base, STRUCT_WINDOW_SIZE)
      if (!window || window.length < 64) continue
      this.traceDetailedLayout(targetName ?? '', 'base', base, window, onStatus)

      for (const offset of directOffsets) {
        const candidate = this.verifyCandidateFromSlice(window, offset, verifyKey, seenCandidates)
        if (candidate) return candidate
      }

      for (const pointer of this.extractPointerValues(window, STRUCT_POINTER_LIMIT)) {
        if (seenPointers.has(pointer)) continue
        seenPointers.add(pointer)
        trace('sibling', pointer)

        const pointed = this.readProcessBuffer(
          ReadProcessMemory,
          hProcess,
          pointer,
          this.getDetailedLayoutReadSize(targetName ?? '', pointer, 160)
        )
        if (!pointed || pointed.length < 32) continue
        this.traceDetailedLayout(targetName ?? '', 'sibling', pointer, pointed, onStatus)

        for (const offset of pointedOffsets) {
          const candidate = this.verifyCandidateFromSlice(pointed, offset, verifyKey, seenCandidates)
          if (candidate) return candidate
        }

        const pointedCandidate = this.findVerifiedCandidateInBuffer(pointed, verifyKey, seenCandidates, {
          rawStep: 8,
          maxRawCandidates: 12
        })
        if (pointedCandidate) return pointedCandidate

        for (const secondHopPointer of this.extractPointerValues(pointed, SECOND_HOP_POINTER_LIMIT)) {
          if (seenPointers.has(secondHopPointer)) continue
          seenPointers.add(secondHopPointer)
          trace('second-hop', secondHopPointer, `via ${this.formatProcessAddress(pointer)}`)

          const secondHop = this.readProcessBuffer(
            ReadProcessMemory,
            hProcess,
            secondHopPointer,
            this.getDetailedLayoutReadSize(targetName ?? '', secondHopPointer, 96)
          )
          if (!secondHop || secondHop.length < 32) continue
          this.traceDetailedLayout(targetName ?? '', 'second-hop', secondHopPointer, secondHop, onStatus)
          if ((targetName ?? '') === 'contact.db') {
            this.traceFocusedContactChildren(ReadProcessMemory, hProcess, secondHopPointer, secondHop, focusedContactHubGraph, onStatus)
            this.traceFocusedContactOwnerChildren(ReadProcessMemory, hProcess, secondHopPointer, secondHop, focusedContactHubGraph, onStatus)
          }

          for (const offset of pointedOffsets) {
            const candidate = this.verifyCandidateFromSlice(secondHop, offset, verifyKey, seenCandidates)
            if (candidate) return candidate
          }

          const secondHopCandidate = this.findVerifiedCandidateInBuffer(secondHop, verifyKey, seenCandidates, {
            rawStep: 8,
            maxRawCandidates: 8
          })
          if (secondHopCandidate) return secondHopCandidate
        }
      }
    }

    if ((targetName ?? '') === 'contact.db') {
      const focusedCandidate = this.traceSharedContactHubCandidates(
        ReadProcessMemory,
        hProcess,
        focusedContactHubGraph ?? new Map<number, Set<number>>(),
        verifyKey,
        seenCandidates,
        onStatus
      )
      if (focusedCandidate) return focusedCandidate
    }

    return null
  }

  private applyMatchedCandidateAcrossTargets(
    candidate: string,
    targets: DbVerificationTarget[],
    matchedKeys: Record<string, string>,
    verifiers: Map<string, (candidate: string) => boolean>,
    onStatus?: (message: string, level: number) => void
  ) {
    for (const target of targets) {
      if (matchedKeys[target.saltHex]) continue
      const verifyKey = verifiers.get(target.saltHex) ?? this.createBestDbKeyVerifier(target.path)
      if (!verifyKey) continue
      verifiers.set(target.saltHex, verifyKey)
      if (!verifyKey(candidate)) continue
      matchedKeys[target.saltHex] = candidate
      onStatus?.(`Native scan: matched ${target.name} via shared candidate reuse`, 1)
    }
  }

  private async scanProcessForMarkerAnchors(
    ReadProcessMemory: any,
    hProcess: any,
    regions: Array<[number, number]>,
    targets: DbVerificationTarget[],
    onStatus?: (message: string, level: number) => void
  ): Promise<Map<string, number[]>> {
    const CHUNK_SIZE = 1024 * 1024
    const OVERLAP = Math.max(...targets.flatMap((target) => target.markers.map((marker) => Buffer.from(marker, 'utf16le').length)), 64)
    const MAX_HITS_PER_TARGET = 6
    const anchorMap = new Map<string, number[]>()
    const markerEntries = targets.flatMap((target) =>
      target.markers.map((marker) => ({
        target,
        buffer: Buffer.from(marker, 'utf16le')
      })).filter((entry) => entry.buffer.length > 0)
    )

    for (let regionIndex = 0; regionIndex < regions.length; regionIndex++) {
      if (
        anchorMap.size >= targets.length &&
        Array.from(anchorMap.values()).every((hits) => hits.length >= MAX_HITS_PER_TARGET)
      ) {
        break
      }
      const [base, size] = regions[regionIndex]
      if (regionIndex > 0 && regionIndex % 32 === 0) {
        onStatus?.(`Native scan: marker-anchor progress ${regionIndex}/${regions.length}`, 0)
        await new Promise((resolve) => setTimeout(resolve, 1))
      }

      let offset = 0
      let trailing = Buffer.alloc(0)
      while (offset < size) {
        const bytesToRead = Math.min(CHUNK_SIZE, size - offset)
        const chunk = this.readProcessBuffer(ReadProcessMemory, hProcess, base + offset, bytesToRead)
        if (!chunk || chunk.length === 0) {
          offset += bytesToRead
          trailing = Buffer.alloc(0)
          continue
        }

        const haystack = trailing.length > 0 ? Buffer.concat([trailing, chunk]) : chunk
        const haystackBase = base + offset - trailing.length

        for (const { target, buffer } of markerEntries) {
          const existing = anchorMap.get(target.saltHex) ?? []
          if (existing.length >= MAX_HITS_PER_TARGET) continue
          const hitIndex = haystack.indexOf(buffer)
          if (hitIndex === -1) continue

          const anchorAddress = haystackBase + hitIndex
          const derivedAnchors = [0, 8, 16, 24, 32, 40, 48, 56, 64]
            .map((delta) => anchorAddress - delta)
            .filter((addr) => this.isLikelyProcessAddress(addr))

          for (const candidate of derivedAnchors) {
            if (!existing.includes(candidate)) {
              existing.push(candidate)
            }
            if (existing.length >= MAX_HITS_PER_TARGET) break
          }
          anchorMap.set(target.saltHex, existing)
        }

        trailing = Buffer.from(haystack.subarray(Math.max(0, haystack.length - OVERLAP)))
        offset += chunk.length
      }
    }

    return anchorMap
  }

  private async scanProcessForPointerReferences(
    ReadProcessMemory: any,
    hProcess: any,
    regions: Array<[number, number]>,
    anchorMap: Map<string, number[]>,
    onStatus?: (message: string, level: number) => void
  ): Promise<Map<string, number[]>> {
    const CHUNK_SIZE = 1024 * 1024
    const refsBySalt = new Map<string, number[]>()
    const patternEntries = Array.from(anchorMap.entries()).flatMap(([saltHex, anchors]) =>
      anchors.map((anchor) => ({
        saltHex,
        anchor,
        pattern: Buffer.from(BigInt(anchor).toString(16).padStart(16, '0'), 'hex').reverse()
      }))
    )
    const MAX_REFS_PER_TARGET = 8

    const targetSaltCount = new Set(patternEntries.map((entry) => entry.saltHex)).size

    for (let regionIndex = 0; regionIndex < regions.length; regionIndex++) {
      if (
        targetSaltCount > 0 &&
        refsBySalt.size >= targetSaltCount &&
        Array.from(refsBySalt.values()).every((refs) => refs.length >= MAX_REFS_PER_TARGET)
      ) {
        break
      }
      const [base, size] = regions[regionIndex]
      if (regionIndex > 0 && regionIndex % 32 === 0) {
        onStatus?.(`Native scan: reverse-pointer progress ${regionIndex}/${regions.length}`, 0)
        await new Promise((resolve) => setTimeout(resolve, 1))
      }

      let offset = 0
      let trailing = Buffer.alloc(0)
      while (offset < size) {
        const bytesToRead = Math.min(CHUNK_SIZE, size - offset)
        const chunk = this.readProcessBuffer(ReadProcessMemory, hProcess, base + offset, bytesToRead)
        if (!chunk || chunk.length === 0) {
          offset += bytesToRead
          trailing = Buffer.alloc(0)
          continue
        }

        const haystack = trailing.length > 0 ? Buffer.concat([trailing, chunk]) : chunk
        const haystackBase = base + offset - trailing.length

        for (const { saltHex, pattern } of patternEntries) {
          const refs = refsBySalt.get(saltHex) ?? []
          if (refs.length >= MAX_REFS_PER_TARGET) continue

          let searchStart = 0
          while (searchStart < haystack.length) {
            const hitIndex = haystack.indexOf(pattern, searchStart)
            if (hitIndex === -1) break
            const refAddress = haystackBase + hitIndex
            if (!refs.includes(refAddress)) {
              refs.push(refAddress)
              refsBySalt.set(saltHex, refs)
            }
            searchStart = hitIndex + 8
            if (refs.length >= MAX_REFS_PER_TARGET) break
          }
        }

        trailing = Buffer.from(haystack.subarray(Math.max(0, haystack.length - 8)))
        offset += chunk.length
      }
    }

    return refsBySalt
  }

  private findVerifiedCandidateViaPointerGraph(
    ReadProcessMemory: any,
    hProcess: any,
    rootRefs: number[],
    verifyKey: (candidate: string) => boolean,
    seenCandidates: Set<string>
  ): string | null {
    const MAX_DEPTH = 3
    const MAX_NODES = 64
    const NODE_WINDOW_BEFORE = 64
    const NODE_WINDOW_SIZE = 320
    const queue: Array<{ address: number; depth: number }> = rootRefs.map((address) => ({ address, depth: 0 }))
    const seenNodes = new Set<number>()
    const seenPointers = new Set<number>()

    while (queue.length > 0 && seenNodes.size < MAX_NODES) {
      const current = queue.shift()!
      if (!this.isLikelyProcessAddress(current.address) || seenNodes.has(current.address)) continue
      seenNodes.add(current.address)

      const windowStart = Math.max(0, current.address - NODE_WINDOW_BEFORE)
      const window = this.readProcessBuffer(ReadProcessMemory, hProcess, windowStart, NODE_WINDOW_SIZE)
      if (!window || window.length < 32) continue

      const directCandidate = this.findVerifiedCandidateInBuffer(window, verifyKey, seenCandidates, {
        rawStep: 8,
        maxRawCandidates: 48
      })
      if (directCandidate) return directCandidate

      const pointerCandidate = this.findVerifiedCandidateViaPointers(
        ReadProcessMemory,
        hProcess,
        window,
        verifyKey,
        seenCandidates,
        seenPointers
      )
      if (pointerCandidate) return pointerCandidate

      if (current.depth >= MAX_DEPTH) continue

      for (const pointer of this.extractPointerValues(window, 24)) {
        if (!seenNodes.has(pointer)) {
          queue.push({ address: pointer, depth: current.depth + 1 })
        }
      }
    }

    return null
  }

  private async collectDbVerificationTargets(): Promise<DbVerificationTarget[]> {
    try {
      const detected = await dbPathService.autoDetect()
      if (!detected.success || !detected.path) return []

      const wxids = dbPathService.scanWxids(detected.path)
      if (wxids.length === 0) return []

      const wxid = wxids[0].wxid
      const dbStoragePath = join(detected.path, wxid, 'db_storage')
      if (!existsSync(dbStoragePath)) return []

      const targetRelativePaths = [
        ['session.db', join('session', 'session.db')],
        ['contact.db', join('contact', 'contact.db')],
        ['message_0.db', join('message', 'message_0.db')],
        ['biz_message_0.db', join('message', 'biz_message_0.db')],
        ['message_fts.db', join('message', 'message_fts.db')],
        ['message_resource.db', join('message', 'message_resource.db')],
        ['sns.db', join('sns', 'sns.db')]
      ] as const

      const { readFileSync } = require('fs') as typeof import('fs')
      const targets: DbVerificationTarget[] = []
      for (const [name, relativePath] of targetRelativePaths) {
        const fullPath = join(dbStoragePath, relativePath)
        if (!existsSync(fullPath)) continue
        try {
          const head = readFileSync(fullPath).subarray(0, 16)
          if (head.length < 16) continue
          const saltHex = head.toString('hex')
          if (/^53514c697465/i.test(saltHex)) continue
          targets.push({
            name,
            path: fullPath,
            saltHex,
            markers: this.collectDbMarkerTexts(fullPath, relativePath)
          })
        } catch { }
      }
      return targets
    } catch {
      return []
    }
  }

  private async scanProcessForHexKeys(
    pid: number,
    onStatus?: (message: string, level: number) => void
  ): Promise<string[]> {
    if (!this.ensureKernel32()) return []
    this.koffi = this.koffi || require('koffi')

    const VirtualQueryEx = this.kernel32.func('VirtualQueryEx', 'size_t', ['void*', 'uintptr', 'void*', 'size_t'])
    const ReadProcessMemory = this.kernel32.func('ReadProcessMemory', 'bool', ['void*', 'uintptr', 'void*', 'size_t', this.koffi.out('size_t*')])

    const PROCESS_QUERY_INFORMATION = 0x0400
    const PROCESS_VM_READ = 0x0010
    const RW_FLAGS = 0x04 | 0x08 | 0x40 | 0x80
    const MEM_COMMIT = 0x1000
    const PAGE_NOACCESS = 0x01
    const PAGE_GUARD = 0x100
    const MBI_SIZE = 48
    const CHUNK_SIZE = 2 * 1024 * 1024
    const OVERLAP = 127
    const MAX_REGION_SIZE = 64 * 1024 * 1024
    const MAX_CANDIDATES = 2048
    const candidateSet = new Set<string>()
    const hexPattern = /(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])/g
    const utf16HexPattern = /(?:[0-9a-fA-F]\x00){64}/g

    const hProcess = this.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
    if (!hProcess) return []

    try {
      const regions: Array<[number, number]> = []
      let address = 0
      const mbi = Buffer.alloc(MBI_SIZE)

      while (address < 0x7fffffffffff) {
        const ret = VirtualQueryEx(hProcess, address, mbi, MBI_SIZE)
        if (ret === 0) break

        const base = Number(mbi.readBigUInt64LE(0))
        const size = Number(mbi.readBigUInt64LE(24))
        const state = mbi.readUInt32LE(32)
        const protect = mbi.readUInt32LE(36)

        if (
          state === MEM_COMMIT &&
          protect !== PAGE_NOACCESS &&
          (protect & PAGE_GUARD) === 0 &&
          (protect & RW_FLAGS) !== 0 &&
          size > 0 &&
          size <= MAX_REGION_SIZE
        ) {
          regions.push([base, size])
        }

        const next = base + size
        if (next <= address) break
        address = next
      }

      onStatus?.(`Native scan: scanning ${regions.length} readable memory regions`, 0)

      for (let regionIndex = 0; regionIndex < regions.length; regionIndex++) {
        if (candidateSet.size >= MAX_CANDIDATES) break
        const [base, size] = regions[regionIndex]
        if (regionIndex > 0 && regionIndex % 32 === 0) {
          onStatus?.(`Native scan: memory region progress ${regionIndex}/${regions.length}`, 0)
          await new Promise((resolve) => setTimeout(resolve, 1))
        }

        let offset = 0
        let trailing = ''
        while (offset < size && candidateSet.size < MAX_CANDIDATES) {
          const bytesToRead = Math.min(CHUNK_SIZE, size - offset)
          const chunk = Buffer.alloc(bytesToRead)
          const bytesRead = Buffer.alloc(8)
          const ok = ReadProcessMemory(hProcess, base + offset, chunk, bytesToRead, bytesRead)
          if (!ok) {
            offset += bytesToRead
            trailing = ''
            continue
          }

          const actualBytes = Number(bytesRead.readBigUInt64LE(0))
          if (actualBytes <= 0) {
            offset += bytesToRead
            trailing = ''
            continue
          }

          const current = chunk.subarray(0, actualBytes).toString('latin1')
          const haystack = trailing + current
          for (const match of haystack.match(hexPattern) ?? []) {
            candidateSet.add(match.toLowerCase())
            if (candidateSet.size >= MAX_CANDIDATES) break
          }
          if (candidateSet.size < MAX_CANDIDATES) {
            for (const match of haystack.match(utf16HexPattern) ?? []) {
              candidateSet.add(match.replace(/\x00/g, '').toLowerCase())
              if (candidateSet.size >= MAX_CANDIDATES) break
            }
          }

          trailing = haystack.slice(Math.max(0, haystack.length - OVERLAP))
          offset += actualBytes
        }
      }

      return Array.from(candidateSet)
    } finally {
      this.CloseHandle(hProcess)
    }
  }

  private async scanProcessForKeysNearDbMarkers(
    pid: number,
    targets: DbVerificationTarget[],
    onStatus?: (message: string, level: number) => void
  ): Promise<Record<string, string>> {
    if (!this.ensureKernel32() || targets.length === 0) return {}
    this.koffi = this.koffi || require('koffi')

    const VirtualQueryEx = this.kernel32.func('VirtualQueryEx', 'size_t', ['void*', 'uintptr', 'void*', 'size_t'])
    const ReadProcessMemory = this.kernel32.func('ReadProcessMemory', 'bool', ['void*', 'uintptr', 'void*', 'size_t', this.koffi.out('size_t*')])

    const PROCESS_QUERY_INFORMATION = 0x0400
    const PROCESS_VM_READ = 0x0010
    const RW_FLAGS = 0x04 | 0x08 | 0x40 | 0x80
    const MAX_REGION_SIZE = 64 * 1024 * 1024
    const verifiers = new Map<string, (candidate: string) => boolean>()
    const matchedKeys: Record<string, string> = {}

    const hProcess = this.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
    if (!hProcess) return {}

    try {
      const regions = this.collectReadableProcessRegions(VirtualQueryEx, hProcess, RW_FLAGS, MAX_REGION_SIZE)
      onStatus?.(`Native scan: probing ${targets.length} DB path/file markers in writable memory`, 0)
      const anchorMap = await this.scanProcessForMarkerAnchors(ReadProcessMemory, hProcess, regions, targets, onStatus)
      onStatus?.(`Native scan: collected ${Array.from(anchorMap.values()).reduce((sum, hits) => sum + hits.length, 0)} anchor candidates for ${anchorMap.size}/${targets.length} DB samples`, 0)
      const refMap = await this.scanProcessForPointerReferences(ReadProcessMemory, hProcess, regions, anchorMap, onStatus)
      onStatus?.(`Native scan: collected ${Array.from(refMap.values()).reduce((sum, refs) => sum + refs.length, 0)} reverse-pointer hits for ${refMap.size}/${targets.length} DB samples`, 0)

      for (const target of targets) {
        const refs = refMap.get(target.saltHex) ?? []
        if (refs.length === 0) continue

        const verifyKey = verifiers.get(target.saltHex) ?? this.createBestDbKeyVerifier(target.path)
        if (!verifyKey) continue
        verifiers.set(target.saltHex, verifyKey)

        const rootSeeds = Array.from(new Set(
          refs.flatMap((ref) =>
            [0, 8, 16, 24, 32, 40, 48, 56, 64]
              .map((delta) => ref - delta)
              .filter((addr) => this.isLikelyProcessAddress(addr))
          )
        ))
        onStatus?.(
          `Native scan: [${target.name}] refs ${refs.slice(0, 4).map((value) => this.formatProcessAddress(value)).join(', ')}; root seeds ${rootSeeds.length}`,
          0
        )

        const seenCandidates = new Set<string>()

        const candidate = this.findVerifiedCandidateViaSiblingFields(
          ReadProcessMemory,
          hProcess,
          rootSeeds,
          verifyKey,
          seenCandidates,
          target.name,
          onStatus
        ) ?? this.findVerifiedCandidateViaPointerGraph(
          ReadProcessMemory,
          hProcess,
          rootSeeds,
          verifyKey,
          seenCandidates
        )
        if (candidate) {
          matchedKeys[target.saltHex] = candidate
          onStatus?.(`Native scan: matched ${target.name} via path-anchor structure scan`, 1)
          this.applyMatchedCandidateAcrossTargets(candidate, targets, matchedKeys, verifiers, onStatus)
          if (Object.keys(matchedKeys).length === targets.length) {
            break
          }
        }
      }

      return matchedKeys
    } finally {
      this.CloseHandle(hProcess)
    }
  }

  private async scanProcessForRawWcdbKeyStrings(
    pid: number,
    targets: DbVerificationTarget[],
    onStatus?: (message: string, level: number) => void
  ): Promise<Record<string, string>> {
    if (!this.ensureKernel32() || targets.length === 0) return {}
    this.koffi = this.koffi || require('koffi')

    const VirtualQueryEx = this.kernel32.func('VirtualQueryEx', 'size_t', ['void*', 'uintptr', 'void*', 'size_t'])
    const ReadProcessMemory = this.kernel32.func('ReadProcessMemory', 'bool', ['void*', 'uintptr', 'void*', 'size_t', this.koffi.out('size_t*')])

    const PROCESS_QUERY_INFORMATION = 0x0400
    const PROCESS_VM_READ = 0x0010
    const RW_FLAGS = 0x04 | 0x08 | 0x40 | 0x80
    const MAX_REGION_SIZE = 64 * 1024 * 1024
    const CHUNK_SIZE = 2 * 1024 * 1024
    const OVERLAP = 160
    const matchedKeys: Record<string, string> = {}

    const targetStates = targets.map((target) => ({
      target,
      verifyKey: this.createSqlcipher4RawKeyVerifier(target.path),
      seenCandidates: new Set<string>(),
      pattern: new RegExp(`(?:x')?([0-9a-fA-F]{64})${target.saltHex}(?:')?`, 'ig')
    })).filter((entry) => Boolean(entry.verifyKey))

    if (targetStates.length === 0) return {}

    const hProcess = this.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
    if (!hProcess) return {}

    try {
      const regions = this.collectReadableProcessRegions(VirtualQueryEx, hProcess, RW_FLAGS, MAX_REGION_SIZE)
      onStatus?.(`Native scan: trying SQLCipher4 raw-key markers across ${targetStates.length} DB salts`, 0)

      for (let regionIndex = 0; regionIndex < regions.length; regionIndex++) {
        if (Object.keys(matchedKeys).length === targetStates.length) break
        const [base, size] = regions[regionIndex]
        if (regionIndex > 0 && regionIndex % 32 === 0) {
          onStatus?.(`Native scan: raw-key marker progress ${regionIndex}/${regions.length}`, 0)
          await new Promise((resolve) => setTimeout(resolve, 1))
        }

        let offset = 0
        let trailing = ''
        while (offset < size && Object.keys(matchedKeys).length < targetStates.length) {
          const bytesToRead = Math.min(CHUNK_SIZE, size - offset)
          const chunk = this.readProcessBuffer(ReadProcessMemory, hProcess, base + offset, bytesToRead)
          if (!chunk || chunk.length === 0) {
            offset += bytesToRead
            trailing = ''
            continue
          }

          const haystack = trailing + chunk.toString('latin1')
          for (const entry of targetStates) {
            const { target, verifyKey, seenCandidates, pattern } = entry
            if (!verifyKey || matchedKeys[target.saltHex]) continue
            pattern.lastIndex = 0
            let match: RegExpExecArray | null = null
            while ((match = pattern.exec(haystack)) !== null) {
              const candidate = String(match[1] || '').toLowerCase()
              if (!this.isHexKey(candidate) || seenCandidates.has(candidate)) continue
              seenCandidates.add(candidate)
              if (!verifyKey(candidate)) continue
              matchedKeys[target.saltHex] = candidate
              onStatus?.(`Native scan: matched ${target.name} via raw wcdb key marker`, 1)
              break
            }
          }

          trailing = haystack.slice(Math.max(0, haystack.length - OVERLAP))
          offset += chunk.length
        }
      }

      return matchedKeys
    } finally {
      this.CloseHandle(hProcess)
    }
  }

  private async _getDbKeyViaPyWxDump(
    onStatus?: (message: string, level: number) => void
  ): Promise<DbKeyResult> {
    const result = await pyWxDumpService.getDbKey(
      (msg) => onStatus?.(msg, 0),
      120_000
    )
    if (!result.success || !result.accounts?.length) {
      return { success: false, error: result.error || 'PyWxDump 未返回任何账号信息' }
    }

    const account = result.accounts.find((a: any) =>
      (a.wcdb_keys && Object.keys(a.wcdb_keys).length > 0) ||
      (a.key && a.key.length === 64)
    ) ?? result.accounts[0]

    if (account.wcdb_keys && Object.keys(account.wcdb_keys).length > 0) {
      onStatus?.('PyWxDump returned Weixin 4.x multi-key result', 1)
      return { success: true, wcdbKeys: account.wcdb_keys, source: 'pywxdump' }
    }

    if (account.key && this.isHexKey(account.key)) {
      onStatus?.('PyWxDump returned a usable DB key', 1)
      return { success: true, key: String(account.key).trim().toLowerCase(), source: 'pywxdump' }
    }

    return { success: false, error: 'PyWxDump 返回的密钥格式无效' }
  }

  private async _getDbKeyViaNativeMemoryScan(
    onStatus?: (message: string, level: number) => void,
    targetOverride?: DbVerificationTarget[],
    allowPartial = false
  ): Promise<DbKeyResult> {
    const targets = targetOverride && targetOverride.length > 0
      ? targetOverride
      : await this.collectDbVerificationTargets()
    if (targets.length === 0) {
      return { success: false, error: '自有内存扫描未找到可用于校验的数据库样本' }
    }

    const pid = await this.findWeChatPid()
    if (!pid) {
      return { success: false, error: '未检测到微信进程，请先启动并登录微信' }
    }

    onStatus?.(`Native scan: found ${targets.length} encrypted DB samples`, 0)
    const matchedKeys = await this.scanProcessForRawWcdbKeyStrings(pid, targets, onStatus)
    if (Object.keys(matchedKeys).length > 0) {
      onStatus?.(`Native scan: raw wcdb key markers covered ${Object.keys(matchedKeys).length}/${targets.length} DB samples`, 0)
    }

    const remainingAfterRaw = targets.filter((target) => !matchedKeys[target.saltHex])
    if (remainingAfterRaw.length > 0) {
      const markerMatchedKeys = await this.scanProcessForKeysNearDbMarkers(pid, remainingAfterRaw, onStatus)
      Object.assign(matchedKeys, markerMatchedKeys)
    }

    if (Object.keys(matchedKeys).length !== targets.length) {
      const candidates = await this.scanProcessForHexKeys(pid, onStatus)
      if (candidates.length === 0 && Object.keys(matchedKeys).length === 0) {
        return { success: false, error: '自有内存扫描未找到可用密钥候选（ASCII / raw）' }
      }

      if (candidates.length > 0) {
        onStatus?.(`Native scan: verifying ${candidates.length} global ASCII candidates`, 0)
      }

      for (let candidateIndex = 0; candidateIndex < candidates.length; candidateIndex++) {
        const candidate = candidates[candidateIndex]
        if (candidateIndex > 0 && candidateIndex % 128 === 0) {
          onStatus?.(`Native scan: global candidate progress ${candidateIndex}/${candidates.length}`, 0)
          await new Promise((resolve) => setTimeout(resolve, 1))
        }

        for (const target of targets) {
          if (matchedKeys[target.saltHex]) continue
          const verifyKey = this.createBestDbKeyVerifier(target.path)
          if (!verifyKey || !verifyKey(candidate)) continue
          matchedKeys[target.saltHex] = candidate
          onStatus?.(`Native scan: matched ${target.name}`, 1)
        }

        if (Object.keys(matchedKeys).length === targets.length) break
      }
    }

    if (Object.keys(matchedKeys).length !== targets.length) {
      if (allowPartial && Object.keys(matchedKeys).length > 0) {
        onStatus?.(`Native scan: partial coverage ${Object.keys(matchedKeys).length}/${targets.length}`, 1)
        return { success: true, wcdbKeys: matchedKeys, source: 'native' }
      }
      return {
        success: false,
        error: `自有内存扫描仅覆盖 ${Object.keys(matchedKeys).length}/${targets.length} 个数据库样本，暂时无法完全替代 DLL`,
        logs: targets
          .filter((target) => matchedKeys[target.saltHex])
          .map((target) => `已命中 ${target.name}`)
      }
    }

    if (allowPartial) {
      onStatus?.(`Native scan: supplemented ${Object.keys(matchedKeys).length} DB salts`, 1)
      return { success: true, wcdbKeys: matchedKeys, source: 'native' }
    }

    const uniqueKeys = Array.from(new Set(Object.values(matchedKeys)))
    if (uniqueKeys.length === 1) {
      onStatus?.('Native scan: key extraction succeeded in single-key mode', 1)
      return { success: true, key: uniqueKeys[0], source: 'native' }
    }

    onStatus?.(`Native scan: key extraction succeeded in multi-key mode (${uniqueKeys.length})`, 1)
    return { success: true, wcdbKeys: matchedKeys, source: 'native' }
  }

  private async supplementWcdbKeysIfNeeded(
    currentKeys: Record<string, string>,
    onStatus?: (message: string, level: number) => void
  ): Promise<Record<string, string>> {
    const normalizedKeys = this.normalizeWcdbKeys(currentKeys) ?? {}
    const targets = await this.collectDbVerificationTargets()
    if (targets.length === 0) return normalizedKeys

    const missingTargets = targets.filter((target) => !normalizedKeys[target.saltHex])
    if (missingTargets.length === 0) return normalizedKeys

    onStatus?.(
      `PyWxDump covered ${Object.keys(normalizedKeys).length}/${targets.length} DB samples; supplementing ${missingTargets.length} missing salts via native scan`,
      0
    )

    const nativeResult = await this._getDbKeyViaNativeMemoryScan(onStatus, missingTargets, true)
    const nativeKeys = this.normalizeWcdbKeys(nativeResult.wcdbKeys)
    if (!nativeResult.success || !nativeKeys) {
      onStatus?.('Native supplement did not recover additional WCDB salts', 1)
      return normalizedKeys
    }

    const mergedKeys = { ...normalizedKeys, ...nativeKeys }
    onStatus?.(
      `Native supplement recovered ${Object.keys(nativeKeys).length} salts; coverage ${Object.keys(mergedKeys).length}/${targets.length}`,
      Object.keys(mergedKeys).length === targets.length ? 1 : 0
    )
    return mergedKeys
  }

  private async _getDbKeyViaDll(
    timeoutMs: number,
    onStatus?: (message: string, level: number) => void
  ): Promise<DbKeyResult> {
    if (!this.ensureDllCompatLoaded()) return { success: false, error: 'wx_key.dll compatibility layer unavailable' }
    if (!this.ensureKernel32()) return { success: false, error: 'Kernel32 init failed' }

    const pid = await this.findWeChatPid()
    if (!pid) {
      return { success: false, error: '未找到微信进程，请先启动微信' }
    }

    onStatus?.(`DLL fallback: attaching to pid ${pid}`, 0)
    const loginRequiredBefore = await this.detectWeChatLoginRequired(pid)
    const readyBefore = await this.waitForWeChatWindowComponents(pid, 1500)

    const compat = this.dllCompatApi
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
      } catch { }
    }

    const loginRequiredAfter = await this.detectWeChatLoginRequired(pid)
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

  private async _autoGetDbKeyChain(
    timeoutMs = 60_000,
    onStatus?: (message: string, level: number) => void
  ): Promise<DbKeyResult> {
    if (!this.ensureWin32()) return { success: false, error: '仅支持 Windows' }

    const chainLogs: string[] = []
    const seenLogs = new Set<string>()
    const emitStatus = (message: string, level: number) => {
      const normalized = String(message || '').trim()
      if (!normalized) return
      const marker = `${level}:${normalized}`
      if (!seenLogs.has(marker)) {
        seenLogs.add(marker)
        chainLogs.push(normalized)
      }
      onStatus?.(normalized, level)
    }
    emitStatus('Pure-native key strategy: PyWxDump bridge first, native memory scan second, no DLL fallback', 0)
    emitStatus('Trying PyWxDump bridge first...', 0)
    const pyResult = await this._getDbKeyViaPyWxDump(emitStatus)
    if (pyResult.success) {
      const pyKeys = this.normalizeWcdbKeys(pyResult.wcdbKeys)
      if (pyKeys) {
        const supplementedKeys = await this.supplementWcdbKeysIfNeeded(pyKeys, emitStatus)
        return { ...pyResult, wcdbKeys: supplementedKeys, logs: chainLogs }
      }
      return { ...pyResult, logs: chainLogs }
    }

    emitStatus(`PyWxDump missed: ${pyResult.error || 'no usable key returned'}`, 1)
    emitStatus('Trying native memory scan...', 1)
    const nativeResult = await this._getDbKeyViaNativeMemoryScan(emitStatus)
    if (nativeResult.success) return { ...nativeResult, logs: chainLogs }

    emitStatus(`Native scan missed: ${nativeResult.error || 'no usable key returned'}`, 1)
    return {
      success: false,
      error: nativeResult.error || pyResult.error || 'Pure-native key chain did not produce a usable database key',
      logs: chainLogs,
      source: nativeResult.source ?? pyResult.source
    }
  }

  private cleanWxid(wxid: string): string {
    const first = wxid.indexOf('_')
    if (first === -1) return wxid
    const second = wxid.indexOf('_', first + 1)
    if (second === -1) return wxid
    return wxid.substring(0, second)
  }

  private deriveImageKeys(code: number, wxid: string): { xorKey: number; aesKey: string } {
    const cleanedWxid = this.cleanWxid(wxid)
    const xorKey = code & 0xFF
    const dataToHash = code.toString() + cleanedWxid
    const md5Full = crypto.createHash('md5').update(dataToHash).digest('hex')
    const aesKey = md5Full.substring(0, 16)
    return { xorKey, aesKey }
  }

  private verifyDerivedAesKey(aesKey: string, ciphertext: Buffer): boolean {
    try {
      if (!aesKey || aesKey.length < 16 || ciphertext.length !== 16) return false
      const decipher = crypto.createDecipheriv('aes-128-ecb', Buffer.from(aesKey, 'ascii').subarray(0, 16), null)
      decipher.setAutoPadding(false)
      const dec = Buffer.concat([decipher.update(ciphertext), decipher.final()])
      if (dec[0] === 0xFF && dec[1] === 0xD8 && dec[2] === 0xFF) return true
      if (dec[0] === 0x89 && dec[1] === 0x50 && dec[2] === 0x4E && dec[3] === 0x47) return true
      if (dec[0] === 0x52 && dec[1] === 0x49 && dec[2] === 0x46 && dec[3] === 0x46) return true
      if (dec[0] === 0x77 && dec[1] === 0x78 && dec[2] === 0x67 && dec[3] === 0x66) return true
      if (dec[0] === 0x47 && dec[1] === 0x49 && dec[2] === 0x46) return true
      return false
    } catch {
      return false
    }
  }

  private async collectWxidCandidates(manualDir?: string, wxidParam?: string): Promise<string[]> {
    const candidates: string[] = []
    const pushUnique = (value: string) => {
      const v = String(value || '').trim()
      if (!v || candidates.includes(v)) return
      candidates.push(v)
    }

    if (wxidParam && wxidParam.startsWith('wxid_')) pushUnique(wxidParam)

    if (manualDir) {
      const normalized = manualDir.replace(/[\\/]+$/, '')
      const dirName = normalized.split(/[\\/]/).pop() ?? ''
      if (dirName.startsWith('wxid_')) pushUnique(dirName)

      const marker = normalized.match(/[\\/]xwechat_files/i) || normalized.match(/[\\/]WeChat Files/i)
      if (marker) {
        const root = normalized.slice(0, marker.index! + marker[0].length)
        try {
          const { readdirSync, statSync } = await import('fs')
          const { join } = await import('path')
          for (const entry of readdirSync(root)) {
            if (!entry.startsWith('wxid_')) continue
            const full = join(root, entry)
            try {
              if (statSync(full).isDirectory()) pushUnique(entry)
            } catch { }
          }
        } catch { }
      }
    }

    pushUnique('unknown')
    return candidates
  }

  private collectKvcommCodes(accountPath?: string): number[] {
    const codeSet = new Set<number>()
    const pattern = /^key_(\d+)_.+\.statistic$/i

    for (const kvcommDir of this.getKvcommCandidates(accountPath)) {
      if (!existsSync(kvcommDir)) continue
      try {
        const files = readdirSync(kvcommDir)
        for (const file of files) {
          const match = file.match(pattern)
          if (!match) continue
          const code = Number(match[1])
          if (!Number.isFinite(code) || code <= 0 || code > 0xFFFFFFFF) continue
          codeSet.add(code)
        }
      } catch { }
    }

    return Array.from(codeSet)
  }

  private getKvcommCandidates(accountPath?: string): string[] {
    const candidates = new Set<string>()

    if (accountPath) {
      const normalized = accountPath.replace(/[\\/]+$/, '')
      const slashPath = normalized.replace(/\\/g, '/')
      const marker = slashPath.match(/\/xwechat_files(?:\/|$)/i) || slashPath.match(/\/wechat files(?:\/|$)/i)
      if (marker?.index !== undefined) {
        const root = slashPath.slice(0, marker.index + marker[0].length).replace(/\/+$/, '')
        const base = root.replace(/\/xwechat_files$/i, '/app_data').replace(/\/wechat files$/i, '/app_data')
        candidates.add(`${base}/net/kvcomm`)
      }

      let cursor = normalized
      for (let i = 0; i < 6; i++) {
        candidates.add(join(cursor, 'net', 'kvcomm'))
        const next = dirname(cursor)
        if (next === cursor) break
        cursor = next
      }
    }

    try {
      const defaultRoot = dbPathService.getDefaultPath().replace(/[\\/]+$/, '')
      candidates.add(join(dirname(defaultRoot), 'app_data', 'net', 'kvcomm'))
      candidates.add(join(defaultRoot, 'app_data', 'net', 'kvcomm'))
    } catch { }

    return Array.from(candidates)
  }

  async autoGetImageKeyPure(
      manualDir?: string,
      onProgress?: (message: string) => void,
      wxidParam?: string
  ): Promise<ImageKeyResult> {
    if (!this.ensureWin32()) return { success: false, error: 'Windows only' }

    onProgress?.('Deriving image key from kvcomm and template data...')

    const codes = this.collectKvcommCodes(manualDir)
    if (codes.length === 0) {
      return { success: false, error: 'No kvcomm image-key codes found' }
    }

    console.log('[ImageKey] kvcomm codes:', codes)

    const wxidCandidates = await this.collectWxidCandidates(manualDir, wxidParam)
    let verifyCiphertext: Buffer | null = null
    if (manualDir && existsSync(manualDir)) {
      const template = await this._findTemplateData(manualDir, 32)
      verifyCiphertext = template.ciphertext
    }

    if (verifyCiphertext) {
      onProgress?.(`Verifying ${wxidCandidates.length} wxid candidates...`)
      for (const candidateWxid of wxidCandidates) {
        for (const code of codes) {
          const { xorKey, aesKey } = this.deriveImageKeys(code, candidateWxid)
          if (!this.verifyDerivedAesKey(aesKey, verifyCiphertext)) continue
          onProgress?.(`Image key resolved (wxid: ${candidateWxid}, code: ${code})`)
          console.log('[ImageKey] verified:', { wxid: candidateWxid, code })
          return { success: true, xorKey, aesKey, verified: true }
        }
      }
      return { success: false, error: 'kvcomm code did not match current wxid; verify the account directory or use memory scan' }
    }

    const fallbackWxid = wxidCandidates[0] || 'unknown'
    const fallbackCode = codes[0]
    const { xorKey, aesKey } = this.deriveImageKeys(fallbackCode, fallbackWxid)
    onProgress?.(`Image key resolved (wxid: ${fallbackWxid}, code: ${fallbackCode})`)
    console.log('[ImageKey] fallback-derived:', { wxid: fallbackWxid, code: fallbackCode })
    return { success: true, xorKey, aesKey, verified: false }
  }

  async autoGetImageKey(
      manualDir?: string,
      onProgress?: (message: string) => void,
      wxidParam?: string
  ): Promise<ImageKeyResult> {
    return this.autoGetImageKeyPure(manualDir, onProgress, wxidParam)
  }

  // --- 内存扫描备选方案（融合 Dart+Python 优点）---
  // 只扫 RW 可写区域（更快），同时支持 ASCII 和 UTF-16LE 两种密钥格式
  // 验证支持 JPEG/PNG/WEBP/WXGF/GIF 多种格式

  async autoGetImageKeyByMemoryScan(
    userDir: string,
    onProgress?: (message: string) => void
  ): Promise<ImageKeyResult> {
    if (!this.ensureWin32()) return { success: false, error: '仅支持 Windows' }

    try {
      // 1. 查找模板文件获取密文和 XOR 密钥
      onProgress?.('正在查找模板文件...')
      let result = await this._findTemplateData(userDir, 32)
      let { ciphertext, xorKey } = result
      
      // 如果找不到密钥，尝试扫描更多文件
      if (ciphertext && xorKey === null) {
        onProgress?.('未找到有效密钥，尝试扫描更多文件...')
        result = await this._findTemplateData(userDir, 100)
        xorKey = result.xorKey
      }
      
      if (!ciphertext) return { success: false, error: '未找到 V2 模板文件，请先在微信中查看几张图片' }
      if (xorKey === null) return { success: false, error: '未能从模板文件中计算出有效的 XOR 密钥，请确保在微信中查看了多张不同的图片' }

      onProgress?.(`XOR 密钥: 0x${xorKey.toString(16).padStart(2, '0')}，正在查找微信进程...`)

      // 2. 找微信 PID
      const pid = await this.findWeChatPid()
      if (!pid) return { success: false, error: '微信进程未运行，请先启动微信' }

      onProgress?.(`已找到微信进程 PID=${pid}，正在扫描内存...`)

      // 3. 持续轮询内存扫描，最多 60 秒
      const deadline = Date.now() + 60_000
      let scanCount = 0
      while (Date.now() < deadline) {
        scanCount++
        onProgress?.(`第 ${scanCount} 次扫描内存，请在微信中打开图片大图...`)
        const aesKey = await this._scanMemoryForAesKey(pid, ciphertext, onProgress)
        if (aesKey) {
          onProgress?.('密钥获取成功')
          return { success: true, xorKey, aesKey }
        }
        // 等 5 秒再试
        await new Promise(r => setTimeout(r, 5000))
      }

      return {
        success: false,
        error: '60 秒内未找到 AES 密钥。\n请确保已在微信中打开 2-3 张图片大图后再试。'
      }
    } catch (e) {
      return { success: false, error: `内存扫描失败: ${e}` }
    }
  }

  private async _findTemplateData(userDir: string, limit: number = 32): Promise<{ ciphertext: Buffer | null; xorKey: number | null }> {
    const { readdirSync, readFileSync, statSync } = await import('fs')
    const { join } = await import('path')
    const V2_MAGIC = Buffer.from([0x07, 0x08, 0x56, 0x32, 0x08, 0x07])

    // 递归收集 *_t.dat 文件
    const collect = (dir: string, results: string[], maxFiles: number) => {
      if (results.length >= maxFiles) return
      try {
        for (const entry of readdirSync(dir, { withFileTypes: true })) {
          if (results.length >= maxFiles) break
          const full = join(dir, entry.name)
          if (entry.isDirectory()) collect(full, results, maxFiles)
          else if (entry.isFile() && entry.name.endsWith('_t.dat')) results.push(full)
        }
      } catch { /* 忽略无权限目录 */ }
    }

    const files: string[] = []
    collect(userDir, files, limit)

    // 按修改时间降序
    files.sort((a, b) => {
      try { return statSync(b).mtimeMs - statSync(a).mtimeMs } catch { return 0 }
    })

    let ciphertext: Buffer | null = null
    const tailCounts: Record<string, number> = {}

    for (const f of files.slice(0, 32)) {
      try {
        const data = readFileSync(f)
        if (data.length < 8) continue

        // 统计末尾两字节用于 XOR 密钥
        if (data.subarray(0, 6).equals(V2_MAGIC) && data.length >= 2) {
          const key = `${data[data.length - 2]}_${data[data.length - 1]}`
          tailCounts[key] = (tailCounts[key] ?? 0) + 1
        }

        // 提取密文（取第一个有效的）
        if (!ciphertext && data.subarray(0, 6).equals(V2_MAGIC) && data.length >= 0x1F) {
          ciphertext = data.subarray(0xF, 0x1F)
        }
      } catch { /* 忽略 */ }
    }

    // 计算 XOR 密钥
    let xorKey: number | null = null
    let maxCount = 0
    for (const [key, count] of Object.entries(tailCounts)) {
      if (count > maxCount) { maxCount = count; const [x, y] = key.split('_').map(Number); const k = x ^ 0xFF; if (k === (y ^ 0xD9)) xorKey = k }
    }

    return { ciphertext, xorKey }
  }

  private async _scanMemoryForAesKey(
    pid: number,
    ciphertext: Buffer,
    onProgress?: (msg: string) => void
  ): Promise<string | null> {
    if (!this.ensureKernel32()) return null

    // 直接用已加载的 kernel32 实例，用 uintptr 传地址
    const VirtualQueryEx = this.kernel32.func('VirtualQueryEx', 'size_t', ['void*', 'uintptr', 'void*', 'size_t'])
    const ReadProcessMemory = this.kernel32.func('ReadProcessMemory', 'bool', ['void*', 'uintptr', 'void*', 'size_t', this.koffi.out('size_t*')])

    // RW 保护标志（只扫可写区域，速度更快）
    const RW_FLAGS = 0x04 | 0x08 | 0x40 | 0x80 // PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    const MEM_COMMIT = 0x1000
    const PAGE_NOACCESS = 0x01
    const PAGE_GUARD = 0x100
    const MBI_SIZE = 48 // MEMORY_BASIC_INFORMATION size on x64

    const hProcess = this.OpenProcess(0x1F0FFF, false, pid)
    if (!hProcess) return null

    try {
      // 枚举 RW 内存区域
      const regions: Array<[number, number]> = []
      let addr = 0
      const mbi = Buffer.alloc(MBI_SIZE)

      while (addr < 0x7FFFFFFFFFFF) {
        const ret = VirtualQueryEx(hProcess, addr, mbi, MBI_SIZE)
        if (ret === 0) break
        // MEMORY_BASIC_INFORMATION x64 布局:
        // 0:  BaseAddress (8)
        // 8:  AllocationBase (8)
        // 16: AllocationProtect (4) + 4 padding
        // 24: RegionSize (8)
        // 32: State (4)
        // 36: Protect (4)
        // 40: Type (4) + 4 padding = 48 total
        const base = Number(mbi.readBigUInt64LE(0))
        const size = Number(mbi.readBigUInt64LE(24))
        const state = mbi.readUInt32LE(32)
        const protect = mbi.readUInt32LE(36)

        if (state === MEM_COMMIT &&
            protect !== PAGE_NOACCESS &&
            (protect & PAGE_GUARD) === 0 &&
            (protect & RW_FLAGS) !== 0 &&
            size <= 50 * 1024 * 1024) {
          regions.push([base, size])
        }
        const next = base + size
        if (next <= addr) break
        addr = next
      }

      const totalMB = regions.reduce((s, [, sz]) => s + sz, 0) / 1024 / 1024
      onProgress?.(`扫描 ${regions.length} 个 RW 区域 (${totalMB.toFixed(0)} MB)...`)

      const CHUNK = 4 * 1024 * 1024
      const OVERLAP = 65

      for (let i = 0; i < regions.length; i++) {
        const [base, size] = regions[i]
        if (i % 20 === 0) {
          onProgress?.(`扫描进度 ${i}/${regions.length}...`)
          await new Promise(r => setTimeout(r, 1)) // 让出事件循环
        }

        let offset = 0
        let trailing: Buffer | null = null

        while (offset < size) {
          const chunkSize = Math.min(CHUNK, size - offset)
          const buf = Buffer.alloc(chunkSize)
          const bytesReadOut = [0]
          const ok = ReadProcessMemory(hProcess, base + offset, buf, chunkSize, bytesReadOut)
          if (!ok || bytesReadOut[0] === 0) { offset += chunkSize; trailing = null; continue }

          const data: Buffer = trailing ? Buffer.concat([trailing, buf.subarray(0, bytesReadOut[0])]) : buf.subarray(0, bytesReadOut[0])

          // 搜索 ASCII 32字节密钥
          const key = this._searchAsciiKey(data, ciphertext)
          if (key) { this.CloseHandle(hProcess); return key }

          // 搜索 UTF-16LE 32字节密钥
          const key16 = this._searchUtf16Key(data, ciphertext)
          if (key16) { this.CloseHandle(hProcess); return key16 }

          trailing = data.subarray(Math.max(0, data.length - OVERLAP))
          offset += chunkSize
        }
      }

      return null
    } finally {
      this.CloseHandle(hProcess)
    }
  }

  private _searchAsciiKey(data: Buffer, ciphertext: Buffer): string | null {
    for (let i = 0; i < data.length - 34; i++) {
      if (this._isAlphaNum(data[i])) continue
      let valid = true
      for (let j = 1; j <= 32; j++) {
        if (!this._isAlphaNum(data[i + j])) { valid = false; break }
      }
      if (!valid) continue
      if (i + 33 < data.length && this._isAlphaNum(data[i + 33])) continue
      const keyBytes = data.subarray(i + 1, i + 33)
      if (this._verifyAesKey(keyBytes, ciphertext)) return keyBytes.toString('ascii').substring(0, 16)
    }
    return null
  }

  private _searchUtf16Key(data: Buffer, ciphertext: Buffer): string | null {
    for (let i = 0; i < data.length - 65; i++) {
      let valid = true
      for (let j = 0; j < 32; j++) {
        if (data[i + j * 2 + 1] !== 0x00 || !this._isAlphaNum(data[i + j * 2])) { valid = false; break }
      }
      if (!valid) continue
      const keyBytes = Buffer.alloc(32)
      for (let j = 0; j < 32; j++) keyBytes[j] = data[i + j * 2]
      if (this._verifyAesKey(keyBytes, ciphertext)) return keyBytes.toString('ascii').substring(0, 16)
    }
    return null
  }

  private _isAlphaNum(b: number): boolean {
    return (b >= 0x61 && b <= 0x7A) || (b >= 0x41 && b <= 0x5A) || (b >= 0x30 && b <= 0x39)
  }

  private _verifyAesKey(keyBytes: Buffer, ciphertext: Buffer): boolean {
    try {
      const decipher = crypto.createDecipheriv('aes-128-ecb', keyBytes.subarray(0, 16), null)
      decipher.setAutoPadding(false)
      const dec = Buffer.concat([decipher.update(ciphertext), decipher.final()])
      // 支持 JPEG / PNG / WEBP / WXGF / GIF
      if (dec[0] === 0xFF && dec[1] === 0xD8 && dec[2] === 0xFF) return true
      if (dec[0] === 0x89 && dec[1] === 0x50 && dec[2] === 0x4E && dec[3] === 0x47) return true
      if (dec[0] === 0x52 && dec[1] === 0x49 && dec[2] === 0x46 && dec[3] === 0x46) return true
      if (dec[0] === 0x77 && dec[1] === 0x78 && dec[2] === 0x67 && dec[3] === 0x66) return true
      if (dec[0] === 0x47 && dec[1] === 0x49 && dec[2] === 0x46) return true
      return false
    } catch { return false }
  }
}
