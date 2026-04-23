/**
 * PyWxDumpService
 *
 * 通过调用 resources/pywxdump_bridge.py 脚本，将 PyWxDump 的解密能力接入 WeFlow。
 * 替代 wx_key.dll（获取密钥）和 wcdb_api.dll（打开加密数据库）两个闭源 DLL。
 *
 * 工作流程（彻底替换方案）：
 *   1. get_key      → 调用 PyWxDump 从微信内存读取数据库密钥
 *   2. decrypt_dir  → 用该密钥批量解密 db_storage/ 到临时目录
 *   3. wcdbCore 的调用方直接用 better-sqlite3 读取解密后的明文 SQLite
 */

import { execFile } from 'child_process'
import { join, dirname } from 'path'
import { existsSync, mkdirSync } from 'fs'
import { tmpdir } from 'os'
import { promisify } from 'util'
const execFileAsync = promisify(execFile)

function getElectronAppPath(): string | null {
  try {
    const electron = require('electron')
    const electronApp = electron?.app
    if (electronApp && typeof electronApp.getAppPath === 'function') {
      return electronApp.getAppPath()
    }
  } catch {}

  return null
}

export interface PyAccountInfo {
  pid?: number
  version?: string
  wxid?: string
  account?: string
  nickname?: string
  key?: string           // 64 位 hex，旧版 WeChat 3.x
  wx_dir?: string
  wcdb_keys?: Record<string, string>  // 新版 Weixin 4.x: { salt_hex: key_hex }
}

export interface GetKeyResult {
  success: boolean
  accounts?: PyAccountInfo[]
  error?: string
}

export interface DecryptDirResult {
  success: boolean
  decrypted?: number
  failed?: number
  out_dir?: string
  errors?: Array<{ in: string; error: string }>
  error?: string
}

export class PyWxDumpService {
  /** Python 可执行文件名，优先使用环境变量 PYWXDUMP_PYTHON 指定 */
  private pythonCmd: string

  /** 桥接脚本绝对路径 */
  private readonly bridgeScript: string

  /** 解密输出目录（临时） */
  private _decryptedDir: string | null = null

  constructor() {
    this.pythonCmd = this.resolvePythonCommand()
    this.bridgeScript = this.resolveBridgePath()
  }

  private resolvePythonCommand(): string {
    const envPython = process.env.PYWXDUMP_PYTHON?.trim()
    if (envPython) return envPython

    const cwd = process.cwd()
    const appPath = getElectronAppPath()
    const candidates = [
      join(cwd, '.venv-pywxdump', 'Scripts', 'python.exe'),
      join(cwd, '.venv', 'Scripts', 'python.exe'),
      appPath ? join(appPath, '.venv-pywxdump', 'Scripts', 'python.exe') : '',
      appPath ? join(dirname(appPath), '.venv-pywxdump', 'Scripts', 'python.exe') : '',
    ].filter(Boolean)

    for (const candidate of candidates) {
      if (existsSync(candidate)) return candidate
    }

    return 'python'
  }

  private resolveBridgePath(): string {
    const candidates: string[] = []

    // 打包后：resourcesPath/resources/pywxdump_bridge.py
    if (process.resourcesPath) {
      candidates.push(join(process.resourcesPath, 'resources', 'pywxdump_bridge.py'))
      candidates.push(join(process.resourcesPath, 'pywxdump_bridge.py'))
    }

    // 开发时：cwd()/resources/pywxdump_bridge.py
    const cwd = process.cwd()
    candidates.push(join(cwd, 'resources', 'pywxdump_bridge.py'))

    // app.getAppPath() 方式
    const appPath = getElectronAppPath()
    if (appPath) {
      candidates.push(join(appPath, 'resources', 'pywxdump_bridge.py'))
    }

    for (const p of candidates) {
      if (existsSync(p)) return p
    }

    // 找不到时返回开发路径，运行时会报错并有明确提示
    return candidates[0]
  }

  /** 调用桥接脚本，返回解析后的 JSON */
  private async runBridge(args: string[], timeoutMs = 60_000): Promise<any> {
    if (!existsSync(this.bridgeScript)) {
      throw new Error(
        `桥接脚本不存在: ${this.bridgeScript}\n` +
        `请确保 resources/pywxdump_bridge.py 已正确部署。`
      )
    }

    // 将 PyWxDump 路径透传给 Python，保证子进程能找到
    const env = {
      ...process.env,
      PYWXDUMP_PATH: process.env.PYWXDUMP_PATH || this.detectPyWxDumpPath(),
    }

    const { stdout, stderr } = await execFileAsync(
      this.pythonCmd,
      [this.bridgeScript, ...args],
      { timeout: timeoutMs, maxBuffer: 50 * 1024 * 1024, env }
    )

    if (stderr && stderr.trim()) {
      console.warn('[PyWxDump] stderr:', stderr.trim())
    }

    const line = stdout.trim().split('\n').pop() || '{}'
    try {
      return JSON.parse(line)
    } catch {
      throw new Error(`桥接脚本输出解析失败: ${stdout.slice(0, 500)}`)
    }
  }

  /** 自动推断 PyWxDump 目录（与 WeFlow 同级） */
  private detectPyWxDumpPath(): string {
    // bridge 脚本在 WeFlow/resources/，PyWxDump 在 <workspace>/PyWxDump/
    const scriptDir = dirname(this.bridgeScript)        // .../WeFlow/resources
    const weflowDir = dirname(scriptDir)                // .../WeFlow
    const workspaceDir = dirname(weflowDir)             // .../workspace
    const candidate = join(workspaceDir, 'PyWxDump')
    return existsSync(candidate) ? candidate : ''
  }

  // ---------------------------------------------------------------------------
  // 公共 API
  // ---------------------------------------------------------------------------

  /**
   * 获取微信数据库密钥（替换 wx_key.dll 的 autoGetDbKey）
   *
   * 支持两种模式：
   *  - 旧版 WeChat 3.x：返回单个 64 位 hex key
   *  - 新版 Weixin 4.x：返回 wcdb_keys = { salt_hex: key_hex }
   */
  async getDbKey(
    onStatus?: (msg: string) => void,
    timeoutMs = 120_000
  ): Promise<GetKeyResult> {
    onStatus?.('正在通过 PyWxDump 获取微信密钥...')
    try {
      const res = await this.runBridge(['get_key'], timeoutMs)
      if (!res.success) {
        return { success: false, error: res.error }
      }
      onStatus?.(`密钥获取成功，共 ${res.accounts?.length ?? 0} 个账号`)
      return { success: true, accounts: res.accounts }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  /**
   * 批量解密数据库目录（替换 wcdb_api.dll 的 open）
   *
   * @param keyOrJson  64 位 hex 字符串（旧版）或 JSON 字符串 {salt_hex: key_hex}（新版）
   * @param dbDir      微信 db_storage 目录（含加密 .db 文件）
   * @param outDir     输出目录（解密后的明文 SQLite 写入此处）
   */
  async decryptDbDir(
    keyOrJson: string,
    dbDir: string,
    outDir: string,
    onStatus?: (msg: string) => void,
    timeoutMs = 180_000
  ): Promise<DecryptDirResult> {
    onStatus?.(`正在解密数据库目录: ${dbDir}`)

    // wcdb_keys 是对象时序列化为 JSON 字符串传给 Python
    const keyArg = typeof keyOrJson === 'object'
      ? JSON.stringify(keyOrJson)
      : keyOrJson

    try {
      const res = await this.runBridge(['decrypt_dir', keyArg, dbDir, outDir], timeoutMs)
      if (!res.success) {
        return { success: false, error: res.error }
      }
      this._decryptedDir = outDir
      onStatus?.(`解密完成：成功 ${res.decrypted}，失败 ${res.failed}`)
      return res as DecryptDirResult
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  /**
   * 创建本次会话的解密输出目录（放在系统临时目录下）
   */
  makeDecryptedDir(wxid: string): string {
    const dir = join(tmpdir(), 'weflow_decrypted', wxid)
    mkdirSync(dir, { recursive: true })
    return dir
  }

  /** 上一次解密后的输出目录 */
  get decryptedDir(): string | null {
    return this._decryptedDir
  }

  /**
   * 检查 Python 环境和 PyWxDump 是否可用
   * 返回 { ok, pythonVersion, pywxdumpAvailable, error }
   */
  async checkEnvironment(): Promise<{
    ok: boolean
    pythonVersion?: string
    pywxdumpAvailable?: boolean
    bridgeExists?: boolean
    error?: string
  }> {
    const bridgeExists = existsSync(this.bridgeScript)

    // 检查 Python 版本
    let pythonVersion: string | undefined
    try {
      const { stdout } = await execFileAsync(this.pythonCmd, ['--version'], { timeout: 5000 })
      pythonVersion = stdout.trim() || 'unknown'
    } catch {
      return {
        ok: false,
        bridgeExists,
        error: `Python 未找到（尝试命令: ${this.pythonCmd}）\n` +
               `可通过环境变量 PYWXDUMP_PYTHON 指定 Python 路径`
      }
    }

    // 检查 PyWxDump import
    let pywxdumpAvailable = false
    try {
      const env = {
        ...process.env,
        PYWXDUMP_PATH: process.env.PYWXDUMP_PATH || this.detectPyWxDumpPath(),
      }
      await execFileAsync(
        this.pythonCmd,
        ['-c', 'import pywxdump; print("ok")'],
        { timeout: 10_000, env }
      )
      pywxdumpAvailable = true
    } catch {}

    return {
      ok: bridgeExists && pywxdumpAvailable,
      pythonVersion,
      pywxdumpAvailable,
      bridgeExists,
    }
  }
}

export const pyWxDumpService = new PyWxDumpService()
