import { join, basename } from 'path'
import { existsSync, readdirSync, statSync, readFileSync } from 'fs'
import { homedir } from 'os'
import { createDecipheriv } from 'crypto'

export interface WxidInfo {
  wxid: string
  modifiedTime: number
  nickname?: string
  avatarUrl?: string
}

export class DbPathService {
  private pushCandidateRoot(target: string[], seen: Set<string>, value?: string | null) {
    if (!value) return
    const normalized = String(value).trim()
    if (!normalized || seen.has(normalized)) return
    seen.add(normalized)
    target.push(normalized)
  }

  private getPossibleRoots(): string[] {
    const roots: string[] = []
    const seen = new Set<string>()
    const home = homedir()

    if (process.platform === 'darwin') {
      this.pushCandidateRoot(roots, seen, join(home, 'Library', 'Containers', 'com.tencent.xinWeChat', 'Data', 'Documents', 'xwechat_files'))
      return roots
    }

    const documentBases = [
      join(home, 'Documents'),
      process.env.USERPROFILE ? join(process.env.USERPROFILE, 'Documents') : '',
      process.env.HOMEDRIVE && process.env.HOMEPATH ? join(`${process.env.HOMEDRIVE}${process.env.HOMEPATH}`, 'Documents') : '',
      process.env.OneDrive ? join(process.env.OneDrive, 'Documents') : '',
      process.env.OneDriveCommercial ? join(process.env.OneDriveCommercial, 'Documents') : '',
      process.env.OneDriveConsumer ? join(process.env.OneDriveConsumer, 'Documents') : ''
    ]

    for (const documentsPath of documentBases) {
      this.pushCandidateRoot(roots, seen, documentsPath ? join(documentsPath, 'xwechat_files') : '')
      this.pushCandidateRoot(roots, seen, documentsPath ? join(documentsPath, 'WeChat Files') : '')
    }

    const systemDrive = process.env.SystemDrive || 'C:'
    const usersRoot = join(systemDrive, 'Users')
    if (existsSync(usersRoot)) {
      try {
        for (const entry of readdirSync(usersRoot)) {
          const userPath = join(usersRoot, entry)
          let stat: ReturnType<typeof statSync>
          try {
            stat = statSync(userPath)
          } catch {
            continue
          }
          if (!stat.isDirectory()) continue

          this.pushCandidateRoot(roots, seen, join(userPath, 'Documents', 'xwechat_files'))
          this.pushCandidateRoot(roots, seen, join(userPath, 'Documents', 'WeChat Files'))
          this.pushCandidateRoot(roots, seen, join(userPath, 'OneDrive', 'Documents', 'xwechat_files'))
          this.pushCandidateRoot(roots, seen, join(userPath, 'OneDrive', 'Documents', 'WeChat Files'))
        }
      } catch { }
    }

    return roots
  }

  private getRootScore(rootPath: string): number {
    const accounts = this.findAccountDirs(rootPath)
    if (accounts.length === 0) return -1

    let latest = 0
    for (const account of accounts) {
      latest = Math.max(latest, this.getAccountModifiedTime(join(rootPath, account)))
    }

    return latest + accounts.length
  }

  private readVarint(buf: Buffer, offset: number): { value: number, length: number } {
    let value = 0
    let length = 0
    let shift = 0
    while (offset < buf.length && shift < 32) {
      const b = buf[offset++]
      value |= (b & 0x7f) << shift
      length++
      if ((b & 0x80) === 0) break
      shift += 7
    }
    return { value, length }
  }

  private extractMmkvString(buf: Buffer, keyName: string): string {
    const keyBuf = Buffer.from(keyName, 'utf8')
    const idx = buf.indexOf(keyBuf)
    if (idx === -1) return ''

    try {
      let offset = idx + keyBuf.length
      const v1 = this.readVarint(buf, offset)
      offset += v1.length
      const v2 = this.readVarint(buf, offset)
      offset += v2.length

      if (v2.value > 0 && v2.value <= 10000 && offset + v2.value <= buf.length) {
        return buf.toString('utf8', offset, offset + v2.value)
      }
    } catch { }

    return ''
  }

  private parseGlobalConfig(rootPath: string): { wxid: string; nickname: string; avatarUrl: string } | null {
    try {
      const configPath = join(rootPath, 'all_users', 'config', 'global_config')
      if (!existsSync(configPath)) return null

      const fullData = readFileSync(configPath)
      if (fullData.length <= 4) return null
      const encryptedData = fullData.subarray(4)

      const key = Buffer.alloc(16, 0)
      Buffer.from('xwechat_crypt_key').copy(key)
      const iv = Buffer.alloc(16, 0)

      const decipher = createDecipheriv('aes-128-cfb', key, iv)
      decipher.setAutoPadding(false)
      const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()])

      const wxid = this.extractMmkvString(decrypted, 'mmkv_key_user_name')
      const nickname = this.extractMmkvString(decrypted, 'mmkv_key_nick_name')
      let avatarUrl = this.extractMmkvString(decrypted, 'mmkv_key_head_img_url')

      if (!avatarUrl && decrypted.includes('http')) {
        const httpIdx = decrypted.indexOf('http')
        const nullIdx = decrypted.indexOf(0x00, httpIdx)
        if (nullIdx !== -1) {
          avatarUrl = decrypted.toString('utf8', httpIdx, nullIdx)
        }
      }

      if (wxid || nickname) {
        return { wxid, nickname, avatarUrl }
      }
      return null
    } catch (e) {
      console.error('解析 global_config 失败:', e)
      return null
    }
  }

  async autoDetect(): Promise<{ success: boolean; path?: string; error?: string }> {
    try {
      let bestPath = ''
      let bestScore = -1

      for (const path of this.getPossibleRoots()) {
        if (!existsSync(path)) continue

        const rootName = path.split(/[/\\]/).pop()?.toLowerCase()
        if (rootName !== 'xwechat_files' && rootName !== 'wechat files') {
          continue
        }

        const score = this.getRootScore(path)
        if (score < 0) continue

        if (score > bestScore) {
          bestScore = score
          bestPath = path
        }
      }

      if (bestPath) {
        return { success: true, path: bestPath }
      }

      return { success: false, error: '未能自动检测到微信数据库目录' }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  findAccountDirs(rootPath: string): string[] {
    const accounts: string[] = []

    try {
      const entries = readdirSync(rootPath)

      for (const entry of entries) {
        const entryPath = join(rootPath, entry)
        let stat: ReturnType<typeof statSync>
        try {
          stat = statSync(entryPath)
        } catch {
          continue
        }

        if (!stat.isDirectory()) continue
        if (!this.isPotentialAccountName(entry)) continue
        if (this.isAccountDir(entryPath)) {
          accounts.push(entry)
        }
      }
    } catch { }

    return accounts
  }

  private isAccountDir(entryPath: string): boolean {
    return (
      existsSync(join(entryPath, 'db_storage')) ||
      existsSync(join(entryPath, 'FileStorage', 'Image')) ||
      existsSync(join(entryPath, 'FileStorage', 'Image2'))
    )
  }

  private isPotentialAccountName(name: string): boolean {
    const lower = name.toLowerCase()
    if (lower.startsWith('all') || lower.startsWith('applet') || lower.startsWith('backup') || lower.startsWith('wmpf')) {
      return false
    }
    return true
  }

  private getAccountModifiedTime(entryPath: string): number {
    try {
      const accountStat = statSync(entryPath)
      let latest = accountStat.mtimeMs

      const dbPath = join(entryPath, 'db_storage')
      if (existsSync(dbPath)) {
        const dbStat = statSync(dbPath)
        latest = Math.max(latest, dbStat.mtimeMs)
      }

      const imagePath = join(entryPath, 'FileStorage', 'Image')
      if (existsSync(imagePath)) {
        const imageStat = statSync(imagePath)
        latest = Math.max(latest, imageStat.mtimeMs)
      }

      const image2Path = join(entryPath, 'FileStorage', 'Image2')
      if (existsSync(image2Path)) {
        const image2Stat = statSync(image2Path)
        latest = Math.max(latest, image2Stat.mtimeMs)
      }

      return latest
    } catch {
      return 0
    }
  }

  scanWxidCandidates(rootPath: string): WxidInfo[] {
    const wxids: WxidInfo[] = []

    try {
      if (existsSync(rootPath)) {
        const entries = readdirSync(rootPath)
        for (const entry of entries) {
          const entryPath = join(rootPath, entry)
          let stat: ReturnType<typeof statSync>
          try {
            stat = statSync(entryPath)
          } catch {
            continue
          }
          if (!stat.isDirectory()) continue
          const lower = entry.toLowerCase()
          if (lower === 'all_users') continue
          if (!entry.includes('_')) continue
          wxids.push({ wxid: entry, modifiedTime: stat.mtimeMs })
        }
      }

      if (wxids.length === 0) {
        const rootName = basename(rootPath)
        if (rootName.includes('_') && rootName.toLowerCase() !== 'all_users') {
          const rootStat = statSync(rootPath)
          wxids.push({ wxid: rootName, modifiedTime: rootStat.mtimeMs })
        }
      }
    } catch { }

    const sorted = wxids.sort((a, b) => {
      if (b.modifiedTime !== a.modifiedTime) return b.modifiedTime - a.modifiedTime
      return a.wxid.localeCompare(b.wxid)
    })

    const globalInfo = this.parseGlobalConfig(rootPath)
    if (globalInfo) {
      for (const w of sorted) {
        if (w.wxid.startsWith(globalInfo.wxid) || sorted.length === 1) {
          w.nickname = globalInfo.nickname
          w.avatarUrl = globalInfo.avatarUrl
        }
      }
    }

    return sorted
  }

  scanWxids(rootPath: string): WxidInfo[] {
    const wxids: WxidInfo[] = []

    try {
      if (this.isAccountDir(rootPath)) {
        const wxid = basename(rootPath)
        const modifiedTime = this.getAccountModifiedTime(rootPath)
        return [{ wxid, modifiedTime }]
      }

      const accounts = this.findAccountDirs(rootPath)
      for (const account of accounts) {
        const fullPath = join(rootPath, account)
        const modifiedTime = this.getAccountModifiedTime(fullPath)
        wxids.push({ wxid: account, modifiedTime })
      }
    } catch { }

    const sorted = wxids.sort((a, b) => {
      if (b.modifiedTime !== a.modifiedTime) return b.modifiedTime - a.modifiedTime
      return a.wxid.localeCompare(b.wxid)
    })

    const globalInfo = this.parseGlobalConfig(rootPath)
    if (globalInfo) {
      for (const w of sorted) {
        if (w.wxid.startsWith(globalInfo.wxid) || sorted.length === 1) {
          w.nickname = globalInfo.nickname
          w.avatarUrl = globalInfo.avatarUrl
        }
      }
    }

    return sorted
  }

  getDefaultPath(): string {
    for (const path of this.getPossibleRoots()) {
      if (existsSync(path)) return path
    }

    const home = homedir()
    if (process.platform === 'darwin') {
      return join(home, 'Library', 'Containers', 'com.tencent.xinWeChat', 'Data', 'Documents', 'xwechat_files')
    }
    return join(home, 'Documents', 'xwechat_files')
  }
}

export const dbPathService = new DbPathService()
