import crypto from 'crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync, copyFileSync, readdirSync } from 'fs'
import { basename, dirname, join, relative } from 'path'

export interface NativeDecryptDirResult {
  success: boolean
  decrypted?: number
  failed?: number
  results?: Array<{ in: string; out: string; skipped?: boolean }>
  errors?: Array<{ in: string; error: string }>
  out_dir?: string
  error?: string
}

type FirstPageInfo = {
  pageSize: number
  reserveSize: number
  logicalPageCount: number
  firstPage: Buffer
  macKey: Buffer
  rawKey: Buffer
}

class NativeSqlcipherService {
  private readonly sqliteHeader = Buffer.from('SQLite format 3\0', 'binary')
  private readonly hmacSize = 64
  private readonly ivSize = 16
  private readonly defaultPageSize = 4096

  async decryptDbDir(
    wcdbKeys: Record<string, string>,
    dbDir: string,
    outDir: string,
    onStatus?: (msg: string) => void
  ): Promise<NativeDecryptDirResult> {
    try {
      if (!dbDir || !existsSync(dbDir)) {
        return { success: false, error: `数据库目录不存在: ${dbDir}` }
      }

      const keyCount = Object.keys(wcdbKeys || {}).length
      if (keyCount === 0) {
        return { success: false, error: '没有可用的 wcdb_keys' }
      }

      mkdirSync(outDir, { recursive: true })
      onStatus?.(`native decrypt: scanning ${dbDir}`)

      const results: Array<{ in: string; out: string; skipped?: boolean }> = []
      const errors: Array<{ in: string; error: string }> = []

      const walk = (dir: string) => {
        for (const entry of readdirSync(dir, { withFileTypes: true })) {
          const full = join(dir, entry.name)
          if (entry.isDirectory()) {
            walk(full)
            continue
          }
          if (!entry.isFile()) continue
          if (!entry.name.toLowerCase().endsWith('.db')) continue
          if (entry.name.toLowerCase().endsWith('.db-wal')) continue
          if (entry.name.toLowerCase().endsWith('.db-shm')) continue
          if (entry.name.toLowerCase().endsWith('.db-journal')) continue

          const relDir = relative(dbDir, dirname(full))
          const outSubdir = join(outDir, relDir)
          mkdirSync(outSubdir, { recursive: true })
          const outPath = join(outSubdir, `de_${basename(full)}`)

          try {
            if (this.isPlainSqliteFile(full)) {
              copyFileSync(full, outPath)
              results.push({ in: full, out: outPath, skipped: true })
              continue
            }

            const saltHex = this.readSaltHex(full)
            const rawKeyHex = wcdbKeys[saltHex]
            if (!rawKeyHex) {
              errors.push({ in: full, error: `未找到对应密钥，salt=${saltHex}` })
              continue
            }

            this.decryptSqlcipher4RawDb(full, rawKeyHex, outPath)
            results.push({ in: full, out: outPath })
          } catch (e) {
            errors.push({ in: full, error: String(e) })
          }
        }
      }

      walk(dbDir)

      onStatus?.(`native decrypt: success ${results.length}, failed ${errors.length}`)
      return {
        success: results.length > 0,
        decrypted: results.length,
        failed: errors.length,
        results,
        errors,
        out_dir: outDir,
        error: results.length > 0 ? undefined : (errors[0]?.error || '没有成功解密任何数据库')
      }
    } catch (e) {
      return { success: false, error: String(e) }
    }
  }

  private isPlainSqliteFile(filePath: string): boolean {
    try {
      const header = readFileSync(filePath).subarray(0, 16)
      return header.equals(this.sqliteHeader)
    } catch {
      return false
    }
  }

  private readSaltHex(filePath: string): string {
    const header = readFileSync(filePath).subarray(0, 16)
    return header.toString('hex')
  }

  private decryptSqlcipher4RawDb(inputPath: string, rawKeyHex: string, outputPath: string): void {
    const fileBuffer = readFileSync(inputPath)
    if (fileBuffer.length < this.defaultPageSize) {
      throw new Error(`文件过小，无法解密: ${inputPath}`)
    }

    const firstPageInfo = this.decryptFirstPage(fileBuffer, rawKeyHex)
    const {
      firstPage,
      logicalPageCount,
      pageSize,
      reserveSize,
      macKey,
      rawKey,
    } = firstPageInfo

    const physicalPageCount = Math.floor(fileBuffer.length / pageSize)
    const pageCount = Math.max(1, Math.min(logicalPageCount, physicalPageCount))
    const outBuffer = Buffer.alloc(pageCount * pageSize)
    firstPage.copy(outBuffer, 0)

    for (let pageNo = 2; pageNo <= pageCount; pageNo++) {
      const pageStart = (pageNo - 1) * pageSize
      const src = fileBuffer.subarray(pageStart, pageStart + pageSize)
      if (src.length < pageSize) {
        throw new Error(`页 ${pageNo} 长度不足，pageSize=${pageSize}`)
      }

      const plain = this.decryptPage(src, rawKey, macKey, reserveSize, pageNo)
      plain.copy(outBuffer, pageStart)
      outBuffer.fill(0, pageStart + plain.length, pageStart + pageSize)
    }

    mkdirSync(dirname(outputPath), { recursive: true })
    writeFileSync(outputPath, outBuffer)
  }

  private decryptFirstPage(fileBuffer: Buffer, rawKeyHex: string): FirstPageInfo {
    const rawKey = Buffer.from(rawKeyHex.trim(), 'hex')
    if (rawKey.length !== 32) {
      throw new Error(`raw key 长度无效: ${rawKey.length}`)
    }

    const salt = fileBuffer.subarray(0, 16)
    const macSalt = Buffer.alloc(16)
    for (let i = 0; i < 16; i++) macSalt[i] = salt[i] ^ 0x3a
    const macKey = crypto.pbkdf2Sync(rawKey, macSalt, 2, 32, 'sha512')

    const firstEncryptedPage = fileBuffer.subarray(16, this.defaultPageSize)
    const plainTail = this.decryptPage(firstEncryptedPage, rawKey, macKey, 80, 1)

    const firstPage = Buffer.alloc(this.defaultPageSize)
    this.sqliteHeader.copy(firstPage, 0)
    plainTail.copy(firstPage, 16)
    firstPage.fill(0, 16 + plainTail.length, this.defaultPageSize)

    let pageSize = firstPage.readUInt16BE(16)
    if (pageSize === 1) pageSize = 65536
    if (!this.isValidPageSize(pageSize)) {
      throw new Error(`pageSize 无效: ${pageSize}`)
    }

    const reserveSize = firstPage.readUInt8(20)
    if (reserveSize < this.ivSize + this.hmacSize) {
      throw new Error(`reserveSize 不支持: ${reserveSize}`)
    }

    let logicalPageCount = firstPage.readUInt32BE(28)
    const physicalPageCount = Math.floor(fileBuffer.length / pageSize)
    if (!logicalPageCount || logicalPageCount > physicalPageCount) {
      logicalPageCount = physicalPageCount
    }

    return { pageSize, reserveSize, logicalPageCount, firstPage, macKey, rawKey }
  }

  private decryptPage(
    encryptedPage: Buffer,
    rawKey: Buffer,
    macKey: Buffer,
    reserveSize: number,
    pageNo: number
  ): Buffer {
    const cipherLength = encryptedPage.length - reserveSize
    const ivOffset = encryptedPage.length - reserveSize
    const macOffset = encryptedPage.length - this.hmacSize
    if (cipherLength <= 0 || ivOffset < 0 || macOffset <= ivOffset) {
      throw new Error(`页布局无效 page=${pageNo}`)
    }

    const cipherText = encryptedPage.subarray(0, cipherLength)
    const iv = encryptedPage.subarray(ivOffset, macOffset)
    const mac = encryptedPage.subarray(macOffset)
    const pageNumber = Buffer.alloc(4)
    pageNumber.writeUInt32LE(pageNo, 0)

    const digest = crypto.createHmac('sha512', macKey)
      .update(cipherText)
      .update(iv)
      .update(pageNumber)
      .digest()
    if (!digest.equals(mac)) {
      throw new Error(`page ${pageNo} mac mismatch`)
    }

    const decipher = crypto.createDecipheriv('aes-256-cbc', rawKey, iv)
    decipher.setAutoPadding(false)
    return Buffer.concat([decipher.update(cipherText), decipher.final()])
  }

  private isValidPageSize(pageSize: number): boolean {
    if (pageSize < 512 || pageSize > 65536) return false
    return (pageSize & (pageSize - 1)) === 0
  }
}

export const nativeSqlcipherService = new NativeSqlcipherService()
