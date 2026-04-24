import { existsSync } from 'fs'
import { basename, dirname, join } from 'path'

type WriteLog = (message: string, force?: boolean) => void

export type WcdbDllCompatBindings = {
  lib: any
  koffi: any
  wcdbInitProtection: any
  wcdbInit: any
  wcdbShutdown: any
  wcdbOpenAccount: any
  wcdbCloseAccount: any
  wcdbSetMyWxid: any
  wcdbFreeString: any
  wcdbUpdateMessage: any
  wcdbDeleteMessage: any
  wcdbGetSessions: any
  wcdbGetMessages: any
  wcdbGetMessageCount: any
  wcdbGetDisplayNames: any
  wcdbGetAvatarUrls: any
  wcdbGetGroupMemberCount: any
  wcdbGetGroupMemberCounts: any
  wcdbGetGroupMembers: any
  wcdbGetGroupNicknames: any
  wcdbGetMessageTables: any
  wcdbGetMessageMeta: any
  wcdbGetContact: any
  wcdbGetContactStatus: any
  wcdbGetMessageTableStats: any
  wcdbGetAggregateStats: any
  wcdbGetAvailableYears: any
  wcdbGetAnnualReportStats: any
  wcdbGetAnnualReportExtras: any
  wcdbGetDualReportStats: any
  wcdbGetGroupStats: any
  wcdbGetMessageDates: any
  wcdbOpenMessageCursor: any
  wcdbOpenMessageCursorLite: any
  wcdbFetchMessageBatch: any
  wcdbCloseMessageCursor: any
  wcdbGetLogs: any
  wcdbExecQuery: any
  wcdbListMessageDbs: any
  wcdbListMediaDbs: any
  wcdbGetMessageById: any
  wcdbGetEmoticonCdnUrl: any
  wcdbGetDbStatus: any
  wcdbGetVoiceData: any
  wcdbSearchMessages: any
  wcdbGetSnsTimeline: any
  wcdbGetSnsAnnualStats: any
  wcdbInstallSnsBlockDeleteTrigger: any
  wcdbUninstallSnsBlockDeleteTrigger: any
  wcdbCheckSnsBlockDeleteTrigger: any
  wcdbDeleteSnsPost: any
  wcdbVerifyUser: any
  wcdbStartMonitorPipe: any
  wcdbStopMonitorPipe: any
  wcdbGetMonitorPipeName: any
  wcdbCloudInit: any
  wcdbCloudReport: any
  wcdbCloudStop: any
}

export const WCDB_DLL_COMPAT_BINDING_KEYS: Array<keyof WcdbDllCompatBindings> = [
  'lib',
  'koffi',
  'wcdbInitProtection',
  'wcdbInit',
  'wcdbShutdown',
  'wcdbOpenAccount',
  'wcdbCloseAccount',
  'wcdbSetMyWxid',
  'wcdbFreeString',
  'wcdbUpdateMessage',
  'wcdbDeleteMessage',
  'wcdbGetSessions',
  'wcdbGetMessages',
  'wcdbGetMessageCount',
  'wcdbGetDisplayNames',
  'wcdbGetAvatarUrls',
  'wcdbGetGroupMemberCount',
  'wcdbGetGroupMemberCounts',
  'wcdbGetGroupMembers',
  'wcdbGetGroupNicknames',
  'wcdbGetMessageTables',
  'wcdbGetMessageMeta',
  'wcdbGetContact',
  'wcdbGetContactStatus',
  'wcdbGetMessageTableStats',
  'wcdbGetAggregateStats',
  'wcdbGetAvailableYears',
  'wcdbGetAnnualReportStats',
  'wcdbGetAnnualReportExtras',
  'wcdbGetDualReportStats',
  'wcdbGetGroupStats',
  'wcdbGetMessageDates',
  'wcdbOpenMessageCursor',
  'wcdbOpenMessageCursorLite',
  'wcdbFetchMessageBatch',
  'wcdbCloseMessageCursor',
  'wcdbGetLogs',
  'wcdbExecQuery',
  'wcdbListMessageDbs',
  'wcdbListMediaDbs',
  'wcdbGetMessageById',
  'wcdbGetEmoticonCdnUrl',
  'wcdbGetDbStatus',
  'wcdbGetVoiceData',
  'wcdbSearchMessages',
  'wcdbGetSnsTimeline',
  'wcdbGetSnsAnnualStats',
  'wcdbInstallSnsBlockDeleteTrigger',
  'wcdbUninstallSnsBlockDeleteTrigger',
  'wcdbCheckSnsBlockDeleteTrigger',
  'wcdbDeleteSnsPost',
  'wcdbVerifyUser',
  'wcdbStartMonitorPipe',
  'wcdbStopMonitorPipe',
  'wcdbGetMonitorPipeName',
  'wcdbCloudInit',
  'wcdbCloudReport',
  'wcdbCloudStop'
]

export type WcdbDllCompatInitResult =
  | { kind: 'ready'; bindings: WcdbDllCompatBindings; dllPath: string }
  | { kind: 'missing'; dllPath: string; error: string }
  | { kind: 'init_failed'; bindings: WcdbDllCompatBindings; dllPath: string; initResult: number; initLogs: string[]; error: string }
  | { kind: 'exception'; error: string }

type InitOptions = {
  resourcesPath: string | null
  writeLog: WriteLog
}

function getDllPath(resourcesPath: string | null): string {
  const isMac = process.platform === 'darwin'
  const libName = isMac ? 'libwcdb_api.dylib' : 'wcdb_api.dll'
  const subDir = isMac ? 'macos' : ''

  const envDllPath = process.env.WCDB_DLL_PATH
  if (envDllPath && envDllPath.length > 0) {
    return envDllPath
  }

  const isPackaged = typeof process['resourcesPath'] !== 'undefined'
  const baseResourcesPath = isPackaged ? process.resourcesPath : join(process.cwd(), 'resources')

  const candidates = [
    process.env.WCDB_RESOURCES_PATH ? join(process.env.WCDB_RESOURCES_PATH, subDir, libName) : null,
    resourcesPath ? join(resourcesPath, subDir, libName) : null,
    join(baseResourcesPath, 'resources', subDir, libName),
    join(baseResourcesPath, subDir, libName),
    join(process.cwd(), 'resources', subDir, libName)
  ].filter(Boolean) as string[]

  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate
  }

  return candidates[0] || libName
}

function readNativeLogs(bindings: Partial<WcdbDllCompatBindings> | null | undefined): string[] {
  try {
    if (!bindings?.wcdbGetLogs || !bindings.koffi) return []
    const outPtr = [null as any]
    const result = bindings.wcdbGetLogs(outPtr)
    if (result !== 0 || !outPtr[0]) return []

    let jsonStr = ''
    try {
      jsonStr = bindings.koffi.decode(outPtr[0], 'char', -1)
    } finally {
      try { bindings.wcdbFreeString?.(outPtr[0]) } catch {}
    }

    if (!jsonStr) return []
    try {
      const parsed = JSON.parse(jsonStr)
      if (Array.isArray(parsed)) {
        return parsed.map((item) => String(item || '')).filter(Boolean)
      }
    } catch {}

    return [jsonStr]
  } catch {
    return []
  }
}

function describeDllInitFailure(initResult: number, logs: string[]): string {
  const joined = logs.join(' | ')
  const lower = joined.toLowerCase()
  const execName = basename(process.execPath || process.argv[0] || '')

  if (lower.includes('expired: self-destruct triggered')) {
    return `WCDB DLL 已过期并触发自毁（错误码: ${initResult}，进程: ${execName}）。当前 resources/wcdb_api.dll 已不可用，需要替换 DLL 或彻底切到纯自有实现。`
  }

  if (lower.includes('securitystatus:2') || lower.includes('security verification failed')) {
    return `WCDB DLL 安全校验失败（错误码: ${initResult}，进程: ${execName}）。当前进程名或运行形态未通过 DLL 校验。`
  }

  if (joined) {
    return `WCDB 初始化失败（错误码: ${initResult}）。原生日志: ${joined}`
  }

  return `初始化失败（错误码: ${initResult}）`
}

function loadOptionalFunc(lib: any, signature: string): any {
  try {
    return lib.func(signature)
  } catch {
    return null
  }
}

function buildBindings(lib: any, koffi: any, writeLog: WriteLog): WcdbDllCompatBindings {
  const bindings: WcdbDllCompatBindings = {
    lib,
    koffi,
    wcdbInitProtection: null,
    wcdbInit: lib.func('int32 wcdb_init()'),
    wcdbShutdown: lib.func('int32 wcdb_shutdown()'),
    wcdbOpenAccount: lib.func('int32 wcdb_open_account(const char* path, const char* key, _Out_ int64* handle)'),
    wcdbCloseAccount: lib.func('int32 wcdb_close_account(int64 handle)'),
    wcdbSetMyWxid: loadOptionalFunc(lib, 'int32 wcdb_set_my_wxid(int64 handle, const char* wxid)'),
    wcdbFreeString: lib.func('void wcdb_free_string(void* ptr)'),
    wcdbUpdateMessage: loadOptionalFunc(lib, 'int32 wcdb_update_message(int64 handle, const char* sessionId, int64 localId, int32 createTime, const char* newContent, _Out_ void** outError)'),
    wcdbDeleteMessage: loadOptionalFunc(lib, 'int32 wcdb_delete_message(int64 handle, const char* sessionId, int64 localId, int32 createTime, const char* dbPathHint, _Out_ void** outError)'),
    wcdbGetSessions: lib.func('int32 wcdb_get_sessions(int64 handle, _Out_ void** outJson)'),
    wcdbGetMessages: lib.func('int32 wcdb_get_messages(int64 handle, const char* username, int32 limit, int32 offset, _Out_ void** outJson)'),
    wcdbGetMessageCount: lib.func('int32 wcdb_get_message_count(int64 handle, const char* username, _Out_ int32* outCount)'),
    wcdbGetDisplayNames: lib.func('int32 wcdb_get_display_names(int64 handle, const char* usernamesJson, _Out_ void** outJson)'),
    wcdbGetAvatarUrls: lib.func('int32 wcdb_get_avatar_urls(int64 handle, const char* usernamesJson, _Out_ void** outJson)'),
    wcdbGetGroupMemberCount: lib.func('int32 wcdb_get_group_member_count(int64 handle, const char* chatroomId, _Out_ int32* outCount)'),
    wcdbGetGroupMemberCounts: loadOptionalFunc(lib, 'int32 wcdb_get_group_member_counts(int64 handle, const char* chatroomIdsJson, _Out_ void** outJson)'),
    wcdbGetGroupMembers: lib.func('int32 wcdb_get_group_members(int64 handle, const char* chatroomId, _Out_ void** outJson)'),
    wcdbGetGroupNicknames: loadOptionalFunc(lib, 'int32 wcdb_get_group_nicknames(int64 handle, const char* chatroomId, _Out_ void** outJson)'),
    wcdbGetMessageTables: lib.func('int32 wcdb_get_message_tables(int64 handle, const char* sessionId, _Out_ void** outJson)'),
    wcdbGetMessageMeta: lib.func('int32 wcdb_get_message_meta(int64 handle, const char* dbPath, const char* tableName, int32 limit, int32 offset, _Out_ void** outJson)'),
    wcdbGetContact: lib.func('int32 wcdb_get_contact(int64 handle, const char* username, _Out_ void** outJson)'),
    wcdbGetContactStatus: loadOptionalFunc(lib, 'int32 wcdb_get_contact_status(int64 handle, const char* usernamesJson, _Out_ void** outJson)'),
    wcdbGetMessageTableStats: lib.func('int32 wcdb_get_message_table_stats(int64 handle, const char* sessionId, _Out_ void** outJson)'),
    wcdbGetAggregateStats: lib.func('int32 wcdb_get_aggregate_stats(int64 handle, const char* sessionIdsJson, int32 begin, int32 end, _Out_ void** outJson)'),
    wcdbGetAvailableYears: loadOptionalFunc(lib, 'int32 wcdb_get_available_years(int64 handle, const char* sessionIdsJson, _Out_ void** outJson)'),
    wcdbGetAnnualReportStats: loadOptionalFunc(lib, 'int32 wcdb_get_annual_report_stats(int64 handle, const char* sessionIdsJson, int32 begin, int32 end, _Out_ void** outJson)'),
    wcdbGetAnnualReportExtras: loadOptionalFunc(lib, 'int32 wcdb_get_annual_report_extras(int64 handle, const char* sessionIdsJson, int32 begin, int32 end, int32 peakBegin, int32 peakEnd, _Out_ void** outJson)'),
    wcdbGetDualReportStats: loadOptionalFunc(lib, 'int32 wcdb_get_dual_report_stats(int64 handle, const char* sessionId, int32 begin, int32 end, _Out_ void** outJson)'),
    wcdbGetGroupStats: loadOptionalFunc(lib, 'int32 wcdb_get_group_stats(int64 handle, const char* chatroomId, int32 begin, int32 end, _Out_ void** outJson)'),
    wcdbGetMessageDates: loadOptionalFunc(lib, 'int32 wcdb_get_message_dates(int64 handle, const char* sessionId, _Out_ void** outJson)'),
    wcdbOpenMessageCursor: lib.func('int32 wcdb_open_message_cursor(int64 handle, const char* sessionId, int32 batchSize, int32 ascending, int32 beginTimestamp, int32 endTimestamp, _Out_ int64* outCursor)'),
    wcdbOpenMessageCursorLite: loadOptionalFunc(lib, 'int32 wcdb_open_message_cursor_lite(int64 handle, const char* sessionId, int32 batchSize, int32 ascending, int32 beginTimestamp, int32 endTimestamp, _Out_ int64* outCursor)'),
    wcdbFetchMessageBatch: lib.func('int32 wcdb_fetch_message_batch(int64 handle, int64 cursor, _Out_ void** outJson, _Out_ int32* outHasMore)'),
    wcdbCloseMessageCursor: lib.func('int32 wcdb_close_message_cursor(int64 handle, int64 cursor)'),
    wcdbGetLogs: loadOptionalFunc(lib, 'int32 wcdb_get_logs(_Out_ void** outJson)'),
    wcdbExecQuery: lib.func('int32 wcdb_exec_query(int64 handle, const char* kind, const char* path, const char* sql, _Out_ void** outJson)'),
    wcdbListMessageDbs: lib.func('int32 wcdb_list_message_dbs(int64 handle, _Out_ void** outJson)'),
    wcdbListMediaDbs: lib.func('int32 wcdb_list_media_dbs(int64 handle, _Out_ void** outJson)'),
    wcdbGetMessageById: lib.func('int32 wcdb_get_message_by_id(int64 handle, const char* sessionId, int32 localId, _Out_ void** outJson)'),
    wcdbGetEmoticonCdnUrl: lib.func('int32 wcdb_get_emoticon_cdn_url(int64 handle, const char* dbPath, const char* md5, _Out_ void** outUrl)'),
    wcdbGetDbStatus: loadOptionalFunc(lib, 'int32 wcdb_get_db_status(int64 handle, _Out_ void** outJson)'),
    wcdbGetVoiceData: loadOptionalFunc(lib, 'int32 wcdb_get_voice_data(int64 handle, const char* sessionId, int32 createTime, int32 localId, int64 svrId, const char* candidatesJson, _Out_ void** outHex)'),
    wcdbSearchMessages: loadOptionalFunc(lib, 'int32 wcdb_search_messages(int64 handle, const char* sessionId, const char* keyword, int32 limit, int32 offset, int32 beginTimestamp, int32 endTimestamp, _Out_ void** outJson)'),
    wcdbGetSnsTimeline: loadOptionalFunc(lib, 'int32 wcdb_get_sns_timeline(int64 handle, int32 limit, int32 offset, const char* username, const char* keyword, int32 startTime, int32 endTime, _Out_ void** outJson)'),
    wcdbGetSnsAnnualStats: loadOptionalFunc(lib, 'int32 wcdb_get_sns_annual_stats(int64 handle, int32 begin, int32 end, _Out_ void** outJson)'),
    wcdbInstallSnsBlockDeleteTrigger: loadOptionalFunc(lib, 'int32 wcdb_install_sns_block_delete_trigger(int64 handle, _Out_ void** outError)'),
    wcdbUninstallSnsBlockDeleteTrigger: loadOptionalFunc(lib, 'int32 wcdb_uninstall_sns_block_delete_trigger(int64 handle, _Out_ void** outError)'),
    wcdbCheckSnsBlockDeleteTrigger: loadOptionalFunc(lib, 'int32 wcdb_check_sns_block_delete_trigger(int64 handle, _Out_ int32* outInstalled)'),
    wcdbDeleteSnsPost: loadOptionalFunc(lib, 'int32 wcdb_delete_sns_post(int64 handle, const char* postId, _Out_ void** outError)'),
    wcdbVerifyUser: loadOptionalFunc(lib, 'void VerifyUser(int64 hwnd, const char* message, _Out_ char* outResult, int maxLen)'),
    wcdbStartMonitorPipe: null,
    wcdbStopMonitorPipe: null,
    wcdbGetMonitorPipeName: null,
    wcdbCloudInit: loadOptionalFunc(lib, 'int32 wcdb_cloud_init(int32 intervalSeconds)'),
    wcdbCloudReport: loadOptionalFunc(lib, 'int32 wcdb_cloud_report(const char* statsJson)'),
    wcdbCloudStop: loadOptionalFunc(lib, 'void wcdb_cloud_stop()')
  }

  try {
    bindings.wcdbStartMonitorPipe = lib.func('int32 wcdb_start_monitor_pipe()')
    bindings.wcdbStopMonitorPipe = lib.func('void wcdb_stop_monitor_pipe()')
    bindings.wcdbGetMonitorPipeName = lib.func('int32 wcdb_get_monitor_pipe_name(_Out_ void** outName)')
    writeLog('Monitor pipe functions loaded')
  } catch (error) {
    console.warn('Failed to load monitor pipe functions:', error)
    writeLog(`Monitor pipe functions unavailable: ${String(error)}`, true)
  }

  return bindings
}

export function readWcdbDllCompatLogs(bindings: Partial<WcdbDllCompatBindings> | null | undefined): string[] {
  return readNativeLogs(bindings)
}

export function initializeWcdbDllCompat(options: InitOptions): WcdbDllCompatInitResult {
  const { resourcesPath, writeLog } = options

  try {
    const koffi = require('koffi')
    const dllPath = getDllPath(resourcesPath)
    writeLog(
      `[bootstrap] initialize platform=${process.platform} execPath=${process.execPath || ''} dllPath=${dllPath} resourcesPath=${resourcesPath || ''}`,
      true
    )

    if (!existsSync(dllPath)) {
      return {
        kind: 'missing',
        dllPath,
        error: `WCDB DLL 文件缺失（${dllPath}）。已切换到自有 fallback，可继续读取和导出。`
      }
    }

    const dllDir = dirname(dllPath)
    const isMac = process.platform === 'darwin'

    if (isMac) {
      const wcdbCorePath = join(dllDir, 'libWCDB.dylib')
      if (existsSync(wcdbCorePath)) {
        try {
          koffi.load(wcdbCorePath)
          writeLog('预加载 libWCDB.dylib 成功')
        } catch (error) {
          console.warn('预加载 libWCDB.dylib 失败(可能不是致命的):', error)
          writeLog(`预加载 libWCDB.dylib 失败: ${String(error)}`)
        }
      }
    } else {
      const wcdbCorePath = join(dllDir, 'WCDB.dll')
      if (existsSync(wcdbCorePath)) {
        try {
          koffi.load(wcdbCorePath)
          writeLog('预加载 WCDB.dll 成功')
        } catch (error) {
          console.warn('预加载 WCDB.dll 失败(可能不是致命的):', error)
          writeLog(`预加载 WCDB.dll 失败: ${String(error)}`)
        }
      }

      const sdl2Path = join(dllDir, 'SDL2.dll')
      if (existsSync(sdl2Path)) {
        try {
          koffi.load(sdl2Path)
          writeLog('预加载 SDL2.dll 成功')
        } catch (error) {
          console.warn('预加载 SDL2.dll 失败(可能不是致命的):', error)
          writeLog(`预加载 SDL2.dll 失败: ${String(error)}`)
        }
      }
    }

    const lib = koffi.load(dllPath)
    const bindings = buildBindings(lib, koffi, writeLog)

    try {
      bindings.wcdbInitProtection = lib.func('bool InitProtection(const char* resourcePath)')
      const resourcePaths = [
        dllDir,
        dirname(dllDir),
        process.resourcesPath,
        process.resourcesPath ? join(process.resourcesPath as string, 'resources') : null,
        resourcesPath,
        join(process.cwd(), 'resources')
      ].filter(Boolean)

      let protectionOk = false
      for (const resourcePath of resourcePaths) {
        try {
          protectionOk = bindings.wcdbInitProtection(resourcePath)
          writeLog(`[bootstrap] InitProtection(${resourcePath}) => ${protectionOk ? 'ok' : 'fail'}`, true)
          if (protectionOk) break
        } catch (error) {
          writeLog(`[bootstrap] InitProtection exception (${resourcePath}): ${String(error)}`, true)
        }
      }

      if (!protectionOk) {
        writeLog('[bootstrap] InitProtection failed for all candidate paths, continuing anyway', true)
      }
    } catch (error) {
      writeLog(`[bootstrap] InitProtection symbol unavailable: ${String(error)}`, true)
    }

    const initResult = bindings.wcdbInit()
    writeLog(`[bootstrap] wcdb_init() => ${initResult}`, true)
    if (initResult !== 0) {
      const initLogs = readNativeLogs(bindings)
      if (initLogs.length > 0) {
        writeLog(`[bootstrap] wcdb_init logs=${JSON.stringify(initLogs)}`, true)
      }
      return {
        kind: 'init_failed',
        bindings,
        dllPath,
        initResult,
        initLogs,
        error: describeDllInitFailure(initResult, initLogs)
      }
    }

    return { kind: 'ready', bindings, dllPath }
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error)
    return { kind: 'exception', error: errorMsg }
  }
}
