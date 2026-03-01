import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useLocation } from 'react-router-dom'
import {
  Aperture,
  ChevronDown,
  ChevronRight,
  CheckSquare,
  Download,
  ExternalLink,
  FolderOpen,
  Image as ImageIcon,
  Loader2,
  MessageSquareText,
  Mic,
  Search,
  Square,
  Video,
  WandSparkles,
  X
} from 'lucide-react'
import type { ChatSession as AppChatSession, ContactInfo } from '../types/models'
import type { ExportOptions as ElectronExportOptions, ExportProgress } from '../types/electron'
import * as configService from '../services/config'
import './ExportPage.scss'

type ConversationTab = 'private' | 'group' | 'official' | 'former_friend'
type TaskStatus = 'queued' | 'running' | 'success' | 'error'
type TaskScope = 'single' | 'multi' | 'content' | 'sns'
type ContentType = 'text' | 'voice' | 'image' | 'video' | 'emoji'
type ContentCardType = ContentType | 'sns'

type SessionLayout = 'shared' | 'per-session'

type DisplayNamePreference = 'group-nickname' | 'remark' | 'nickname'

type TextExportFormat = 'chatlab' | 'chatlab-jsonl' | 'json' | 'html' | 'txt' | 'excel' | 'weclone' | 'sql'

interface ExportOptions {
  format: TextExportFormat
  dateRange: { start: Date; end: Date } | null
  useAllTime: boolean
  exportAvatars: boolean
  exportMedia: boolean
  exportImages: boolean
  exportVoices: boolean
  exportVideos: boolean
  exportEmojis: boolean
  exportVoiceAsText: boolean
  excelCompactColumns: boolean
  txtColumns: string[]
  displayNamePreference: DisplayNamePreference
  exportConcurrency: number
}

interface SessionRow extends AppChatSession {
  kind: ConversationTab
  wechatId?: string
}

interface SessionMetrics {
  totalMessages?: number
  voiceMessages?: number
  imageMessages?: number
  videoMessages?: number
  emojiMessages?: number
  privateMutualGroups?: number
  groupMemberCount?: number
  groupMyMessages?: number
  groupActiveSpeakers?: number
  groupMutualFriends?: number
  firstTimestamp?: number
  lastTimestamp?: number
}

interface TaskProgress {
  current: number
  total: number
  currentName: string
  phaseLabel: string
  phaseProgress: number
  phaseTotal: number
}

interface ExportTaskPayload {
  sessionIds: string[]
  outputDir: string
  options?: ElectronExportOptions
  scope: TaskScope
  contentType?: ContentType
  sessionNames: string[]
  snsOptions?: {
    format: 'json' | 'html'
    exportMedia?: boolean
    startTime?: number
    endTime?: number
  }
}

interface ExportTask {
  id: string
  title: string
  status: TaskStatus
  createdAt: number
  startedAt?: number
  finishedAt?: number
  error?: string
  payload: ExportTaskPayload
  progress: TaskProgress
}

interface ExportDialogState {
  open: boolean
  scope: TaskScope
  contentType?: ContentType
  sessionIds: string[]
  sessionNames: string[]
  title: string
}

const defaultTxtColumns = ['index', 'time', 'senderRole', 'messageType', 'content']
const contentTypeLabels: Record<ContentType, string> = {
  text: '聊天文本',
  voice: '语音',
  image: '图片',
  video: '视频',
  emoji: '表情包'
}

const formatOptions: Array<{ value: TextExportFormat; label: string; desc: string }> = [
  { value: 'chatlab', label: 'ChatLab', desc: '标准格式，支持其他软件导入' },
  { value: 'chatlab-jsonl', label: 'ChatLab JSONL', desc: '流式格式，适合大量消息' },
  { value: 'json', label: 'JSON', desc: '详细格式，包含完整消息信息' },
  { value: 'html', label: 'HTML', desc: '网页格式，可直接浏览' },
  { value: 'txt', label: 'TXT', desc: '纯文本，通用格式' },
  { value: 'excel', label: 'Excel', desc: '电子表格，适合统计分析' },
  { value: 'weclone', label: 'WeClone CSV', desc: 'WeClone 兼容字段格式（CSV）' },
  { value: 'sql', label: 'PostgreSQL', desc: '数据库脚本，便于导入到数据库' }
]

const displayNameOptions: Array<{ value: DisplayNamePreference; label: string; desc: string }> = [
  { value: 'group-nickname', label: '群昵称优先', desc: '仅群聊有效，私聊显示备注/昵称' },
  { value: 'remark', label: '备注优先', desc: '有备注显示备注，否则显示昵称' },
  { value: 'nickname', label: '微信昵称', desc: '始终显示微信昵称' }
]

const writeLayoutOptions: Array<{ value: configService.ExportWriteLayout; label: string; desc: string }> = [
  {
    value: 'A',
    label: 'A（类型分目录）',
    desc: '聊天文本、语音、视频、表情包、图片分别创建文件夹'
  },
  {
    value: 'B',
    label: 'B（文本根目录+媒体按会话）',
    desc: '聊天文本在根目录；媒体按类型目录后再按会话分目录'
  },
  {
    value: 'C',
    label: 'C（按会话分目录）',
    desc: '每个会话一个目录，目录内包含文本与媒体文件'
  }
]

const createEmptyProgress = (): TaskProgress => ({
  current: 0,
  total: 0,
  currentName: '',
  phaseLabel: '',
  phaseProgress: 0,
  phaseTotal: 0
})

const formatAbsoluteDate = (timestamp: number): string => {
  const d = new Date(timestamp)
  const y = d.getFullYear()
  const m = `${d.getMonth() + 1}`.padStart(2, '0')
  const day = `${d.getDate()}`.padStart(2, '0')
  return `${y}-${m}-${day}`
}

const formatRecentExportTime = (timestamp?: number, now = Date.now()): string => {
  if (!timestamp) return ''
  const diff = Math.max(0, now - timestamp)
  const minute = 60 * 1000
  const hour = 60 * minute
  const day = 24 * hour
  if (diff < hour) {
    const minutes = Math.max(1, Math.floor(diff / minute))
    return `${minutes} 分钟前`
  }
  if (diff < day) {
    const hours = Math.max(1, Math.floor(diff / hour))
    return `${hours} 小时前`
  }
  return formatAbsoluteDate(timestamp)
}

const formatDateInputValue = (date: Date): string => {
  const y = date.getFullYear()
  const m = `${date.getMonth() + 1}`.padStart(2, '0')
  const d = `${date.getDate()}`.padStart(2, '0')
  return `${y}-${m}-${d}`
}

const parseDateInput = (value: string, endOfDay: boolean): Date => {
  const [year, month, day] = value.split('-').map(v => Number(v))
  const date = new Date(year, month - 1, day)
  if (endOfDay) {
    date.setHours(23, 59, 59, 999)
  } else {
    date.setHours(0, 0, 0, 0)
  }
  return date
}

const toKindByContactType = (session: AppChatSession, contact?: ContactInfo): ConversationTab => {
  if (session.username.endsWith('@chatroom')) return 'group'
  if (contact?.type === 'official') return 'official'
  if (contact?.type === 'former_friend') return 'former_friend'
  return 'private'
}

const getAvatarLetter = (name: string): string => {
  if (!name) return '?'
  return [...name][0] || '?'
}

const valueOrDash = (value?: number): string => {
  if (value === undefined || value === null) return '--'
  return value.toLocaleString()
}

const timestampOrDash = (timestamp?: number): string => {
  if (!timestamp) return '--'
  return formatAbsoluteDate(timestamp * 1000)
}

const createTaskId = (): string => `task-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`

function ExportPage() {
  const location = useLocation()

  const [isLoading, setIsLoading] = useState(true)
  const [isSessionEnriching, setIsSessionEnriching] = useState(false)
  const [isTabCountsLoading, setIsTabCountsLoading] = useState(true)
  const [isSnsStatsLoading, setIsSnsStatsLoading] = useState(true)
  const [isBaseConfigLoading, setIsBaseConfigLoading] = useState(true)
  const [isTaskCenterExpanded, setIsTaskCenterExpanded] = useState(false)
  const [sessions, setSessions] = useState<SessionRow[]>([])
  const [prefetchedTabCounts, setPrefetchedTabCounts] = useState<Record<ConversationTab, number> | null>(null)
  const [sessionMetrics, setSessionMetrics] = useState<Record<string, SessionMetrics>>({})
  const [searchKeyword, setSearchKeyword] = useState('')
  const [activeTab, setActiveTab] = useState<ConversationTab>('private')
  const [selectedSessions, setSelectedSessions] = useState<Set<string>>(new Set())

  const [exportFolder, setExportFolder] = useState('')
  const [writeLayout, setWriteLayout] = useState<configService.ExportWriteLayout>('A')
  const [showWriteLayoutSelect, setShowWriteLayoutSelect] = useState(false)

  const [options, setOptions] = useState<ExportOptions>({
    format: 'excel',
    dateRange: {
      start: new Date(new Date().setHours(0, 0, 0, 0)),
      end: new Date()
    },
    useAllTime: false,
    exportAvatars: true,
    exportMedia: false,
    exportImages: true,
    exportVoices: true,
    exportVideos: true,
    exportEmojis: true,
    exportVoiceAsText: false,
    excelCompactColumns: true,
    txtColumns: defaultTxtColumns,
    displayNamePreference: 'remark',
    exportConcurrency: 2
  })

  const [exportDialog, setExportDialog] = useState<ExportDialogState>({
    open: false,
    scope: 'single',
    sessionIds: [],
    sessionNames: [],
    title: ''
  })

  const [tasks, setTasks] = useState<ExportTask[]>([])
  const [lastExportBySession, setLastExportBySession] = useState<Record<string, number>>({})
  const [lastExportByContent, setLastExportByContent] = useState<Record<string, number>>({})
  const [lastSnsExportPostCount, setLastSnsExportPostCount] = useState(0)
  const [snsStats, setSnsStats] = useState<{ totalPosts: number; totalFriends: number }>({
    totalPosts: 0,
    totalFriends: 0
  })
  const [nowTick, setNowTick] = useState(Date.now())

  const progressUnsubscribeRef = useRef<(() => void) | null>(null)
  const runningTaskIdRef = useRef<string | null>(null)
  const tasksRef = useRef<ExportTask[]>([])
  const sessionMetricsRef = useRef<Record<string, SessionMetrics>>({})
  const sessionLoadTokenRef = useRef(0)
  const loadingMetricsRef = useRef<Set<string>>(new Set())
  const preselectAppliedRef = useRef(false)
  const writeLayoutControlRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    tasksRef.current = tasks
  }, [tasks])

  useEffect(() => {
    sessionMetricsRef.current = sessionMetrics
  }, [sessionMetrics])

  const preselectSessionIds = useMemo(() => {
    const state = location.state as { preselectSessionIds?: unknown; preselectSessionId?: unknown } | null
    const rawList = Array.isArray(state?.preselectSessionIds)
      ? state?.preselectSessionIds
      : (typeof state?.preselectSessionId === 'string' ? [state.preselectSessionId] : [])

    return rawList
      .filter((item): item is string => typeof item === 'string')
      .map(item => item.trim())
      .filter(Boolean)
  }, [location.state])

  useEffect(() => {
    const timer = setInterval(() => setNowTick(Date.now()), 60 * 1000)
    return () => clearInterval(timer)
  }, [])

  const loadBaseConfig = useCallback(async () => {
    setIsBaseConfigLoading(true)
    try {
      const [savedPath, savedFormat, savedMedia, savedVoiceAsText, savedExcelCompactColumns, savedTxtColumns, savedConcurrency, savedWriteLayout, savedSessionMap, savedContentMap, savedSnsPostCount] = await Promise.all([
        configService.getExportPath(),
        configService.getExportDefaultFormat(),
        configService.getExportDefaultMedia(),
        configService.getExportDefaultVoiceAsText(),
        configService.getExportDefaultExcelCompactColumns(),
        configService.getExportDefaultTxtColumns(),
        configService.getExportDefaultConcurrency(),
        configService.getExportWriteLayout(),
        configService.getExportLastSessionRunMap(),
        configService.getExportLastContentRunMap(),
        configService.getExportLastSnsPostCount()
      ])

      if (savedPath) {
        setExportFolder(savedPath)
      } else {
        const downloadsPath = await window.electronAPI.app.getDownloadsPath()
        setExportFolder(downloadsPath)
      }

      setWriteLayout(savedWriteLayout)
      setLastExportBySession(savedSessionMap)
      setLastExportByContent(savedContentMap)
      setLastSnsExportPostCount(savedSnsPostCount)

      const txtColumns = savedTxtColumns && savedTxtColumns.length > 0 ? savedTxtColumns : defaultTxtColumns
      setOptions(prev => ({
        ...prev,
        format: (savedFormat as TextExportFormat) || prev.format,
        exportMedia: savedMedia ?? prev.exportMedia,
        exportVoiceAsText: savedVoiceAsText ?? prev.exportVoiceAsText,
        excelCompactColumns: savedExcelCompactColumns ?? prev.excelCompactColumns,
        txtColumns,
        exportConcurrency: savedConcurrency ?? prev.exportConcurrency
      }))
    } catch (error) {
      console.error('加载导出配置失败:', error)
    } finally {
      setIsBaseConfigLoading(false)
    }
  }, [])

  const loadTabCounts = useCallback(async () => {
    setIsTabCountsLoading(true)
    try {
      const result = await window.electronAPI.chat.getExportTabCounts()
      if (result.success && result.counts) {
        setPrefetchedTabCounts(result.counts)
      }
    } catch (error) {
      console.error('加载导出页会话分类数量失败:', error)
    } finally {
      setIsTabCountsLoading(false)
    }
  }, [])

  const loadSnsStats = useCallback(async () => {
    setIsSnsStatsLoading(true)
    try {
      const result = await window.electronAPI.sns.getExportStats()
      if (result.success && result.data) {
        setSnsStats({
          totalPosts: result.data.totalPosts || 0,
          totalFriends: result.data.totalFriends || 0
        })
      }
    } catch (error) {
      console.error('加载朋友圈导出统计失败:', error)
    } finally {
      setIsSnsStatsLoading(false)
    }
  }, [])

  const loadSessions = useCallback(async () => {
    const loadToken = Date.now()
    sessionLoadTokenRef.current = loadToken
    setIsLoading(true)
    setIsSessionEnriching(false)

    const isStale = () => sessionLoadTokenRef.current !== loadToken

    try {
      const connectResult = await window.electronAPI.chat.connect()
      if (!connectResult.success) {
        console.error('连接失败:', connectResult.error)
        if (!isStale()) setIsLoading(false)
        return
      }

      const sessionsResult = await window.electronAPI.chat.getSessions()
      if (isStale()) return

      if (sessionsResult.success && sessionsResult.sessions) {
        const baseSessions = sessionsResult.sessions
          .map((session) => {
            return {
              ...session,
              kind: toKindByContactType(session),
              wechatId: session.username,
              displayName: session.displayName || session.username,
              avatarUrl: session.avatarUrl
            } as SessionRow
          })
          .sort((a, b) => (b.sortTimestamp || b.lastTimestamp || 0) - (a.sortTimestamp || a.lastTimestamp || 0))

        if (isStale()) return
        setSessions(baseSessions)
        setIsLoading(false)

        // 后台补齐联系人字段（昵称、头像、类型），不阻塞首屏会话列表渲染。
        setIsSessionEnriching(true)
        void (async () => {
          try {
            const contactsResult = await window.electronAPI.chat.getContacts()
            if (isStale()) return

            const contacts: ContactInfo[] = contactsResult.success && contactsResult.contacts ? contactsResult.contacts : []
            const nextContactMap = contacts.reduce<Record<string, ContactInfo>>((map, contact) => {
              map[contact.username] = contact
              return map
            }, {})

            const needsEnrichment = baseSessions
              .filter(session => !session.avatarUrl || !session.displayName || session.displayName === session.username)
              .map(session => session.username)

            let extraContactMap: Record<string, { displayName?: string; avatarUrl?: string }> = {}
            if (needsEnrichment.length > 0) {
              const enrichResult = await window.electronAPI.chat.enrichSessionsContactInfo(needsEnrichment)
              if (enrichResult.success && enrichResult.contacts) {
                extraContactMap = enrichResult.contacts
              }
            }

            if (isStale()) return
            const nextSessions = baseSessions
              .map((session) => {
                const contact = nextContactMap[session.username]
                const extra = extraContactMap[session.username]
                const displayName = extra?.displayName || contact?.displayName || session.displayName || session.username
                const avatarUrl = extra?.avatarUrl || session.avatarUrl || contact?.avatarUrl
                return {
                  ...session,
                  kind: toKindByContactType(session, contact),
                  wechatId: contact?.username || session.wechatId || session.username,
                  displayName,
                  avatarUrl
                }
              })
              .sort((a, b) => {
                const aMetric = sessionMetricsRef.current[a.username]?.totalMessages ?? 0
                const bMetric = sessionMetricsRef.current[b.username]?.totalMessages ?? 0
                if (bMetric !== aMetric) return bMetric - aMetric
                return (b.sortTimestamp || b.lastTimestamp || 0) - (a.sortTimestamp || a.lastTimestamp || 0)
              })

            setSessions(nextSessions)
          } catch (enrichError) {
            console.error('导出页补充会话联系人信息失败:', enrichError)
          } finally {
            if (!isStale()) setIsSessionEnriching(false)
          }
        })()
      } else {
        setIsLoading(false)
      }
    } catch (error) {
      console.error('加载会话失败:', error)
      if (!isStale()) setIsLoading(false)
    } finally {
      if (!isStale()) setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadBaseConfig()
    void (async () => {
      await loadTabCounts()
      await loadSessions()
    })()

    // 朋友圈统计延后一点加载，避免与首屏会话初始化抢占。
    const timer = window.setTimeout(() => {
      void loadSnsStats()
    }, 180)

    return () => window.clearTimeout(timer)
  }, [loadTabCounts, loadBaseConfig, loadSessions, loadSnsStats])

  useEffect(() => {
    preselectAppliedRef.current = false
  }, [location.key, preselectSessionIds])

  useEffect(() => {
    if (!showWriteLayoutSelect) return

    const handleOutsideClick = (event: MouseEvent) => {
      if (writeLayoutControlRef.current?.contains(event.target as Node)) return
      setShowWriteLayoutSelect(false)
    }

    document.addEventListener('mousedown', handleOutsideClick)
    return () => document.removeEventListener('mousedown', handleOutsideClick)
  }, [showWriteLayoutSelect])

  useEffect(() => {
    if (preselectAppliedRef.current) return
    if (sessions.length === 0 || preselectSessionIds.length === 0) return

    const exists = new Set(sessions.map(session => session.username))
    const matched = preselectSessionIds.filter(id => exists.has(id))
    preselectAppliedRef.current = true

    if (matched.length > 0) {
      setSelectedSessions(new Set(matched))
    }
  }, [sessions, preselectSessionIds])

  const visibleSessions = useMemo(() => {
    const keyword = searchKeyword.trim().toLowerCase()
    return sessions
      .filter((session) => {
        if (session.kind !== activeTab) return false
        if (!keyword) return true
        return (
          (session.displayName || '').toLowerCase().includes(keyword) ||
          session.username.toLowerCase().includes(keyword)
        )
      })
      .sort((a, b) => {
        const totalA = sessionMetrics[a.username]?.totalMessages ?? 0
        const totalB = sessionMetrics[b.username]?.totalMessages ?? 0
        if (totalB !== totalA) {
          return totalB - totalA
        }

        const latestA = sessionMetrics[a.username]?.lastTimestamp ?? a.lastTimestamp ?? 0
        const latestB = sessionMetrics[b.username]?.lastTimestamp ?? b.lastTimestamp ?? 0
        return latestB - latestA
      })
  }, [sessions, activeTab, searchKeyword, sessionMetrics])

  const ensureSessionMetrics = useCallback(async (targetSessions: SessionRow[]) => {
    const currentMetrics = sessionMetricsRef.current
    const pending = targetSessions.filter(session => !currentMetrics[session.username] && !loadingMetricsRef.current.has(session.username))
    if (pending.length === 0) return

    const updates: Record<string, SessionMetrics> = {}
    for (const session of pending) {
      loadingMetricsRef.current.add(session.username)
      updates[session.username] = {}
    }

    try {
      const statsResult = await window.electronAPI.chat.getExportSessionStats(pending.map(session => session.username))
      if (statsResult.success && statsResult.data) {
        for (const session of pending) {
          const raw = statsResult.data[session.username]
          if (!raw) continue
          updates[session.username] = {
            totalMessages: raw.totalMessages,
            voiceMessages: raw.voiceMessages,
            imageMessages: raw.imageMessages,
            videoMessages: raw.videoMessages,
            emojiMessages: raw.emojiMessages,
            privateMutualGroups: raw.privateMutualGroups,
            groupMemberCount: raw.groupMemberCount,
            groupMyMessages: raw.groupMyMessages,
            groupActiveSpeakers: raw.groupActiveSpeakers,
            groupMutualFriends: raw.groupMutualFriends,
            firstTimestamp: raw.firstTimestamp,
            lastTimestamp: raw.lastTimestamp
          }
        }
      }
    } catch (error) {
      console.error('加载会话统计失败:', error)
    } finally {
      for (const session of pending) {
        loadingMetricsRef.current.delete(session.username)
      }
    }

    if (Object.keys(updates).length > 0) {
      setSessionMetrics(prev => ({ ...prev, ...updates }))
    }
  }, [])

  useEffect(() => {
    const targets = visibleSessions.slice(0, 40)
    void ensureSessionMetrics(targets)
  }, [visibleSessions, ensureSessionMetrics])

  useEffect(() => {
    if (sessions.length === 0) return
    void ensureSessionMetrics(sessions)
  }, [sessions, ensureSessionMetrics])

  const selectedCount = selectedSessions.size

  const toggleSelectSession = (sessionId: string) => {
    setSelectedSessions(prev => {
      const next = new Set(prev)
      if (next.has(sessionId)) {
        next.delete(sessionId)
      } else {
        next.add(sessionId)
      }
      return next
    })
  }

  const toggleSelectAllVisible = () => {
    const visibleIds = visibleSessions.map(session => session.username)
    if (visibleIds.length === 0) return

    setSelectedSessions(prev => {
      const next = new Set(prev)
      const allSelected = visibleIds.every(id => next.has(id))
      if (allSelected) {
        for (const id of visibleIds) {
          next.delete(id)
        }
      } else {
        for (const id of visibleIds) {
          next.add(id)
        }
      }
      return next
    })
  }

  const clearSelection = () => setSelectedSessions(new Set())

  const openExportDialog = (payload: Omit<ExportDialogState, 'open'>) => {
    setExportDialog({ open: true, ...payload })

    if (payload.scope === 'sns') {
      setOptions(prev => ({
        ...prev,
        format: prev.format === 'json' || prev.format === 'html' ? prev.format : 'html'
      }))
      return
    }

    if (payload.scope === 'content' && payload.contentType) {
      if (payload.contentType === 'text') {
        setOptions(prev => ({ ...prev, exportMedia: false }))
      } else {
        setOptions(prev => ({
          ...prev,
          exportMedia: true,
          exportImages: payload.contentType === 'image',
          exportVoices: payload.contentType === 'voice',
          exportVideos: payload.contentType === 'video',
          exportEmojis: payload.contentType === 'emoji'
        }))
      }
    }
  }

  const closeExportDialog = () => {
    setExportDialog(prev => ({ ...prev, open: false }))
  }

  const buildExportOptions = (scope: TaskScope, contentType?: ContentType): ElectronExportOptions => {
    const sessionLayout: SessionLayout = writeLayout === 'C' ? 'per-session' : 'shared'

    const base: ElectronExportOptions = {
      format: options.format,
      exportAvatars: options.exportAvatars,
      exportMedia: options.exportMedia,
      exportImages: options.exportMedia && options.exportImages,
      exportVoices: options.exportMedia && options.exportVoices,
      exportVideos: options.exportMedia && options.exportVideos,
      exportEmojis: options.exportMedia && options.exportEmojis,
      exportVoiceAsText: options.exportVoiceAsText,
      excelCompactColumns: options.excelCompactColumns,
      txtColumns: options.txtColumns,
      displayNamePreference: options.displayNamePreference,
      exportConcurrency: options.exportConcurrency,
      sessionLayout,
      dateRange: options.useAllTime
        ? null
        : options.dateRange
          ? {
              start: Math.floor(options.dateRange.start.getTime() / 1000),
              end: Math.floor(options.dateRange.end.getTime() / 1000)
            }
          : null
    }

    if (scope === 'content' && contentType) {
      if (contentType === 'text') {
        return {
          ...base,
          exportMedia: false,
          exportImages: false,
          exportVoices: false,
          exportVideos: false,
          exportEmojis: false
        }
      }

      return {
        ...base,
        exportMedia: true,
        exportImages: contentType === 'image',
        exportVoices: contentType === 'voice',
        exportVideos: contentType === 'video',
        exportEmojis: contentType === 'emoji'
      }
    }

    return base
  }

  const buildSnsExportOptions = () => {
    const format: 'json' | 'html' = options.format === 'json' ? 'json' : 'html'
    const dateRange = options.useAllTime
      ? null
      : options.dateRange
        ? {
            startTime: Math.floor(options.dateRange.start.getTime() / 1000),
            endTime: Math.floor(options.dateRange.end.getTime() / 1000)
          }
        : null

    return {
      format,
      exportMedia: options.exportMedia,
      startTime: dateRange?.startTime,
      endTime: dateRange?.endTime
    }
  }

  const markSessionExported = useCallback((sessionIds: string[], timestamp: number) => {
    setLastExportBySession(prev => {
      const next = { ...prev }
      for (const id of sessionIds) {
        next[id] = timestamp
      }
      void configService.setExportLastSessionRunMap(next)
      return next
    })
  }, [])

  const markContentExported = useCallback((sessionIds: string[], contentTypes: ContentType[], timestamp: number) => {
    setLastExportByContent(prev => {
      const next = { ...prev }
      for (const id of sessionIds) {
        for (const type of contentTypes) {
          next[`${id}::${type}`] = timestamp
        }
      }
      void configService.setExportLastContentRunMap(next)
      return next
    })
  }, [])

  const inferContentTypesFromOptions = (opts: ElectronExportOptions): ContentType[] => {
    const types: ContentType[] = ['text']
    if (opts.exportMedia) {
      if (opts.exportVoices) types.push('voice')
      if (opts.exportImages) types.push('image')
      if (opts.exportVideos) types.push('video')
      if (opts.exportEmojis) types.push('emoji')
    }
    return types
  }

  const updateTask = useCallback((taskId: string, updater: (task: ExportTask) => ExportTask) => {
    setTasks(prev => prev.map(task => (task.id === taskId ? updater(task) : task)))
  }, [])

  const runNextTask = useCallback(async () => {
    if (runningTaskIdRef.current) return

    const queue = [...tasksRef.current].reverse()
    const next = queue.find(task => task.status === 'queued')
    if (!next) return

    runningTaskIdRef.current = next.id
    updateTask(next.id, task => ({ ...task, status: 'running', startedAt: Date.now() }))

    progressUnsubscribeRef.current?.()
    if (next.payload.scope === 'sns') {
      progressUnsubscribeRef.current = window.electronAPI.sns.onExportProgress((payload) => {
        updateTask(next.id, task => ({
          ...task,
          progress: {
            current: payload.current || 0,
            total: payload.total || 0,
            currentName: '',
            phaseLabel: payload.status || '',
            phaseProgress: payload.total > 0 ? payload.current : 0,
            phaseTotal: payload.total || 0
          }
        }))
      })
    } else {
      progressUnsubscribeRef.current = window.electronAPI.export.onProgress((payload: ExportProgress) => {
        updateTask(next.id, task => ({
          ...task,
          progress: {
            current: payload.current,
            total: payload.total,
            currentName: payload.currentSession,
            phaseLabel: payload.phaseLabel || '',
            phaseProgress: payload.phaseProgress || 0,
            phaseTotal: payload.phaseTotal || 0
          }
        }))
      })
    }

    try {
      if (next.payload.scope === 'sns') {
        const snsOptions = next.payload.snsOptions || { format: 'html' as const, exportMedia: false }
        const result = await window.electronAPI.sns.exportTimeline({
          outputDir: next.payload.outputDir,
          format: snsOptions.format,
          exportMedia: snsOptions.exportMedia,
          startTime: snsOptions.startTime,
          endTime: snsOptions.endTime
        })

        if (!result.success) {
          updateTask(next.id, task => ({
            ...task,
            status: 'error',
            finishedAt: Date.now(),
            error: result.error || '朋友圈导出失败'
          }))
        } else {
          const doneAt = Date.now()
          const exportedPosts = Math.max(0, result.postCount || 0)
          const mergedExportedCount = Math.max(lastSnsExportPostCount, exportedPosts)
          setLastSnsExportPostCount(mergedExportedCount)
          await configService.setExportLastSnsPostCount(mergedExportedCount)
          await loadSnsStats()

          updateTask(next.id, task => ({
            ...task,
            status: 'success',
            finishedAt: doneAt,
            progress: {
              ...task.progress,
              current: exportedPosts,
              total: exportedPosts,
              phaseLabel: '完成',
              phaseProgress: 1,
              phaseTotal: 1
            }
          }))
        }
      } else {
        if (!next.payload.options) {
          throw new Error('导出参数缺失')
        }

        const result = await window.electronAPI.export.exportSessions(
          next.payload.sessionIds,
          next.payload.outputDir,
          next.payload.options
        )

        if (!result.success) {
          updateTask(next.id, task => ({
            ...task,
            status: 'error',
            finishedAt: Date.now(),
            error: result.error || '导出失败'
          }))
        } else {
          const doneAt = Date.now()
          const contentTypes = next.payload.contentType
            ? [next.payload.contentType]
            : inferContentTypesFromOptions(next.payload.options)

          markSessionExported(next.payload.sessionIds, doneAt)
          markContentExported(next.payload.sessionIds, contentTypes, doneAt)

          updateTask(next.id, task => ({
            ...task,
            status: 'success',
            finishedAt: doneAt,
            progress: {
              ...task.progress,
              current: task.progress.total || next.payload.sessionIds.length,
              total: task.progress.total || next.payload.sessionIds.length,
              phaseLabel: '完成',
              phaseProgress: 1,
              phaseTotal: 1
            }
          }))
        }
      }
    } catch (error) {
      updateTask(next.id, task => ({
        ...task,
        status: 'error',
        finishedAt: Date.now(),
        error: String(error)
      }))
    } finally {
      progressUnsubscribeRef.current?.()
      progressUnsubscribeRef.current = null
      runningTaskIdRef.current = null
      void runNextTask()
    }
  }, [updateTask, markSessionExported, markContentExported, loadSnsStats, lastSnsExportPostCount])

  useEffect(() => {
    void runNextTask()
  }, [tasks, runNextTask])

  useEffect(() => {
    return () => {
      progressUnsubscribeRef.current?.()
      progressUnsubscribeRef.current = null
    }
  }, [])

  const createTask = async () => {
    if (!exportDialog.open || !exportFolder) return
    if (exportDialog.scope !== 'sns' && exportDialog.sessionIds.length === 0) return

    const exportOptions = exportDialog.scope === 'sns'
      ? undefined
      : buildExportOptions(exportDialog.scope, exportDialog.contentType)
    const snsOptions = exportDialog.scope === 'sns'
      ? buildSnsExportOptions()
      : undefined
    const title =
      exportDialog.scope === 'single'
        ? `${exportDialog.sessionNames[0] || '会话'} 导出`
        : exportDialog.scope === 'multi'
          ? `批量导出（${exportDialog.sessionIds.length} 个会话）`
          : exportDialog.scope === 'sns'
            ? '朋友圈批量导出'
            : `${contentTypeLabels[exportDialog.contentType || 'text']}批量导出`

    const task: ExportTask = {
      id: createTaskId(),
      title,
      status: 'queued',
      createdAt: Date.now(),
      payload: {
        sessionIds: exportDialog.sessionIds,
        sessionNames: exportDialog.sessionNames,
        outputDir: exportFolder,
        options: exportOptions,
        scope: exportDialog.scope,
        contentType: exportDialog.contentType,
        snsOptions
      },
      progress: createEmptyProgress()
    }

    setTasks(prev => [task, ...prev])
    closeExportDialog()

    await configService.setExportDefaultFormat(options.format)
    await configService.setExportDefaultMedia(options.exportMedia)
    await configService.setExportDefaultVoiceAsText(options.exportVoiceAsText)
    await configService.setExportDefaultExcelCompactColumns(options.excelCompactColumns)
    await configService.setExportDefaultTxtColumns(options.txtColumns)
    await configService.setExportDefaultConcurrency(options.exportConcurrency)
  }

  const openSingleExport = (session: SessionRow) => {
    openExportDialog({
      scope: 'single',
      sessionIds: [session.username],
      sessionNames: [session.displayName || session.username],
      title: `导出会话：${session.displayName || session.username}`
    })
  }

  const openBatchExport = () => {
    const ids = Array.from(selectedSessions)
    if (ids.length === 0) return
    const nameMap = new Map(sessions.map(session => [session.username, session.displayName || session.username]))
    const names = ids.map(id => nameMap.get(id) || id)

    openExportDialog({
      scope: 'multi',
      sessionIds: ids,
      sessionNames: names,
      title: `批量导出（${ids.length} 个会话）`
    })
  }

  const openContentExport = (contentType: ContentType) => {
    const ids = sessions
      .filter(session => session.kind === 'private' || session.kind === 'group')
      .map(session => session.username)

    const names = sessions
      .filter(session => session.kind === 'private' || session.kind === 'group')
      .map(session => session.displayName || session.username)

    openExportDialog({
      scope: 'content',
      contentType,
      sessionIds: ids,
      sessionNames: names,
      title: `${contentTypeLabels[contentType]}批量导出`
    })
  }

  const openSnsExport = () => {
    openExportDialog({
      scope: 'sns',
      sessionIds: [],
      sessionNames: ['全部朋友圈动态'],
      title: '朋友圈批量导出'
    })
  }

  const runningSessionIds = useMemo(() => {
    const set = new Set<string>()
    for (const task of tasks) {
      if (task.status !== 'running') continue
      for (const id of task.payload.sessionIds) {
        set.add(id)
      }
    }
    return set
  }, [tasks])

  const queuedSessionIds = useMemo(() => {
    const set = new Set<string>()
    for (const task of tasks) {
      if (task.status !== 'queued') continue
      for (const id of task.payload.sessionIds) {
        set.add(id)
      }
    }
    return set
  }, [tasks])

  const sessionTabCounts = useMemo(() => {
    const counts: Record<ConversationTab, number> = {
      private: 0,
      group: 0,
      official: 0,
      former_friend: 0
    }
    for (const session of sessions) {
      counts[session.kind] += 1
    }
    return counts
  }, [sessions])

  const tabCounts = useMemo(() => {
    if (sessions.length > 0) {
      return sessionTabCounts
    }
    if (prefetchedTabCounts) {
      return prefetchedTabCounts
    }
    return sessionTabCounts
  }, [sessions.length, sessionTabCounts, prefetchedTabCounts])

  const contentCards = useMemo(() => {
    const scopeSessions = sessions.filter(session => session.kind === 'private' || session.kind === 'group')
    const totalSessions = scopeSessions.length
    const snsExportedCount = Math.min(lastSnsExportPostCount, snsStats.totalPosts)

    const sessionCards = [
      { type: 'text' as ContentType, icon: MessageSquareText },
      { type: 'voice' as ContentType, icon: Mic },
      { type: 'image' as ContentType, icon: ImageIcon },
      { type: 'video' as ContentType, icon: Video },
      { type: 'emoji' as ContentType, icon: WandSparkles }
    ].map(item => {
      let exported = 0
      for (const session of scopeSessions) {
        if (lastExportByContent[`${session.username}::${item.type}`]) {
          exported += 1
        }
      }

      return {
        ...item,
        label: contentTypeLabels[item.type],
        stats: [
          { label: '总会话数', value: totalSessions },
          { label: '已导出会话数', value: exported }
        ]
      }
    })

    const snsCard = {
      type: 'sns' as ContentCardType,
      icon: Aperture,
      label: '朋友圈',
      stats: [
        { label: '朋友圈条数', value: snsStats.totalPosts },
        { label: '好友数', value: snsStats.totalFriends },
        { label: '已导出朋友圈条数', value: snsExportedCount }
      ]
    }

    return [...sessionCards, snsCard]
  }, [sessions, lastExportByContent, snsStats, lastSnsExportPostCount])

  const activeTabLabel = useMemo(() => {
    if (activeTab === 'private') return '私聊'
    if (activeTab === 'group') return '群聊'
    if (activeTab === 'former_friend') return '曾经的好友'
    return '公众号'
  }, [activeTab])

  const renderSessionName = (session: SessionRow) => {
    return (
      <div className="session-cell">
        <div className="session-avatar">
          {session.avatarUrl ? <img src={session.avatarUrl} alt="" /> : <span>{getAvatarLetter(session.displayName || session.username)}</span>}
        </div>
        <div className="session-meta">
          <div className="session-name">{session.displayName || session.username}</div>
          <div className="session-id">{session.wechatId || session.username}</div>
        </div>
      </div>
    )
  }

  const renderActionCell = (session: SessionRow) => {
    const isRunning = runningSessionIds.has(session.username)
    const isQueued = queuedSessionIds.has(session.username)
    const recent = formatRecentExportTime(lastExportBySession[session.username], nowTick)

    return (
      <div className="row-action-cell">
        <button
          className={`row-export-btn ${isRunning ? 'running' : ''}`}
          disabled={isRunning}
          onClick={() => openSingleExport(session)}
        >
          {isRunning ? (
            <>
              <Loader2 size={14} className="spin" />
              导出中
            </>
          ) : isQueued ? '排队中' : '导出'}
        </button>
        {recent && <span className="row-export-time">{recent}</span>}
      </div>
    )
  }

  const renderTableHeader = () => {
    if (activeTab === 'private' || activeTab === 'former_friend') {
      return (
        <tr>
          <th className="sticky-col">选择</th>
          <th>会话名（头像/昵称/微信号）</th>
          <th>总消息</th>
          <th>语音</th>
          <th>图片</th>
          <th>视频</th>
          <th>表情包</th>
          <th>共同群聊数</th>
          <th>最早时间</th>
          <th>最新时间</th>
          <th className="sticky-right">操作</th>
        </tr>
      )
    }

    if (activeTab === 'group') {
      return (
        <tr>
          <th className="sticky-col">选择</th>
          <th>会话名（群头像/群名称/群ID）</th>
          <th>总消息</th>
          <th>语音</th>
          <th>图片</th>
          <th>视频</th>
          <th>表情包</th>
          <th>我发的消息数</th>
          <th>群人数</th>
          <th>群发言人数</th>
          <th>群共同好友数</th>
          <th>最早时间</th>
          <th>最新时间</th>
          <th className="sticky-right">操作</th>
        </tr>
      )
    }

    return (
      <tr>
        <th className="sticky-col">选择</th>
        <th>会话名（头像/名称/微信号）</th>
        <th>总消息</th>
        <th>语音</th>
        <th>图片</th>
        <th>视频</th>
        <th>表情包</th>
        <th>最早时间</th>
        <th>最新时间</th>
        <th className="sticky-right">操作</th>
      </tr>
    )
  }

  const renderRow = (session: SessionRow) => {
    const metrics = sessionMetrics[session.username] || {}
    const checked = selectedSessions.has(session.username)

    return (
      <tr key={session.username} className={checked ? 'selected-row' : ''}>
        <td className="sticky-col">
          <button
            className={`select-icon-btn ${checked ? 'checked' : ''}`}
            onClick={() => toggleSelectSession(session.username)}
            title={checked ? '取消选择' : '选择会话'}
          >
            {checked ? <CheckSquare size={16} /> : <Square size={16} />}
          </button>
        </td>

        <td>{renderSessionName(session)}</td>
        <td>{valueOrDash(metrics.totalMessages)}</td>
        <td>{valueOrDash(metrics.voiceMessages)}</td>
        <td>{valueOrDash(metrics.imageMessages)}</td>
        <td>{valueOrDash(metrics.videoMessages)}</td>
        <td>{valueOrDash(metrics.emojiMessages)}</td>

        {(activeTab === 'private' || activeTab === 'former_friend') && (
          <>
            <td>{valueOrDash(metrics.privateMutualGroups)}</td>
            <td>{timestampOrDash(metrics.firstTimestamp)}</td>
            <td>{timestampOrDash(metrics.lastTimestamp)}</td>
          </>
        )}

        {activeTab === 'group' && (
          <>
            <td>{valueOrDash(metrics.groupMyMessages)}</td>
            <td>{valueOrDash(metrics.groupMemberCount)}</td>
            <td>{valueOrDash(metrics.groupActiveSpeakers)}</td>
            <td>{valueOrDash(metrics.groupMutualFriends)}</td>
            <td>{timestampOrDash(metrics.firstTimestamp)}</td>
            <td>{timestampOrDash(metrics.lastTimestamp)}</td>
          </>
        )}

        {activeTab === 'official' && (
          <>
            <td>{timestampOrDash(metrics.firstTimestamp)}</td>
            <td>{timestampOrDash(metrics.lastTimestamp)}</td>
          </>
        )}

        <td className="sticky-right">{renderActionCell(session)}</td>
      </tr>
    )
  }

  const visibleSelectedCount = useMemo(() => {
    const visibleSet = new Set(visibleSessions.map(session => session.username))
    let count = 0
    for (const id of selectedSessions) {
      if (visibleSet.has(id)) count += 1
    }
    return count
  }, [visibleSessions, selectedSessions])

  const writeLayoutLabel = writeLayoutOptions.find(option => option.value === writeLayout)?.label || 'A（类型分目录）'
  const tableColSpan = activeTab === 'group' ? 14 : (activeTab === 'private' || activeTab === 'former_friend' ? 11 : 10)
  const canCreateTask = exportDialog.scope === 'sns'
    ? Boolean(exportFolder)
    : Boolean(exportFolder) && exportDialog.sessionIds.length > 0
  const scopeLabel = exportDialog.scope === 'single'
    ? '单会话'
    : exportDialog.scope === 'multi'
      ? '多会话'
      : exportDialog.scope === 'sns'
        ? '朋友圈批量'
        : `按内容批量（${contentTypeLabels[exportDialog.contentType || 'text']}）`
  const scopeCountLabel = exportDialog.scope === 'sns'
    ? `共 ${snsStats.totalPosts} 条朋友圈动态`
    : `共 ${exportDialog.sessionIds.length} 个会话`
  const formatCandidateOptions = exportDialog.scope === 'sns'
    ? formatOptions.filter(option => option.value === 'html' || option.value === 'json')
    : formatOptions
  const hasTabCountsSource = prefetchedTabCounts !== null || sessions.length > 0
  const isTabCountComputing = isTabCountsLoading && !hasTabCountsSource
  const isSessionCardStatsLoading = isLoading || isBaseConfigLoading
  const taskRunningCount = tasks.filter(task => task.status === 'running').length
  const taskQueuedCount = tasks.filter(task => task.status === 'queued').length
  const showInitialSkeleton = isLoading && sessions.length === 0

  return (
    <div className="export-board-page">
      <div className="export-top-panel">
        <div className="global-export-controls">
          <div className="path-control">
            <span className="control-label">导出位置</span>
            <div className="path-inline-row">
              <button
                className="path-value path-link"
                type="button"
                title={exportFolder}
                disabled={!exportFolder}
                onClick={() => exportFolder && void window.electronAPI.shell.openPath(exportFolder)}
              >
                {exportFolder || '未设置'}
              </button>
              <div className="path-actions">
                <button className="secondary-btn" onClick={() => exportFolder && void window.electronAPI.shell.openPath(exportFolder)}>
                  <ExternalLink size={14} /> 打开
                </button>
                <button
                  className="secondary-btn"
                  onClick={async () => {
                    const result = await window.electronAPI.dialog.openFile({
                      title: '选择导出目录',
                      properties: ['openDirectory']
                    })
                    if (!result.canceled && result.filePaths.length > 0) {
                      const nextPath = result.filePaths[0]
                      setExportFolder(nextPath)
                      await configService.setExportPath(nextPath)
                    }
                  }}
                >
                  <FolderOpen size={14} /> 更换
                </button>
              </div>
            </div>
          </div>

          <div className="write-layout-control" ref={writeLayoutControlRef}>
            <span className="control-label">写入目录方式</span>
            <button
              className={`layout-trigger ${showWriteLayoutSelect ? 'active' : ''}`}
              type="button"
              onClick={() => setShowWriteLayoutSelect(prev => !prev)}
            >
              {writeLayoutLabel}
            </button>
            <div className={`layout-dropdown ${showWriteLayoutSelect ? 'open' : ''}`}>
              {writeLayoutOptions.map(option => (
                <button
                  key={option.value}
                  className={`layout-option ${writeLayout === option.value ? 'active' : ''}`}
                  type="button"
                  onClick={async () => {
                    setWriteLayout(option.value)
                    setShowWriteLayoutSelect(false)
                    await configService.setExportWriteLayout(option.value)
                  }}
                >
                  <span className="layout-option-label">{option.label}</span>
                  <span className="layout-option-desc">{option.desc}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="content-card-grid">
        {contentCards.map(card => {
          const Icon = card.icon
          const isCardStatsLoading = card.type === 'sns'
            ? (isSnsStatsLoading || isBaseConfigLoading)
            : isSessionCardStatsLoading
          return (
            <div key={card.type} className="content-card">
              <div className="card-header">
                <div className="card-title"><Icon size={16} /> {card.label}</div>
              </div>
              <div className="card-stats">
                {card.stats.map((stat) => (
                  <div key={stat.label} className="stat-item">
                    <span>{stat.label}</span>
                    <strong>
                      {isCardStatsLoading ? (
                        <span className="count-loading">
                          统计中<span className="animated-ellipsis" aria-hidden="true">...</span>
                        </span>
                      ) : stat.value.toLocaleString()}
                    </strong>
                  </div>
                ))}
              </div>
              <button
                className="card-export-btn"
                onClick={() => {
                  if (card.type === 'sns') {
                    openSnsExport()
                    return
                  }
                  openContentExport(card.type)
                }}
              >
                导出
              </button>
            </div>
          )
        })}
      </div>

      <div className={`task-center ${isTaskCenterExpanded ? 'expanded' : 'collapsed'}`}>
        <div className="task-center-header">
          <div className="section-title">任务中心</div>
          <div className="task-summary">
            <span>进行中 {taskRunningCount}</span>
            <span>排队 {taskQueuedCount}</span>
            <span>总计 {tasks.length}</span>
          </div>
          <button
            className="task-collapse-btn"
            type="button"
            onClick={() => setIsTaskCenterExpanded(prev => !prev)}
          >
            {isTaskCenterExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            {isTaskCenterExpanded ? '收起' : '展开'}
          </button>
        </div>

        {isTaskCenterExpanded && (tasks.length === 0 ? (
          <div className="task-empty">暂无任务。点击会话导出或卡片导出后会在这里创建任务。</div>
        ) : (
          <div className="task-list">
            {tasks.map(task => (
              <div key={task.id} className={`task-card ${task.status}`}>
                <div className="task-main">
                  <div className="task-title">{task.title}</div>
                  <div className="task-meta">
                    <span className={`task-status ${task.status}`}>{task.status === 'queued' ? '排队中' : task.status === 'running' ? '进行中' : task.status === 'success' ? '已完成' : '失败'}</span>
                    <span>{new Date(task.createdAt).toLocaleString('zh-CN')}</span>
                  </div>
                  {task.status === 'running' && (
                    <>
                      <div className="task-progress-bar">
                        <div
                          className="task-progress-fill"
                          style={{ width: `${task.progress.total > 0 ? (task.progress.current / task.progress.total) * 100 : 0}%` }}
                        />
                      </div>
                      <div className="task-progress-text">
                        {task.progress.total > 0
                          ? `${task.progress.current} / ${task.progress.total}`
                          : '处理中'}
                        {task.progress.phaseLabel ? ` · ${task.progress.phaseLabel}` : ''}
                      </div>
                    </>
                  )}
                  {task.status === 'error' && <div className="task-error">{task.error || '任务失败'}</div>}
                </div>
                <div className="task-actions">
                  <button className="secondary-btn" onClick={() => exportFolder && void window.electronAPI.shell.openPath(exportFolder)}>
                    <FolderOpen size={14} /> 目录
                  </button>
                </div>
              </div>
            ))}
          </div>
        ))}
      </div>

      <div className="session-table-section">
        <div className="table-toolbar">
          <div className="table-tabs" role="tablist" aria-label="会话类型">
            <button className={`tab-btn ${activeTab === 'private' ? 'active' : ''}`} onClick={() => setActiveTab('private')}>
              私聊 {isTabCountComputing ? <span className="count-loading">计算中<span className="animated-ellipsis" aria-hidden="true">...</span></span> : tabCounts.private}
            </button>
            <button className={`tab-btn ${activeTab === 'group' ? 'active' : ''}`} onClick={() => setActiveTab('group')}>
              群聊 {isTabCountComputing ? <span className="count-loading">计算中<span className="animated-ellipsis" aria-hidden="true">...</span></span> : tabCounts.group}
            </button>
            <button className={`tab-btn ${activeTab === 'official' ? 'active' : ''}`} onClick={() => setActiveTab('official')}>
              公众号 {isTabCountComputing ? <span className="count-loading">计算中<span className="animated-ellipsis" aria-hidden="true">...</span></span> : tabCounts.official}
            </button>
            <button className={`tab-btn ${activeTab === 'former_friend' ? 'active' : ''}`} onClick={() => setActiveTab('former_friend')}>
              曾经的好友 {isTabCountComputing ? <span className="count-loading">计算中<span className="animated-ellipsis" aria-hidden="true">...</span></span> : tabCounts.former_friend}
            </button>
          </div>

          <div className="toolbar-actions">
            <div className="search-input-wrap">
              <Search size={14} />
              <input
                value={searchKeyword}
                onChange={(event) => setSearchKeyword(event.target.value)}
                placeholder={`搜索${activeTabLabel}会话...`}
              />
              {searchKeyword && (
                <button className="clear-search" onClick={() => setSearchKeyword('')}>
                  <X size={12} />
                </button>
              )}
            </div>

            <button className="secondary-btn" onClick={toggleSelectAllVisible}>
              {visibleSelectedCount > 0 && visibleSelectedCount === visibleSessions.length ? '取消全选' : '全选当前'}
            </button>

            {selectedCount > 0 && (
              <div className="selected-batch-actions">
                <span>已选中 {selectedCount} 个会话</span>
                <button className="primary-btn" onClick={openBatchExport}>
                  <Download size={14} /> 导出
                </button>
                <button className="secondary-btn" onClick={clearSelection}>清空</button>
              </div>
            )}
          </div>
        </div>

        {(isLoading || isSessionEnriching) && (
          <div className="table-stage-hint">
            <Loader2 size={14} className="spin" />
            {isLoading ? '正在加载会话列表…' : '正在补充头像和统计…'}
          </div>
        )}

        <div className="table-wrap">
          <table className="session-table">
            <thead>{renderTableHeader()}</thead>
            <tbody>
              {showInitialSkeleton ? (
                <tr>
                  <td colSpan={tableColSpan}>
                    <div className="table-skeleton-list">
                      {Array.from({ length: 8 }).map((_, rowIndex) => (
                        <div key={`skeleton-row-${rowIndex}`} className="table-skeleton-item">
                          <span className="skeleton-shimmer skeleton-dot"></span>
                          <span className="skeleton-shimmer skeleton-avatar"></span>
                          <span className="skeleton-shimmer skeleton-line w-30"></span>
                          <span className="skeleton-shimmer skeleton-line w-12"></span>
                          <span className="skeleton-shimmer skeleton-line w-12"></span>
                          <span className="skeleton-shimmer skeleton-line w-12"></span>
                        </div>
                      ))}
                    </div>
                  </td>
                </tr>
              ) : visibleSessions.length === 0 ? (
                <tr>
                  <td colSpan={tableColSpan}>
                    <div className="table-state">暂无会话</div>
                  </td>
                </tr>
              ) : (
                visibleSessions.map(renderRow)
              )}
            </tbody>
          </table>
        </div>
      </div>

      {exportDialog.open && (
        <div className="export-dialog-overlay" onClick={closeExportDialog}>
          <div className="export-dialog" onClick={(event) => event.stopPropagation()}>
            <div className="dialog-header">
              <h3>{exportDialog.title}</h3>
              <button className="close-icon-btn" onClick={closeExportDialog}><X size={16} /></button>
            </div>

            <div className="dialog-section">
              <h4>导出范围</h4>
              <div className="scope-tag-row">
                <span className="scope-tag">{scopeLabel}</span>
                <span className="scope-count">{scopeCountLabel}</span>
              </div>
              <div className="scope-list">
                {exportDialog.sessionNames.slice(0, 20).map(name => (
                  <span key={name} className="scope-item">{name}</span>
                ))}
                {exportDialog.sessionNames.length > 20 && <span className="scope-item">... 还有 {exportDialog.sessionNames.length - 20} 个</span>}
              </div>
            </div>

            <div className="dialog-section">
              <h4>对话文本导出格式选择</h4>
              <div className="format-grid">
                {formatCandidateOptions.map(option => (
                  <button
                    key={option.value}
                    className={`format-card ${options.format === option.value ? 'active' : ''}`}
                    onClick={() => setOptions(prev => ({ ...prev, format: option.value }))}
                  >
                    <div className="format-label">{option.label}</div>
                    <div className="format-desc">{option.desc}</div>
                  </button>
                ))}
              </div>
            </div>

            <div className="dialog-section">
              <h4>时间范围</h4>
              <div className="switch-row">
                <span>导出全部时间</span>
                <label className="switch">
                  <input
                    type="checkbox"
                    checked={options.useAllTime}
                    onChange={(event) => setOptions(prev => ({ ...prev, useAllTime: event.target.checked }))}
                  />
                  <span className="switch-slider"></span>
                </label>
              </div>

              {!options.useAllTime && options.dateRange && (
                <div className="date-range-row">
                  <label>
                    开始
                    <input
                      type="date"
                      value={formatDateInputValue(options.dateRange.start)}
                      onChange={(event) => {
                        const start = parseDateInput(event.target.value, false)
                        setOptions(prev => ({
                          ...prev,
                          dateRange: prev.dateRange ? {
                            start,
                            end: prev.dateRange.end < start ? parseDateInput(event.target.value, true) : prev.dateRange.end
                          } : { start, end: new Date() }
                        }))
                      }}
                    />
                  </label>
                  <label>
                    结束
                    <input
                      type="date"
                      value={formatDateInputValue(options.dateRange.end)}
                      onChange={(event) => {
                        const end = parseDateInput(event.target.value, true)
                        setOptions(prev => ({
                          ...prev,
                          dateRange: prev.dateRange ? {
                            start: prev.dateRange.start > end ? parseDateInput(event.target.value, false) : prev.dateRange.start,
                            end
                          } : { start: new Date(), end }
                        }))
                      }}
                    />
                  </label>
                </div>
              )}
            </div>

            <div className="dialog-section">
              <h4>媒体与头像</h4>
              <div className="switch-row">
                <span>导出媒体文件</span>
                <label className="switch">
                  <input
                    type="checkbox"
                    checked={options.exportMedia}
                    onChange={(event) => setOptions(prev => ({ ...prev, exportMedia: event.target.checked }))}
                  />
                  <span className="switch-slider"></span>
                </label>
              </div>

              <div className="media-check-grid">
                <label><input type="checkbox" checked={options.exportImages} disabled={!options.exportMedia} onChange={event => setOptions(prev => ({ ...prev, exportImages: event.target.checked }))} /> 图片</label>
                <label><input type="checkbox" checked={options.exportVoices} disabled={!options.exportMedia} onChange={event => setOptions(prev => ({ ...prev, exportVoices: event.target.checked }))} /> 语音</label>
                <label><input type="checkbox" checked={options.exportVideos} disabled={!options.exportMedia} onChange={event => setOptions(prev => ({ ...prev, exportVideos: event.target.checked }))} /> 视频</label>
                <label><input type="checkbox" checked={options.exportEmojis} disabled={!options.exportMedia} onChange={event => setOptions(prev => ({ ...prev, exportEmojis: event.target.checked }))} /> 表情包</label>
                <label><input type="checkbox" checked={options.exportVoiceAsText} onChange={event => setOptions(prev => ({ ...prev, exportVoiceAsText: event.target.checked }))} /> 语音转文字</label>
                <label><input type="checkbox" checked={options.exportAvatars} onChange={event => setOptions(prev => ({ ...prev, exportAvatars: event.target.checked }))} /> 导出头像</label>
              </div>
            </div>

            <div className="dialog-section">
              <h4>发送者名称显示</h4>
              <div className="display-name-options">
                {displayNameOptions.map(option => (
                  <label key={option.value} className={`display-name-item ${options.displayNamePreference === option.value ? 'active' : ''}`}>
                    <input
                      type="radio"
                      checked={options.displayNamePreference === option.value}
                      onChange={() => setOptions(prev => ({ ...prev, displayNamePreference: option.value }))}
                    />
                    <span>{option.label}</span>
                    <small>{option.desc}</small>
                  </label>
                ))}
              </div>
            </div>

            <div className="dialog-actions">
              <button className="secondary-btn" onClick={closeExportDialog}>取消</button>
              <button className="primary-btn" onClick={() => void createTask()} disabled={!canCreateTask}>
                <Download size={14} /> 创建导出任务
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default ExportPage
