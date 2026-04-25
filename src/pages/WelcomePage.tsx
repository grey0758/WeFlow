import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAppStore } from '../stores/appStore'
import { dialog } from '../services/ipc'
import * as configService from '../services/config'
import {
  ArrowLeft, ArrowRight, CheckCircle2, Database, Eye, EyeOff,
  FolderOpen, FolderSearch, KeyRound, ShieldCheck, Sparkles,
  UserRound, Wand2, Minus, X, HardDrive, RotateCcw
} from 'lucide-react'
import ConfirmDialog from '../components/ConfirmDialog'
import './WelcomePage.scss'

const steps = [
  { id: 'intro', title: '欢迎', desc: '准备开始你的本地数据探索' },
  { id: 'db', title: '数据库目录', desc: '定位 xwechat_files 目录' },
  { id: 'cache', title: '缓存目录', desc: '设置本地缓存存储位置（可选）' },
  { id: 'key', title: '解密密钥', desc: '获取密钥与自动识别账号' },
  { id: 'image', title: '图片密钥', desc: '获取 XOR 与 AES 密钥' },
  { id: 'security', title: '安全防护', desc: '保护你的数据' }
]

interface WelcomePageProps {
  standalone?: boolean
}

interface DbRuntimeStatus {
  initialized: boolean
  fallbackMode: boolean
  dllAvailable: boolean
  dllInitError: string | null
  mode: 'native' | 'dll'
  dllCompatEnabled: boolean
}

const formatDbKeyFailureMessage = (error?: string, logs?: string[]): string => {
  const rawBase = String(error || '自动获取密钥失败').trim()
  const base = rawBase.includes('DLL 取钥需要在登录过程中抓取')
    ? '自有链路未取到密钥，请保持微信已登录并重试'
    : rawBase
  const tailLogs = Array.isArray(logs)
    ? logs
      .map(item => String(item || '').trim())
      .filter(Boolean)
      .slice(-6)
    : []
  if (tailLogs.length === 0) return base
  return `${base}；最近状态：${tailLogs.join(' | ')}`
}

const getDbKeySourceLabel = (source?: 'pywxdump' | 'native' | 'dll'): string => {
  if (source === 'pywxdump') return '自有桥接'
  if (source === 'native') return '自有内存扫描'
  if (source === 'dll') return '兼容 DLL'
  return '自动链路'
}

const isExpiredDllFallback = (status?: DbRuntimeStatus | null): boolean => {
  const error = String(status?.dllInitError || '')
  return Boolean(status?.dllCompatEnabled && status?.fallbackMode && error.includes('WCDB DLL 已过期并触发自毁'))
}

const formatDbRuntimeStatus = (status?: DbRuntimeStatus | null): string => {
  if (!status?.initialized) return ''
  if (status.mode === 'dll') {
    return '当前数据库运行模式：WCDB DLL 兼容层。'
  }
  if (isExpiredDllFallback(status)) {
    return '当前数据库运行模式：自有链路。WCDB DLL 兼容层已过期并返回 -1000，当前已自动回退到自有链路，读取和导出可继续使用。'
  }
  if (status.dllCompatEnabled && status.fallbackMode) {
    return status.dllInitError
      ? `当前数据库运行模式：自有链路。WCDB DLL 兼容层状态：${status.dllInitError}`
      : '当前数据库运行模式：自有链路。WCDB DLL 兼容层未接管，当前读取链路可继续使用。'
  }
  return '当前数据库运行模式：自有链路（默认）。未启用 WCDB DLL 兼容层。'
}

function WelcomePage({ standalone = false }: WelcomePageProps) {
  const navigate = useNavigate()
  const { isDbConnected, setDbConnected, setLoading } = useAppStore()

  const [stepIndex, setStepIndex] = useState(0)
  const [dbPath, setDbPath] = useState('')
  const [decryptKey, setDecryptKey] = useState('')
  const [wcdbKeys, setWcdbKeys] = useState<Record<string, string> | null>(null)
  const [imageXorKey, setImageXorKey] = useState('')
  const [imageAesKey, setImageAesKey] = useState('')
  const [cachePath, setCachePath] = useState('')
  const [wxid, setWxid] = useState('')
  const [wxidOptions, setWxidOptions] = useState<Array<{
      avatarUrl?: string;
      nickname?: string;
      wxid: string;
      modifiedTime: number
  }>>([])
  const [showWxidSelect, setShowWxidSelect] = useState(false)
  const wxidSelectRef = useRef<HTMLDivElement>(null)
  const [error, setError] = useState('')
  const [isConnecting, setIsConnecting] = useState(false)
  const [isDetectingPath, setIsDetectingPath] = useState(false)
  const [isScanningWxid, setIsScanningWxid] = useState(false)
  const [isFetchingDbKey, setIsFetchingDbKey] = useState(false)
  const [isFetchingImageKey, setIsFetchingImageKey] = useState(false)
  const [showDecryptKey, setShowDecryptKey] = useState(false)
  const [isClosing, setIsClosing] = useState(false)
  const [dbKeyStatus, setDbKeyStatus] = useState('')
  const [dbRuntimeStatus, setDbRuntimeStatus] = useState<DbRuntimeStatus | null>(null)
  const [imageKeyStatus, setImageKeyStatus] = useState('')
  const [isManualStartPrompt, setIsManualStartPrompt] = useState(false)
  const [imageKeyPercent, setImageKeyPercent] = useState<number | null>(null)
  const [showDbKeyConfirm, setShowDbKeyConfirm] = useState(false)

  // 安全相关 state
  const [enableAuth, setEnableAuth] = useState(false)
  const [authPassword, setAuthPassword] = useState('')
  const [authConfirmPassword, setAuthConfirmPassword] = useState('')
  const [enableHello, setEnableHello] = useState(false)
  const [helloAvailable, setHelloAvailable] = useState(false)
  const [isSettingHello, setIsSettingHello] = useState(false)

  // 检查 Hello 可用性
  useEffect(() => {
    if (window.PublicKeyCredential) {
      void PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().then(setHelloAvailable)
    }
  }, [])

  async function sha256(message: string) {
    const msgBuffer = new TextEncoder().encode(message)
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
    return hashHex
  }

  const handleSetupHello = async () => {
    setIsSettingHello(true)
    try {
      // 注册凭证 (WebAuthn)
      const challenge = new Uint8Array(32)
      window.crypto.getRandomValues(challenge)

      const credential = await navigator.credentials.create({
        publicKey: {
          challenge,
          rp: { name: 'WeFlow', id: 'localhost' },
          user: {
            id: new Uint8Array([1]),
            name: 'user',
            displayName: 'User'
          },
          pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
          authenticatorSelection: { userVerification: 'required' },
          timeout: 60000
        }
      })

      if (credential) {
        setEnableHello(true)
        // 成功提示?
      }
    } catch (e: any) {
      if (e.name !== 'NotAllowedError') {
        setError('Windows Hello 设置失败: ' + e.message)
      }
    } finally {
      setIsSettingHello(false)
    }
  }

  useEffect(() => {
    const removeDb = window.electronAPI.key.onDbKeyStatus((payload: { message: string; level: number }) => {
      setDbKeyStatus(payload.message)
      if (payload.message.includes('现在可以登录') || payload.message.includes('Hook安装成功')) {
        window.electronAPI.notification?.show({
          title: 'WeFlow 准备就绪',
          content: '现在可以登录微信了',
          avatarUrl: './logo.png',
          sessionId: 'weflow-system'
        })
      }
    })
    const removeImage = window.electronAPI.key.onImageKeyStatus((payload: { message: string, percent?: number }) => {
      let msg = payload.message;
      let pct = payload.percent;

      // 解析文本中的百分比
      if (pct === undefined) {
        const match = msg.match(/\(([\d.]+)%\)/);
        if (match) {
          pct = parseFloat(match[1]);
          msg = msg.replace(/\s*\([\d.]+%\)/, '');
        }
      }

      setImageKeyStatus(msg);
      if (pct !== undefined) {
        setImageKeyPercent(pct);
      } else if (msg.includes('启动多核') || msg.includes('定位') || msg.includes('准备')) {
        setImageKeyPercent(0);
      }
    })
    return () => {
      removeDb?.()
      removeImage?.()
    }
  }, [])

  const refreshDbRuntimeStatus = async (): Promise<DbRuntimeStatus | null> => {
    try {
      const runtime = await window.electronAPI.wcdb.getRuntimeStatus()
      setDbRuntimeStatus(runtime)
      return runtime
    } catch {
      setDbRuntimeStatus(null)
      return null
    }
  }

  useEffect(() => {
    if (isDbConnected) {
      void refreshDbRuntimeStatus()
    } else {
      setDbRuntimeStatus(null)
    }
  }, [isDbConnected])

  useEffect(() => {
    if (isDbConnected && !standalone) {
      navigate('/home')
    }
  }, [isDbConnected, standalone, navigate])

  useEffect(() => {
    setWxidOptions([])
    setWxid('')
    setShowWxidSelect(false)
  }, [dbPath])

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (!showWxidSelect) return
      const target = event.target as Node
      if (wxidSelectRef.current && !wxidSelectRef.current.contains(target)) {
        setShowWxidSelect(false)
      }
    }

    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [showWxidSelect])

  const currentStep = steps[stepIndex]
  const rootClassName = `welcome-page${isClosing ? ' is-closing' : ''}${standalone ? ' is-standalone' : ''}`
  const showWindowControls = standalone

  const handleMinimize = () => {
    window.electronAPI.window.minimize()
  }

  const handleCloseWindow = () => {
    window.electronAPI.window.close()
  }

  const validatePath = (path: string): string | null => {
    if (!path) return null
    // 检测中文字符和其他可能有问题的特殊字符
    if (/[\u4e00-\u9fa5]/.test(path)) {
      return '路径包含中文字符，请迁移至全英文目录'
    }
    return null
  }

  const handleSelectPath = async () => {
    try {
      const result = await dialog.openFile({
        title: '选择微信数据库目录',
        properties: ['openDirectory']
      })

      if (!result.canceled && result.filePaths.length > 0) {
        const selectedPath = result.filePaths[0]
        const validationError = validatePath(selectedPath)
        if (validationError) {
          setError(validationError)
        } else {
          setDbPath(selectedPath)
          setError('')
        }
      }
    } catch (e) {
      setError('选择目录失败')
    }
  }

  const handleAutoDetectPath = async () => {
    if (isDetectingPath) return
    setIsDetectingPath(true)
    setError('')
    try {
      const result = await window.electronAPI.dbPath.autoDetect()
      if (result.success && result.path) {
        const validationError = validatePath(result.path)
        if (validationError) {
          setError(validationError)
        } else {
          setDbPath(result.path)
          setError('')
        }
      } else {
        setError(result.error || '未能检测到数据库目录')
      }
    } catch (e) {
      setError(`自动检测失败: ${e}`)
    } finally {
      setIsDetectingPath(false)
    }
  }

  const handleSelectCachePath = async () => {
    try {
      const result = await dialog.openFile({
        title: '选择缓存目录',
        properties: ['openDirectory']
      })

      if (!result.canceled && result.filePaths.length > 0) {
        setCachePath(result.filePaths[0])
        setError('')
      }
    } catch (e) {
      setError('选择缓存目录失败')
    }
  }

  const handleScanWxid = async (silent = false) => {
    if (!dbPath) {
      if (!silent) setError('请先选择数据库目录')
      return
    }
    if (isScanningWxid) return
    setIsScanningWxid(true)
    if (!silent) setError('')
    try {
      const wxids = await window.electronAPI.dbPath.scanWxids(dbPath)
      setWxidOptions(wxids)
      if (wxids.length > 0) {
        // scanWxids 已经按时间排过序了，直接取第一个
        setWxid(wxids[0].wxid)
        if (!silent) setError('')
      } else {
        if (!silent) setError('未检测到账号目录，请检查路径')
      }
    } catch (e) {
      if (!silent) setError(`扫描失败: ${e}`)
    } finally {
      setIsScanningWxid(false)
    }
  }

  const handleScanWxidCandidates = async () => {
    if (!dbPath) {
      setError('请先选择数据库目录')
      return
    }
    if (isScanningWxid) return
    setIsScanningWxid(true)
    setError('')
    try {
      const wxids = await window.electronAPI.dbPath.scanWxidCandidates(dbPath)
      setWxidOptions(wxids)
      setShowWxidSelect(true)
      if (!wxids.length) {
        setError('未检测到可用的账号目录，请检查路径')
      }
    } catch (e) {
      setError(`扫描失败: ${e}`)
    } finally {
      setIsScanningWxid(false)
    }
  }

  const handleAutoGetDbKey = async () => {
    if (isFetchingDbKey) return
    setShowDbKeyConfirm(true)
  }

  const handleDbKeyConfirm = async () => {
    setShowDbKeyConfirm(false)
    setIsFetchingDbKey(true)
    setError('')
    setIsManualStartPrompt(false)
    setDbKeyStatus('正在连接微信进程...')
    try {
      const result = await window.electronAPI.key.autoGetDbKey()
      if (result.success && result.key) {
        setDecryptKey(result.key)
        setWcdbKeys(null)
        const sourceLabel = getDbKeySourceLabel(result.source)
        setDbKeyStatus(`密钥获取成功（${sourceLabel}）`)
        setError('')
        await handleScanWxid(true)
      } else if (result.success && result.wcdbKeys && Object.keys(result.wcdbKeys).length > 0) {
        setWcdbKeys(result.wcdbKeys)
        setDecryptKey('')
        const sourceLabel = getDbKeySourceLabel(result.source)
        setDbKeyStatus(`密钥获取成功（${sourceLabel} / 多密钥模式，共 ${Object.keys(result.wcdbKeys).length} 个）`)
        setError('')
        await handleScanWxid(true)
      } else {
        if (result.error?.includes('未找到微信安装路径') || result.error?.includes('启动微信失败')) {
          setIsManualStartPrompt(true)
          setDbKeyStatus('需要手动启动微信')
        } else {
          if (result.error?.includes('DLL 取钥需要在登录过程中抓取')) {
            setDbKeyStatus('自有链路未命中，请保持微信已登录后重试')
          } else if (result.error?.includes('尚未完成登录')) {
            setDbKeyStatus('请先在微信完成登录后重试')
          }
          setError(formatDbKeyFailureMessage(result.error, result.logs))
        }
      }
    } catch (e) {
      setError(`自动获取密钥失败: ${e}`)
    } finally {
      setIsFetchingDbKey(false)
    }
  }

  const handleManualConfirm = async () => {
    setIsManualStartPrompt(false)
    handleAutoGetDbKey()
  }

  const imageKeyFallbackHint = '当前账号仍缺少图片 AES 密钥，V4 图片暂时无法解密。请先尝试“缓存计算（支持 kvcomm / MMKV）”；若仍失败，请在微信中打开 2-3 张图片大图后再用“内存扫描”。'
  const formatImageKeySourceLabel = (source?: 'kvcomm' | 'mmkv' | 'memory') => {
    if (source === 'kvcomm') return 'kvcomm 缓存'
    if (source === 'mmkv') return 'MMKV 缓存'
    if (source === 'memory') return '内存扫描'
    return '本地缓存'
  }

  const handleAutoGetImageKey = async () => {
    if (isFetchingImageKey) return
    if (!dbPath) { setError('请先选择数据库目录'); return }
    setIsFetchingImageKey(true)
    setError('')
    setImageKeyPercent(0)
    setImageKeyStatus('正在准备获取图片密钥...')
    try {
      const accountPath = wxid ? `${dbPath}/${wxid}` : dbPath
      const result = await window.electronAPI.key.autoGetImageKey(accountPath, wxid)
      if (result.success && result.aesKey) {
        if (typeof result.xorKey === 'number') {
          setImageXorKey(`0x${result.xorKey.toString(16).toUpperCase().padStart(2, '0')}`)
        }
        setImageAesKey(result.aesKey)
        const sourceLabel = formatImageKeySourceLabel(result.source)
        const verificationLabel = result.verified === false ? '（未校验）' : ''
        setImageKeyStatus(`已获取图片密钥（${sourceLabel}${verificationLabel}）`)
      } else {
        const failureMessage = result.error || imageKeyFallbackHint
        setImageKeyStatus(failureMessage)
        setError(failureMessage)
      }
    } catch (e) {
      const failureMessage = `自动获取图片密钥失败: ${e}`
      setImageKeyStatus(failureMessage)
      setError(failureMessage)
    } finally {
      setIsFetchingImageKey(false)
    }
  }

  const handleScanImageKeyFromMemory = async () => {
    if (isFetchingImageKey) return
    if (!dbPath) { setError('请先选择数据库目录'); return }
    setIsFetchingImageKey(true)
    setError('')
    setImageKeyPercent(0)
    setImageKeyStatus('正在扫描内存...')
    try {
      const accountPath = wxid ? `${dbPath}/${wxid}` : dbPath
      const result = await window.electronAPI.key.scanImageKeyFromMemory(accountPath)
      if (result.success && result.aesKey) {
        if (typeof result.xorKey === 'number') {
          setImageXorKey(`0x${result.xorKey.toString(16).toUpperCase().padStart(2, '0')}`)
        }
        setImageAesKey(result.aesKey)
        setImageKeyStatus('内存扫描成功，已获取图片密钥')
      } else {
        const failureMessage = result.error || imageKeyFallbackHint
        setImageKeyStatus(failureMessage)
        setError(failureMessage)
      }
    } catch (e) {
      const failureMessage = `内存扫描失败: ${e}`
      setImageKeyStatus(failureMessage)
      setError(failureMessage)
    } finally {
      setIsFetchingImageKey(false)
    }
  }

  const canGoNext = () => {
    if (currentStep.id === 'intro') return true
    if (currentStep.id === 'db') return Boolean(dbPath)
    if (currentStep.id === 'cache') return true
    if (currentStep.id === 'key') return (decryptKey.length === 64 || wcdbKeys !== null) && Boolean(wxid)
    if (currentStep.id === 'image') return true
    if (currentStep.id === 'security') {
      if (enableAuth) {
        return authPassword.length > 0 && authPassword === authConfirmPassword
      }
      return true
    }
    return false
  }

  const handleNext = () => {
    if (!canGoNext()) {
      if (currentStep.id === 'db' && !dbPath) setError('请先选择数据库目录')
      if (currentStep.id === 'key') {
        if (decryptKey.length !== 64 && !wcdbKeys) setError('密钥长度必须为 64 个字符')
        else if (!wxid) setError('未能自动识别 wxid，请尝试重新获取或检查目录')
      }
      return
    }
    setError('')
    setStepIndex((prev) => Math.min(prev + 1, steps.length - 1))
  }

  const handleBack = () => {
    setError('')
    setStepIndex((prev) => Math.max(prev - 1, 0))
  }

  const handleConnect = async () => {
    if (!dbPath) { setError('请先选择数据库目录'); return }
    if (!wxid) { setError('请填写微信ID'); return }
    if (!decryptKey && !wcdbKeys) { setError('请先使用自动获取密钥获取解密密钥'); return }

    setIsConnecting(true)
    setError('')
    setLoading(true, '正在连接数据库...')

    try {
      const result = await window.electronAPI.wcdb.testConnection(
        dbPath, decryptKey || '', wxid, wcdbKeys ?? undefined
      )
      if (!result.success) {
        setError(result.error || 'WCDB 连接失败')
        setLoading(false)
        return
      }

      await configService.setDbPath(dbPath)
      if (decryptKey) await configService.setDecryptKey(decryptKey)
      if (wcdbKeys) await configService.setWcdbKeys(wcdbKeys)
      await configService.setMyWxid(wxid)
      await configService.setCachePath(cachePath)
      const parsedXorKey = imageXorKey ? parseInt(imageXorKey.replace(/^0x/i, ''), 16) : null
      await configService.setImageXorKey(typeof parsedXorKey === 'number' && !Number.isNaN(parsedXorKey) ? parsedXorKey : 0)
      await configService.setImageAesKey(imageAesKey || '')
      await configService.setWxidConfig(wxid, {
        decryptKey: decryptKey || undefined,
        imageXorKey: typeof parsedXorKey === 'number' && !Number.isNaN(parsedXorKey) ? parsedXorKey : 0,
        imageAesKey
      })

      // 保存安全配置
      if (enableAuth && authPassword) {
        const hash = await sha256(authPassword)
        await configService.setAuthEnabled(true)
        await configService.setAuthPassword(hash)
        await configService.setAuthUseHello(enableHello)
      }

      await configService.setOnboardingDone(true)

      const runtimeStatus = await refreshDbRuntimeStatus()
      if (runtimeStatus && isExpiredDllFallback(runtimeStatus)) {
        setDbKeyStatus(`现在可以登录并继续使用。${formatDbRuntimeStatus(runtimeStatus)}`)
      }
      setDbConnected(true, dbPath)
      setLoading(false)

      if (standalone) {
        setIsClosing(true)
        setTimeout(() => {
          window.electronAPI.window.completeOnboarding()
        }, 450)
      } else {
        navigate('/home')
      }
    } catch (e) {
      setError(`连接失败: ${e}`)
      setLoading(false)
    } finally {
      setIsConnecting(false)
    }
  }

  const formatModifiedTime = (time: number) => {
    if (!time) return '未知时间'
    const date = new Date(time)
    const year = date.getFullYear()
    const month = String(date.getMonth() + 1).padStart(2, '0')
    const day = String(date.getDate()).padStart(2, '0')
    const hours = String(date.getHours()).padStart(2, '0')
    const minutes = String(date.getMinutes()).padStart(2, '0')
    return `${year}-${month}-${day} ${hours}:${minutes}`
  }

  if (isDbConnected) {
    return (
      <div className={rootClassName}>
        <div className="welcome-container">
          {showWindowControls && (
            <div className="window-controls">
              <button type="button" className="window-btn" onClick={handleMinimize} aria-label="最小化">
                <Minus size={14} />
              </button>
              <button type="button" className="window-btn is-close" onClick={handleCloseWindow} aria-label="关闭">
                <X size={14} />
              </button>
            </div>
          )}
          <div className="welcome-sidebar">
            <div className="sidebar-header">
              <img src="./logo.png" alt="WeFlow" className="sidebar-logo" />
              <div className="sidebar-brand">
                <span className="brand-name">WeFlow</span>
                <span className="brand-tag">Connected</span>
              </div>
            </div>

            <div className="sidebar-spacer" style={{ flex: 1 }} />

            <div className="sidebar-footer">
              <ShieldCheck size={14} />
              <span>本地安全存储</span>
            </div>
          </div>

          <div className="welcome-content success-content">
            <div className="success-body">
              <div className="success-icon">
                <CheckCircle2 size={48} />
              </div>
              <h1 className="success-title">配置已完成</h1>
              <p className="success-desc">数据库已连接，你可以直接进入首页使用全部功能。</p>

              <button
                className="btn btn-primary btn-large"
                onClick={() => {
                  if (standalone) {
                    setIsClosing(true)
                    setTimeout(() => {
                      window.electronAPI.window.completeOnboarding()
                    }, 450)
                  } else {
                    navigate('/home')
                  }
                }}
              >
                进入首页 <ArrowRight size={18} />
              </button>
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className={rootClassName}>
      <div className="welcome-container">
        {showWindowControls && (
          <div className="window-controls">
            <button type="button" className="window-btn" onClick={handleMinimize} aria-label="最小化">
              <Minus size={14} />
            </button>
            <button type="button" className="window-btn is-close" onClick={handleCloseWindow} aria-label="关闭">
              <X size={14} />
            </button>
          </div>
        )}
        <div className="welcome-sidebar">
          <div className="sidebar-header">
            <img src="./logo.png" alt="WeFlow" className="sidebar-logo" />
            <div className="sidebar-brand">
              <span className="brand-name">WeFlow</span>
              <span className="brand-tag">Setup</span>
            </div>
          </div>

          <div className="sidebar-nav">
            {steps.map((step, index) => (
              <div key={step.id} className={`nav-item ${index === stepIndex ? 'active' : ''} ${index < stepIndex ? 'completed' : ''}`}>
                <div className="nav-indicator">
                  {index < stepIndex ? <CheckCircle2 size={14} /> : <div className="dot" />}
                </div>
                <div className="nav-info">
                  <div className="nav-title">{step.title}</div>
                  <div className="nav-desc">{step.desc}</div>
                </div>
              </div>
            ))}
          </div>

          <div className="sidebar-footer">
            <ShieldCheck size={14} />
            <span>数据仅在本地处理，不上传服务器</span>
          </div>
        </div>

        <div className="welcome-content">
          <div className="content-header">
            <div>
              <h2>{currentStep.title}</h2>
              <p className="header-desc">{currentStep.desc}</p>
            </div>
          </div>

          <div className="content-body">
            {currentStep.id === 'intro' && (
              <div className="intro-block">
                {/* 内容移至底部 */}
              </div>
            )}

            {currentStep.id === 'db' && (
              <div className="form-group">
                <label className="field-label">数据库根目录</label>
                <div className="input-group">
                  <input
                    type="text"
                    className="field-input"
                    placeholder="例如：C:\\Users\\xxx\\Documents\\xwechat_files"
                    value={dbPath}
                    onChange={(e) => setDbPath(e.target.value)}
                  />
                </div>
                <div className="action-row">
                  <button className="btn btn-secondary" onClick={handleAutoDetectPath} disabled={isDetectingPath}>
                    <FolderSearch size={16} /> {isDetectingPath ? '检测中...' : '自动检测'}
                  </button>
                  <button className="btn btn-secondary" onClick={handleSelectPath}>
                    <FolderOpen size={16} /> 浏览...
                  </button>
                </div>

                <div className="field-hint">请选择微信-设置-存储位置对应的目录</div>
              </div>
            )}

            {currentStep.id === 'cache' && (
              <div className="form-group">
                <label className="field-label">缓存目录</label>
                <div className="input-group">
                  <input
                    type="text"
                    className="field-input"
                    placeholder="留空即使用默认目录"
                    value={cachePath}
                    onChange={(e) => setCachePath(e.target.value)}
                  />
                </div>
                <div className="action-row">
                  <button className="btn btn-secondary" onClick={handleSelectCachePath}>
                    <FolderOpen size={16} /> 浏览
                  </button>
                  <button className="btn btn-secondary" onClick={() => setCachePath('')}>
                    <RotateCcw size={16} /> 重置默认
                  </button>
                </div>
                <div className="field-hint">用于头像、表情与图片缓存</div>
              </div>
            )}

            {currentStep.id === 'key' && (
              <div className="form-group">
                <label className="field-label">微信账号 (Wxid)</label>
                <div className="wxid-select" ref={wxidSelectRef}>
                  <input
                    type="text"
                    className="field-input"
                    placeholder="点击选择..."
                    value={wxid}
                    readOnly
                    onClick={handleScanWxidCandidates}
                    onChange={(e) => setWxid(e.target.value)}
                  />
                  {showWxidSelect && wxidOptions.length > 0 && (
                      <div className="wxid-dropdown">
                        {wxidOptions.map((opt) => (
                            <button
                                key={opt.wxid}
                                type="button"
                                className={`wxid-option ${opt.wxid === wxid ? 'active' : ''}`}
                                onClick={() => {
                                  setWxid(opt.wxid)
                                  setShowWxidSelect(false)
                                }}
                            >
                              <div className="wxid-profile">
                                {opt.avatarUrl ? (
                                    <img src={opt.avatarUrl} alt="avatar" className="wxid-avatar" />
                                ) : (
                                    <div className="wxid-avatar-fallback"><UserRound size={14}/></div>
                                )}
                                <div className="wxid-info">
                                  <span className="wxid-nickname">{opt.nickname || opt.wxid}</span>
                                  {opt.nickname && <span className="wxid-sub">{opt.wxid}</span>}
                                </div>
                              </div>
                              <span className="wxid-time">{formatModifiedTime(opt.modifiedTime)}</span>
                            </button>
                        ))}
                      </div>
                  )}
                </div>

                <label className="field-label mt-4">解密密钥</label>
                <div className="field-with-toggle">
                  <input
                    type={showDecryptKey ? 'text' : 'password'}
                    className="field-input"
                    placeholder="64 位十六进制密钥"
                    value={decryptKey}
                    onChange={(e) => setDecryptKey(e.target.value.trim())}
                  />
                  <button type="button" className="toggle-btn" onClick={() => setShowDecryptKey(!showDecryptKey)}>
                    {showDecryptKey ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>

                <div className="key-actions">
                  {isManualStartPrompt ? (
                    <div className="manual-prompt">
                      <p>未能自动启动微信，请手动启动并登录</p>
                      <button className="btn btn-primary" onClick={handleManualConfirm}>
                        我已登录，继续
                      </button>
                    </div>
                  ) : (
                    <button className="btn btn-secondary btn-block" onClick={handleAutoGetDbKey} disabled={isFetchingDbKey}>
                      {isFetchingDbKey ? '正在获取...' : '自动获取密钥'}
                    </button>
                  )}
                </div>

                {dbKeyStatus && <div className={`status-message ${dbKeyStatus.includes('现在可以登录') || dbKeyStatus.includes('Hook安装成功') ? 'is-success' : ''}`}>{dbKeyStatus}</div>}
                <div className="field-hint">点击自动获取后微信将重启，请留意弹窗提示</div>
              </div>
            )}

            {currentStep.id === 'security' && (
              <div className="form-group">
                <div className="security-toggle-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                  <div className="toggle-info">
                    <label className="field-label" style={{ marginBottom: 0 }}>启用应用锁</label>
                    <div className="field-hint">每次启动应用时需要验证密码</div>
                  </div>
                  <label className="switch">
                    <input type="checkbox" checked={enableAuth} onChange={e => setEnableAuth(e.target.checked)} />
                    <span className="switch-slider" />
                  </label>
                </div>

                {enableAuth && (
                  <div className="security-settings" style={{ marginTop: 20, padding: 16, backgroundColor: 'var(--bg-secondary)', borderRadius: 8 }}>
                    <div className="form-group">
                      <label className="field-label">应用密码</label>
                      <input
                        type="password"
                        className="field-input"
                        placeholder="请输入密码"
                        value={authPassword}
                        onChange={e => setAuthPassword(e.target.value)}
                      />
                    </div>
                    <div className="form-group">
                      <label className="field-label">确认密码</label>
                      <input
                        type="password"
                        className="field-input"
                        placeholder="请再次输入密码"
                        value={authConfirmPassword}
                        onChange={e => setAuthConfirmPassword(e.target.value)}
                      />
                      {authPassword && authConfirmPassword && authPassword !== authConfirmPassword && (
                        <div className="error-text" style={{ color: '#ff4d4f', fontSize: 12, marginTop: 4 }}>两次密码不一致</div>
                      )}
                    </div>

                    <div className="divider" style={{ margin: '20px 0', borderTop: '1px solid var(--border-color)' }}></div>

                    <div className="security-toggle-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div className="toggle-info">
                        <label className="field-label" style={{ marginBottom: 0 }}>Windows Hello</label>
                        <div className="field-hint">使用面容、指纹或 PIN 码快速解锁</div>
                      </div>

                      {enableHello ? (
                        <div style={{ color: '#52c41a', display: 'flex', alignItems: 'center', gap: 6 }}>
                          <CheckCircle2 size={16} /> 已开启
                          <button className="btn btn-ghost btn-sm" onClick={() => setEnableHello(false)} style={{ padding: '2px 8px', height: 24, fontSize: 12 }}>关闭</button>
                        </div>
                      ) : (
                        <button
                          className="btn btn-secondary btn-sm"
                          disabled={!helloAvailable || isSettingHello}
                          onClick={handleSetupHello}
                        >
                          {isSettingHello ? '设置中...' : (helloAvailable ? '点击开启' : '不可用')}
                        </button>
                      )}
                    </div>
                    {!helloAvailable && <div className="field-hint warning"> 当前设备不支持 Windows Hello 或未设置 PIN 码</div>}
                  </div>
                )}
              </div>
            )}

            {currentStep.id === 'image' && (
              <div className="form-group">
                <div className="grid-2">
                  <div>
                    <label className="field-label">图片 XOR 密钥</label>
                    <input type="text" className="field-input" placeholder="0x..." value={imageXorKey} onChange={(e) => setImageXorKey(e.target.value)} />
                  </div>
                  <div>
                    <label className="field-label">图片 AES 密钥</label>
                    <input type="text" className="field-input" placeholder="16位密钥" value={imageAesKey} onChange={(e) => setImageAesKey(e.target.value)} />
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '8px', marginTop: '16px' }}>
                  <button className="btn btn-primary btn-block" onClick={handleAutoGetImageKey} disabled={isFetchingImageKey} title="从本地缓存快速计算">
                    {isFetchingImageKey ? '获取中...' : '缓存计算（推荐）'}
                  </button>
                  <button className="btn btn-secondary btn-block" onClick={handleScanImageKeyFromMemory} disabled={isFetchingImageKey} title="扫描微信进程内存">
                    {isFetchingImageKey ? '扫描中...' : '内存扫描'}
                  </button>
                </div>

                {isFetchingImageKey ? (
                  <div className="brute-force-progress">
                    <div className="status-header">
                      <span className="status-text">{imageKeyStatus || '正在启动...'}</span>
                    </div>
                  </div>
                ) : (
                  imageKeyStatus && <div className="status-message" style={{ marginTop: '12px' }}>{imageKeyStatus}</div>
                )}

                <div className="field-hint" style={{ marginTop: '8px' }}>优先尝试缓存计算，当前已同时支持旧 kvcomm 与新版 MMKV 目录。若仍提示缺少图片 AES 密钥，请在微信中打开 2-3 张图片大图后再用内存扫描。</div>
              </div>
            )}
          </div>

          {error && <div className="error-message">{error}</div>}

          {currentStep.id === 'intro' && (
            <div className="intro-footer">
              <p>接下来的几个步骤将引导你连接本地微信数据库。</p>
              <p>WeFlow 需要访问你的本地数据文件以提供分析与导出功能。</p>
            </div>
          )}

          <div className="content-actions">
            <button className="btn btn-ghost" onClick={handleBack} disabled={stepIndex === 0}>
              <ArrowLeft size={16} /> 上一步
            </button>

            {stepIndex < steps.length - 1 ? (
              <button className="btn btn-primary" onClick={handleNext} disabled={!canGoNext()}>
                下一步 <ArrowRight size={16} />
              </button>
            ) : (
              <button className="btn btn-primary" onClick={handleConnect} disabled={isConnecting || !canGoNext()}>
                {isConnecting ? '连接中...' : '完成配置'} <ArrowRight size={16} />
              </button>
            )}
          </div>
        </div>

        <ConfirmDialog
          open={showDbKeyConfirm}
          title="开始获取数据库密钥"
          message={`当开始获取后 WeFlow 将会执行准备操作

当 WeFlow 内的提示条变为绿色显示允许登录或看到来自WeFlow的登录通知时，登录你的微信或退出当前登录并重新登录。`}
          onConfirm={handleDbKeyConfirm}
          onCancel={() => setShowDbKeyConfirm(false)}
        />
      </div>
    </div>
  )
}

export default WelcomePage
