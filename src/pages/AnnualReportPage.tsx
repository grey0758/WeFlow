import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Calendar, Loader2, Sparkles, Users } from 'lucide-react'
import './AnnualReportPage.scss'

type YearOption = number | 'all'

const formatLoadElapsed = (ms: number) => {
  const totalSeconds = Math.max(0, ms) / 1000
  if (totalSeconds < 60) return `${totalSeconds.toFixed(1)}s`
  const minutes = Math.floor(totalSeconds / 60)
  const seconds = Math.floor(totalSeconds % 60)
  return `${minutes}m ${String(seconds).padStart(2, '0')}s`
}

function AnnualReportPage() {
  const navigate = useNavigate()
  const [availableYears, setAvailableYears] = useState<number[]>([])
  const [selectedYear, setSelectedYear] = useState<YearOption | null>(null)
  const [selectedPairYear, setSelectedPairYear] = useState<YearOption | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isLoadingMoreYears, setIsLoadingMoreYears] = useState(false)
  const [hasYearsLoadFinished, setHasYearsLoadFinished] = useState(false)
  const [loadElapsedMs, setLoadElapsedMs] = useState(0)
  const [isGenerating, setIsGenerating] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)

  useEffect(() => {
    let disposed = false
    let taskId = ''
    const loadStartedAt = Date.now()
    let ticker: ReturnType<typeof setInterval> | null = null

    const startTicker = () => {
      setLoadElapsedMs(0)
      if (ticker) clearInterval(ticker)
      ticker = setInterval(() => {
        if (disposed) return
        setLoadElapsedMs(Date.now() - loadStartedAt)
      }, 100)
    }

    const stopTicker = () => {
      setLoadElapsedMs(Date.now() - loadStartedAt)
      if (ticker) {
        clearInterval(ticker)
        ticker = null
      }
    }

    const stopListen = window.electronAPI.annualReport.onAvailableYearsProgress((payload) => {
      if (disposed) return
      if (taskId && payload.taskId !== taskId) return
      if (!taskId) taskId = payload.taskId

      const years = Array.isArray(payload.years) ? payload.years : []
      if (years.length > 0) {
        setAvailableYears(years)
        setSelectedYear((prev) => {
          if (prev === 'all') return prev
          if (typeof prev === 'number' && years.includes(prev)) return prev
          return years[0]
        })
        setSelectedPairYear((prev) => {
          if (prev === 'all') return prev
          if (typeof prev === 'number' && years.includes(prev)) return prev
          return years[0]
        })
        // 只要有首批年份可选，就不再阻塞整个页面。
        setIsLoading(false)
      }

      if (payload.error && !payload.canceled) {
        setLoadError(payload.error || '加载年度数据失败')
      }

      if (payload.done) {
        setIsLoading(false)
        setIsLoadingMoreYears(false)
        setHasYearsLoadFinished(true)
        stopTicker()
      } else {
        setIsLoadingMoreYears(true)
        setHasYearsLoadFinished(false)
      }
    })

    const startLoad = async () => {
      setIsLoading(true)
      setIsLoadingMoreYears(true)
      setHasYearsLoadFinished(false)
      setLoadError(null)
      startTicker()
      try {
        const startResult = await window.electronAPI.annualReport.startAvailableYearsLoad()
        if (!startResult.success || !startResult.taskId) {
          setLoadError(startResult.error || '加载年度数据失败')
          setIsLoading(false)
          setIsLoadingMoreYears(false)
          stopTicker()
          return
        }
        taskId = startResult.taskId
      } catch (e) {
        console.error(e)
        setLoadError(String(e))
        setIsLoading(false)
        setIsLoadingMoreYears(false)
        stopTicker()
      }
    }

    void startLoad()

    return () => {
      disposed = true
      stopTicker()
      stopListen()
      if (taskId) {
        void window.electronAPI.annualReport.cancelAvailableYearsLoad(taskId)
      }
    }
  }, [])

  const handleGenerateReport = async () => {
    if (selectedYear === null) return
    setIsGenerating(true)
    try {
      const yearParam = selectedYear === 'all' ? 0 : selectedYear
      navigate(`/annual-report/view?year=${yearParam}`)
    } catch (e) {
      console.error('生成报告失败:', e)
    } finally {
      setIsGenerating(false)
    }
  }

  const handleGenerateDualReport = () => {
    if (selectedPairYear === null) return
    const yearParam = selectedPairYear === 'all' ? 0 : selectedPairYear
    navigate(`/dual-report?year=${yearParam}`)
  }

  if (isLoading && availableYears.length === 0) {
    return (
      <div className="annual-report-page">
        <Loader2 size={32} className="spin" style={{ color: 'var(--text-tertiary)' }} />
        <p style={{ color: 'var(--text-tertiary)', marginTop: 16 }}>正在加载年份数据（首批）...</p>
        <p style={{ color: 'var(--text-tertiary)', marginTop: 8 }}>已耗时 {formatLoadElapsed(loadElapsedMs)}</p>
      </div>
    )
  }

  if (availableYears.length === 0 && !isLoadingMoreYears) {
    return (
      <div className="annual-report-page">
        <Calendar size={64} style={{ color: 'var(--text-tertiary)', opacity: 0.5 }} />
        <h2 style={{ fontSize: 20, fontWeight: 600, color: 'var(--text-primary)', margin: '16px 0 8px' }}>暂无聊天记录</h2>
        <p style={{ color: 'var(--text-tertiary)', margin: 0 }}>
          {loadError || '请先解密数据库后再生成年度报告'}
        </p>
      </div>
    )
  }

  const yearOptions: YearOption[] = availableYears.length > 0
    ? ['all', ...availableYears]
    : []

  const getYearLabel = (value: YearOption | null) => {
    if (!value) return ''
    return value === 'all' ? '全部时间' : `${value} 年`
  }

  const loadedYearCount = availableYears.length
  const isYearStatusComplete = hasYearsLoadFinished
  const renderYearLoadStatus = () => (
    <div className={`year-load-status ${isYearStatusComplete ? 'complete' : 'loading'}`}>
      {isYearStatusComplete ? (
        <>全部年份已加载完毕</>
      ) : (
        <>
          更多年份加载中<span className="dot-ellipsis" aria-hidden="true">...</span>
        </>
      )}
    </div>
  )

  return (
    <div className="annual-report-page">
      <Sparkles size={32} className="header-icon" />
      <h1 className="page-title">年度报告</h1>
      <p className="page-desc">选择年份，回顾你在微信里的点点滴滴</p>
      {loadedYearCount > 0 && (
        <p className={`page-desc load-summary ${isYearStatusComplete ? 'complete' : 'loading'}`}>
          {isYearStatusComplete ? (
            <>已显示 {loadedYearCount} 个年份，年份数据已全部加载完毕。总耗时 {formatLoadElapsed(loadElapsedMs)}</>
          ) : (
            <>
              已显示 {loadedYearCount} 个年份，正在补充更多年份<span className="dot-ellipsis" aria-hidden="true">...</span>
              （已耗时 {formatLoadElapsed(loadElapsedMs)}）
            </>
          )}
        </p>
      )}

      <div className="report-sections">
        <section className="report-section">
          <div className="section-header">
            <div>
              <h2 className="section-title">总年度报告</h2>
              <p className="section-desc">包含所有会话与消息</p>
            </div>
          </div>

          <div className="year-grid-with-status">
            <div className="year-grid">
              {yearOptions.map(option => (
                <div
                  key={option}
                  className={`year-card ${option === 'all' ? 'all-time' : ''} ${selectedYear === option ? 'selected' : ''}`}
                  onClick={() => setSelectedYear(option)}
                >
                  <span className="year-number">{option === 'all' ? '全部' : option}</span>
                  <span className="year-label">{option === 'all' ? '时间' : '年'}</span>
                </div>
              ))}
            </div>
            {renderYearLoadStatus()}
          </div>

          <button
            className="generate-btn"
            onClick={handleGenerateReport}
            disabled={!selectedYear || isGenerating}
          >
            {isGenerating ? (
              <>
                <Loader2 size={20} className="spin" />
                <span>正在生成...</span>
              </>
            ) : (
              <>
                <Sparkles size={20} />
                <span>生成 {getYearLabel(selectedYear)} 年度报告</span>
              </>
            )}
          </button>
        </section>

        <section className="report-section">
          <div className="section-header">
            <div>
              <h2 className="section-title">双人年度报告</h2>
              <p className="section-desc">选择一位好友，只看你们的私聊</p>
            </div>
            <div className="section-badge">
              <Users size={16} />
              <span>私聊</span>
            </div>
          </div>

          <div className="year-grid-with-status">
            <div className="year-grid">
              {yearOptions.map(option => (
                <div
                  key={`pair-${option}`}
                  className={`year-card ${option === 'all' ? 'all-time' : ''} ${selectedPairYear === option ? 'selected' : ''}`}
                  onClick={() => setSelectedPairYear(option)}
                >
                  <span className="year-number">{option === 'all' ? '全部' : option}</span>
                  <span className="year-label">{option === 'all' ? '时间' : '年'}</span>
                </div>
              ))}
            </div>
            {renderYearLoadStatus()}
          </div>

          <button
            className="generate-btn secondary"
            onClick={handleGenerateDualReport}
            disabled={!selectedPairYear}
          >
            <Users size={20} />
            <span>选择好友并生成报告</span>
          </button>
          <p className="section-hint">从聊天排行中选择好友生成双人报告</p>
        </section>
      </div>
    </div>
  )
}

export default AnnualReportPage
