import React, { useState, useEffect, useRef, useMemo } from 'react'
import { Loader2, User } from 'lucide-react'
import { avatarLoadQueue } from '../utils/AvatarLoadQueue'
import './Avatar.scss'

// 全局缓存已成功加载过的头像 URL，用于控制后续是否显示动画
const loadedAvatarCache = new Set<string>()
const proxiedAvatarCache = new Map<string, string>()
const proxiedAvatarLoading = new Map<string, Promise<string | null>>()

const canProxyAvatar = (url?: string): url is string => {
    if (!url) return false
    return /^https?:\/\/([^/]+\.)?(qlogo\.cn|qpic\.cn|qq\.com|wechat\.com|weixin\.qq\.com)\//i.test(url)
}

const fetchProxiedAvatar = (url: string): Promise<string | null> => {
    const cached = proxiedAvatarCache.get(url)
    if (cached) return Promise.resolve(cached)

    const existing = proxiedAvatarLoading.get(url)
    if (existing) return existing

    const fetchAvatarDataUrl = window.electronAPI?.chat?.fetchAvatarDataUrl
    if (!fetchAvatarDataUrl) return Promise.resolve(null)

    const request = fetchAvatarDataUrl(url)
        .then((result) => {
            const dataUrl = result?.success ? result.dataUrl : undefined
            if (dataUrl) {
                proxiedAvatarCache.set(url, dataUrl)
                return dataUrl
            }
            return null
        })
        .catch(() => null)
        .finally(() => {
            proxiedAvatarLoading.delete(url)
        })

    proxiedAvatarLoading.set(url, request)
    return request
}

interface AvatarProps {
    src?: string
    name?: string
    size?: number | string
    shape?: 'circle' | 'square' | 'rounded'
    className?: string
    lazy?: boolean
    loading?: boolean
    onClick?: () => void
}

export const Avatar = React.memo(function Avatar({
    src,
    name,
    size = 48,
    shape = 'rounded',
    className = '',
    lazy = true,
    loading = false,
    onClick
}: AvatarProps) {
    // 如果 URL 已在缓存中，则直接标记为已加载，不显示骨架屏和淡入动画
    const isCached = useMemo(() => src ? loadedAvatarCache.has(src) : false, [src])
    const isFailed = useMemo(() => src && lazy ? avatarLoadQueue.hasFailed(src) : false, [src, lazy])
    const [imageLoaded, setImageLoaded] = useState(isCached)
    const [imageError, setImageError] = useState(isFailed)
    const [shouldLoad, setShouldLoad] = useState(!lazy || isCached)
    const [isInQueue, setIsInQueue] = useState(false)
    const [displaySrc, setDisplaySrc] = useState(() => src ? (proxiedAvatarCache.get(src) || src) : undefined)
    const [proxyTried, setProxyTried] = useState(false)
    const imgRef = useRef<HTMLImageElement>(null)
    const containerRef = useRef<HTMLDivElement>(null)

    const getAvatarLetter = (): string => {
        if (!name) return '?'
        const chars = [...name]
        return chars[0] || '?'
    }

    // Intersection Observer for lazy loading
    useEffect(() => {
        if (!lazy || shouldLoad || isInQueue || !src || !containerRef.current || isCached || imageError || isFailed) return

        const observer = new IntersectionObserver(
            (entries) => {
                entries.forEach((entry) => {
                    if (entry.isIntersecting && !isInQueue) {
                        setIsInQueue(true)
                        avatarLoadQueue.enqueue(src).then(() => {
                            setImageError(false)
                            setShouldLoad(true)
                        }).catch(() => {
                            if (canProxyAvatar(src)) {
                                void fetchProxiedAvatar(src).then((dataUrl) => {
                                    if (dataUrl) {
                                        setDisplaySrc(dataUrl)
                                        setImageError(false)
                                        setShouldLoad(true)
                                        return
                                    }
                                    setImageError(true)
                                    setShouldLoad(false)
                                })
                                return
                            }
                            setImageError(true)
                            setShouldLoad(false)
                        }).finally(() => {
                            setIsInQueue(false)
                        })
                        observer.disconnect()
                    }
                })
            },
            { rootMargin: '100px' }
        )

        observer.observe(containerRef.current)

        return () => observer.disconnect()
    }, [src, lazy, shouldLoad, isInQueue, isCached, imageError, isFailed])

    // Reset state when src changes
    useEffect(() => {
        const cached = src ? loadedAvatarCache.has(src) : false
        const failed = src && lazy ? avatarLoadQueue.hasFailed(src) : false
        if (src && !lazy) {
            avatarLoadQueue.clearFailed(src)
        }
        setDisplaySrc(src ? (proxiedAvatarCache.get(src) || src) : undefined)
        setProxyTried(false)
        setImageLoaded(cached)
        setImageError(failed)
        if (failed) {
            setShouldLoad(false)
            setIsInQueue(false)
        } else if (lazy && !cached) {
            setShouldLoad(false)
            setIsInQueue(false)
        } else {
            setShouldLoad(true)
        }
    }, [src, lazy])

    // Check if image is already cached/loaded
    useEffect(() => {
        if (shouldLoad && imgRef.current?.complete && imgRef.current?.naturalWidth > 0) {
            setImageLoaded(true)
        }
    }, [displaySrc, shouldLoad])

    const style = {
        width: typeof size === 'number' ? `${size}px` : size,
        height: typeof size === 'number' ? `${size}px` : size,
    }

    const hasValidUrl = !!displaySrc && !imageError && shouldLoad
    const shouldShowLoadingPlaceholder = loading && !hasValidUrl && !imageError

    return (
        <div
            ref={containerRef}
            className={`avatar-component ${shape} ${className}`}
            style={style}
            onClick={onClick}
        >
            {hasValidUrl ? (
                <>
                    {!imageLoaded && <div className="avatar-skeleton" />}
                    <img
                        ref={imgRef}
                        src={displaySrc}
                        alt={name || 'avatar'}
                        className={`avatar-image ${imageLoaded ? 'loaded' : ''} ${isCached ? 'instant' : ''}`}
                        onLoad={() => {
                            if (src) {
                                avatarLoadQueue.clearFailed(src)
                                loadedAvatarCache.add(src)
                            }
                            if (displaySrc) loadedAvatarCache.add(displaySrc)
                            setImageLoaded(true)
                            setImageError(false)
                        }}
                        onError={() => {
                            if (src && displaySrc === src && canProxyAvatar(src) && !proxyTried) {
                                setProxyTried(true)
                                setImageLoaded(false)
                                setImageError(false)
                                void fetchProxiedAvatar(src).then((dataUrl) => {
                                    if (dataUrl) {
                                        avatarLoadQueue.clearFailed(src)
                                        setDisplaySrc(dataUrl)
                                        setShouldLoad(true)
                                        return
                                    }
                                    avatarLoadQueue.markFailed(src)
                                    loadedAvatarCache.delete(src)
                                    setImageError(true)
                                    setShouldLoad(false)
                                })
                                return
                            }
                            if (src) {
                                avatarLoadQueue.markFailed(src)
                                loadedAvatarCache.delete(src)
                            }
                            if (displaySrc) loadedAvatarCache.delete(displaySrc)
                            setImageLoaded(false)
                            setImageError(true)
                            setShouldLoad(false)
                        }}
                        loading={lazy ? "lazy" : "eager"}
                        referrerPolicy="no-referrer"
                    />
                </>
            ) : shouldShowLoadingPlaceholder ? (
                <div className="avatar-loading">
                    <Loader2 size="50%" className="avatar-loading-icon" />
                </div>
            ) : (
                <div className="avatar-placeholder">
                    {name ? <span className="avatar-letter">{getAvatarLetter()}</span> : <User size="50%" />}
                </div>
            )}
        </div>
    )
})
