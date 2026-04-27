export interface ContactSnsTimelineTarget {
  username: string
  displayName: string
  avatarUrl?: string
  candidateUsernames?: string[]
}

export interface ContactSnsRankItem {
  name: string
  count: number
  latestTime: number
}

export type ContactSnsRankMode = 'likes' | 'comments'

export const isSingleContactSession = (sessionId: string): boolean => {
  const normalized = String(sessionId || '').trim()
  if (!normalized) return false
  if (normalized.includes('@chatroom')) return false
  if (normalized.startsWith('gh_')) return false
  return true
}

export const getAvatarLetter = (name: string): string => {
  if (!name) return '?'
  return [...name][0] || '?'
}

export const normalizeTimelineAccountId = (value?: string | null): string => {
  const trimmed = String(value || '').trim()
  if (!trimmed) return ''
  if (trimmed.toLowerCase().startsWith('wxid_')) {
    const match = trimmed.match(/^(wxid_[^_]+)/i)
    return (match?.[1] || trimmed).toLowerCase()
  }
  const suffixMatch = trimmed.match(/^(.+)_([a-zA-Z0-9]{4})$/)
  return (suffixMatch ? suffixMatch[1] : trimmed).toLowerCase()
}

export const buildTimelineTargetUsernames = (...values: Array<string | undefined | null>): string[] => {
  const seen = new Set<string>()
  const result: string[] = []

  for (const value of values) {
    const trimmed = String(value || '').trim()
    if (!trimmed) continue
    const candidates = [trimmed, normalizeTimelineAccountId(trimmed)]
    for (const candidate of candidates) {
      const normalized = String(candidate || '').trim()
      if (!normalized) continue
      const lowered = normalized.toLowerCase()
      if (seen.has(lowered)) continue
      seen.add(lowered)
      result.push(normalized)
    }
  }

  return result
}
