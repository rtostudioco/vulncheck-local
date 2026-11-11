// SENTINEL DESK 1.0 — Global client store (Zustand)
// Holds the active view (single-page desktop-style navigation), UI language,
// and the in-app notification center fed by the collector pipeline.

import { create } from 'zustand'
import { translate, type Lang } from '@/lib/i18n'

export type ViewId =
  | 'overview' | 'monitor' | 'detections' | 'incidents' | 'timeline'
  | 'intel' | 'ai' | 'response' | 'reports' | 'settings'

export interface Notification {
  id: string
  kind: 'alert' | 'incident' | 'info'
  severity?: string
  title: string
  body: string
  at: string
  target?: ViewId
}

interface AppState {
  view: ViewId
  setView: (v: ViewId) => void
  lang: Lang
  setLang: (l: Lang) => void
  /** i18n helper bound to current language */
  t: (key: string, vars?: Record<string, string | number>) => string
  notifications: Notification[]
  pushNotifications: (items: Notification[]) => void
  markAllRead: () => void
  unread: number
  /** incident id to open when navigating to incidents/timeline from elsewhere */
  focusIncidentId: string | null
  setFocusIncidentId: (id: string | null) => void
}

export const useApp = create<AppState>((set, get) => ({
  view: 'overview',
  setView: (v) => set({ view: v }),
  lang: 'en',
  // Regenerate `t` on language change so components subscribed to `t`
  // (not to `lang`) still re-render — a stable reference would freeze
  // the previous language in every view.
  setLang: (l) => set({ lang: l, t: (key, vars) => translate(l, key, vars) }),
  t: (key, vars) => translate(get().lang, key, vars),
  notifications: [],
  pushNotifications: (items) =>
    set((s) => ({
      notifications: [...items, ...s.notifications].slice(0, 50),
      unread: s.unread + items.length,
    })),
  markAllRead: () => set({ unread: 0 }),
  unread: 0,
  focusIncidentId: null,
  setFocusIncidentId: (id) => set({ focusIncidentId: id }),
}))
