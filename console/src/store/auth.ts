// 壳层状态:主题、登录门、当前目的地、仪表盘快照。
// 轮询由 App 里的 useEffect 统一驱动(见 hooks/usePolling),store 只管状态。
import { create } from 'zustand'

import { ApiError, loadDashboard, login as apiLogin, logout as apiLogout } from '../api'
import {
  createDashboardView,
  type DashboardSnapshot,
  type DashboardView
} from '../dashboard'

export type Theme = 'dark' | 'light'

/** 左侧导航的目的地。面板不再是抽屉,而是主区域里的页面。 */
export type Route = 'chat' | 'blackboard' | 'projects' | 'findings' | 'health' | 'settings'

const THEME_KEY = 'lode.theme'

function readTheme(): Theme {
  try {
    return localStorage.getItem(THEME_KEY) === 'light' ? 'light' : 'dark'
  } catch {
    return 'dark'
  }
}

/** 把主题写到 <html data-theme>,CSS 令牌据此换取值。 */
export function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme
  // 移动端状态栏跟着底走,否则暗色页面配一条白边很割裂。
  // 这两个值必须和 globals.css 里 --app-bg 的暗/浅取值一致,否则状态栏会和页面差一档。
  const meta = document.querySelector('meta[name="theme-color"]')
  if (meta) meta.setAttribute('content', theme === 'dark' ? '#0a0c0d' : '#fbfbfa')
}

interface AuthState {
  theme: Theme
  authenticated: boolean
  booting: boolean
  refreshing: boolean
  route: Route
  snapshot: DashboardSnapshot | null
  loginError: string
  loggingIn: boolean

  toggleTheme: () => void
  setRoute: (route: Route) => void
  boot: () => Promise<void>
  refresh: (showSpinner?: boolean) => Promise<void>
  submitLogin: (password: string) => Promise<void>
  signOut: () => Promise<void>
}

export const useAuth = create<AuthState>()((set, get) => ({
  theme: readTheme(),
  authenticated: false,
  booting: true,
  refreshing: false,
  route: 'chat',
  snapshot: null,
  loginError: '',
  loggingIn: false,

  toggleTheme() {
    const theme: Theme = get().theme === 'dark' ? 'light' : 'dark'
    try {
      localStorage.setItem(THEME_KEY, theme)
    } catch {
      /* 隐私模式:记不住也行 */
    }
    applyTheme(theme)
    set({ theme })
  },

  setRoute(route) {
    set({ route })
  },

  async refresh(showSpinner = true) {
    if (showSpinner) set({ refreshing: true })
    try {
      const snapshot = await loadDashboard()
      set({ snapshot, authenticated: true })
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        set({ authenticated: false, snapshot: null })
      }
    } finally {
      set({ booting: false, refreshing: false })
    }
  },

  async boot() {
    applyTheme(get().theme)
    await get().refresh(false)
  },

  async submitLogin(password) {
    set({ loginError: '' })
    if (!password) {
      set({ loginError: '请输入口令' })
      return
    }
    set({ loggingIn: true })
    try {
      await apiLogin(password)
      await get().refresh()
    } catch {
      set({ loginError: '口令校验失败' })
    } finally {
      set({ loggingIn: false })
    }
  },

  async signOut() {
    try {
      await apiLogout()
    } finally {
      set({ authenticated: false, snapshot: null })
    }
  }
}))

export function dashboardView(snapshot: DashboardSnapshot | null): DashboardView | null {
  return snapshot ? createDashboardView(snapshot) : null
}
