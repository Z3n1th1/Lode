import { useEffect } from 'react'

import AppShell from './components/shell/AppShell'
import { TooltipProvider } from './components/ui/tooltip'
import { applyTheme, useAuth } from './store/auth'
import { useChat } from './store/chat'
import { usePanels } from './store/panels'
import LoginView from './views/LoginView'
import Wordmark from './components/Wordmark'

const POLL_MS = 20_000

/** 登录后:进入目的地就载一次,之后每 20s 刷新仪表盘与当前页面。 */
function useRouteLoader(): void {
  const authenticated = useAuth((state) => state.authenticated)
  const route = useAuth((state) => state.route)

  useEffect(() => {
    if (!authenticated) return
    const polled = route !== 'chat' && route !== 'settings'
    if (polled) void usePanels.getState().load(route)
    const timer = window.setInterval(() => {
      void useAuth.getState().refresh(false)
      if (polled) void usePanels.getState().load(route)
    }, POLL_MS)
    return () => window.clearInterval(timer)
  }, [authenticated, route])
}

let booted = false

export default function App() {
  const authenticated = useAuth((state) => state.authenticated)
  const booting = useAuth((state) => state.booting)
  const theme = useAuth((state) => state.theme)

  // index.html 已经预置了 data-theme,这里只是把 localStorage 里的选择对回来
  useEffect(() => {
    applyTheme(theme)
  }, [theme])

  useEffect(() => {
    if (booted) return
    booted = true
    void useAuth.getState().boot()
  }, [])

  useEffect(() => {
    if (!authenticated) return
    void useChat.getState().bootstrap()
  }, [authenticated])

  useRouteLoader()

  return (
    <TooltipProvider>
      {booting ? <Boot /> : authenticated ? <AppShell /> : <LoginView />}
    </TooltipProvider>
  )
}

function Boot() {
  return (
    <div className="grid h-full place-items-center">
      <Wordmark className="animate-[pulse-dot_1.6s_ease-in-out_infinite]" />
    </div>
  )
}
