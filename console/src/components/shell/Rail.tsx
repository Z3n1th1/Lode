import {
  Activity,
  Bug,
  FolderGit2,
  LayoutGrid,
  LogOut,
  type LucideIcon,
  MessageSquare,
  Moon,
  Settings,
  Sun
} from 'lucide-react'

import { cn } from '../../lib/utils'
import { useAuth, type Route } from '../../store/auth'
import { GemMark } from '../Wordmark'
import { Tooltip } from '../ui/tooltip'

const NAV: { route: Route; label: string; icon: LucideIcon }[] = [
  { route: 'chat', label: '对话', icon: MessageSquare },
  { route: 'blackboard', label: '黑板', icon: LayoutGrid },
  { route: 'projects', label: '项目', icon: FolderGit2 },
  { route: 'findings', label: '发现', icon: Bug },
  { route: 'health', label: '运行', icon: Activity }
]

export default function Rail() {
  const route = useAuth((state) => state.route)
  const theme = useAuth((state) => state.theme)
  const setRoute = useAuth((state) => state.setRoute)
  const toggleTheme = useAuth((state) => state.toggleTheme)
  const signOut = useAuth((state) => state.signOut)

  return (
    <nav
      aria-label="主导航"
      className="flex w-13 shrink-0 flex-col items-center gap-1 border-r border-line bg-raised py-3"
    >
      <GemMark size={22} className="mb-3 text-accent" />

      {NAV.map(({ route: target, label, icon: Icon }) => {
        const active = route === target
        return (
          <Tooltip key={target} label={label} side="right">
            <button
              type="button"
              aria-current={active ? 'page' : undefined}
              aria-label={label}
              onClick={() => setRoute(target)}
              className={cn(
                'grid size-9 place-items-center rounded-md transition-colors',
                active ? 'bg-active text-accent' : 'text-fg-3 hover:bg-hover hover:text-fg-2'
              )}
            >
              <Icon size={18} strokeWidth={1.8} />
            </button>
          </Tooltip>
        )
      })}

      <span className="flex-1" />

      <Tooltip label={theme === 'dark' ? '切到浅色' : '切到暗色'} side="right">
        <button
          type="button"
          aria-label={theme === 'dark' ? '切到浅色' : '切到暗色'}
          onClick={toggleTheme}
          className="grid size-9 place-items-center rounded-md text-fg-3 transition-colors hover:bg-hover hover:text-fg-2"
        >
          {theme === 'dark' ? <Sun size={17} strokeWidth={1.8} /> : <Moon size={17} strokeWidth={1.8} />}
        </button>
      </Tooltip>

      <Tooltip label="挖洞设置" side="right">
        <button
          type="button"
          aria-label="挖洞设置"
          aria-current={route === 'settings' ? 'page' : undefined}
          onClick={() => setRoute('settings')}
          className={cn(
            'grid size-9 place-items-center rounded-md transition-colors',
            route === 'settings' ? 'bg-active text-accent' : 'text-fg-3 hover:bg-hover hover:text-fg-2'
          )}
        >
          <Settings size={18} strokeWidth={1.8} />
        </button>
      </Tooltip>

      <Tooltip label="退出" side="right">
        <button
          type="button"
          aria-label="退出登录"
          onClick={() => void signOut()}
          className="grid size-9 place-items-center rounded-md text-fg-3 transition-colors hover:bg-hover hover:text-fg-2"
        >
          <LogOut size={17} strokeWidth={1.8} />
        </button>
      </Tooltip>
    </nav>
  )
}
