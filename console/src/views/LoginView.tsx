import { useState, type FormEvent } from 'react'
import { Moon, Sun } from 'lucide-react'

import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import Wordmark from '../components/Wordmark'
import { useAuth } from '../store/auth'

export default function LoginView() {
  const [password, setPassword] = useState('')
  const loggingIn = useAuth((state) => state.loggingIn)
  const loginError = useAuth((state) => state.loginError)
  const theme = useAuth((state) => state.theme)
  const toggleTheme = useAuth((state) => state.toggleTheme)

  async function submit(event: FormEvent) {
    event.preventDefault()
    await useAuth.getState().submitLogin(password)
    setPassword('')
  }

  return (
    <div className="relative grid h-full place-items-center px-6">
      <button
        type="button"
        aria-label={theme === 'dark' ? '切到浅色' : '切到暗色'}
        onClick={toggleTheme}
        className="absolute top-4 right-4 grid size-9 place-items-center rounded-md text-fg-3 transition-colors hover:bg-hover hover:text-fg-2"
      >
        {theme === 'dark' ? <Sun size={18} strokeWidth={1.8} /> : <Moon size={18} strokeWidth={1.8} />}
      </button>

      {/* 只有品牌、一条分隔线和一个口令框 —— 登录页没有别的事要做 */}
      <div className="w-full max-w-[25rem] -translate-y-[8%]">
        <h1>
          <Wordmark size={24} />
        </h1>
        <div className="mt-5 h-px bg-line" />

        <form onSubmit={submit} className="mt-5">
          <label htmlFor="password" className="block font-mono text-[10.5px] tracking-wide text-fg-4">
            口令
          </label>
          <div className="mt-2 flex items-center gap-2">
            <Input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              autoFocus
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              aria-invalid={Boolean(loginError)}
              aria-describedby={loginError ? 'password-error' : undefined}
              className="h-10 flex-1"
            />
            <Button
              type="submit"
              variant="primary"
              disabled={loggingIn || !password}
              className="h-10 px-4"
            >
              {loggingIn ? '校验中' : '进入'}
            </Button>
          </div>
          {/* 错误占固定高度,免得出现时整页跳一下 */}
          <p
            id="password-error"
            role={loginError ? 'alert' : undefined}
            className="mt-2 h-5 text-[12px] text-danger"
          >
            {loginError}
          </p>
        </form>
      </div>
    </div>
  )
}
