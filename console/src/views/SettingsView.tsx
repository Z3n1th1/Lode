import { useEffect, useState, type ReactNode } from 'react'
import { ChevronDown } from 'lucide-react'

import {
  loadLlmSettings,
  saveLlmSettings,
  testLlmProvider,
  type LlmProviderInput
} from '../api'
import PageHeader from '../components/shell/PageHeader'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import EmptyState from '../components/ui/empty-state'
import { Input, MonoInput } from '../components/ui/input'
import { MenuItem, Popover, PopoverContent, PopoverTrigger } from '../components/ui/popover'
import { Switch } from '../components/ui/switch'
import { cn } from '../lib/utils'

const TIER_LABEL: Record<string, string> = {
  reasoner: '推理档',
  explorer: '探索档'
}

type Notice = { tone: 'ok' | 'danger'; text: string } | null

export default function SettingsView() {
  const [providers, setProviders] = useState<LlmProviderInput[]>([])
  const [tiers, setTiers] = useState<Record<string, string>>({})
  const [settingsPath, setSettingsPath] = useState('')
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState<Notice>(null)
  const [testing, setTesting] = useState('')

  useEffect(() => {
    void (async () => {
      try {
        const view = await loadLlmSettings()
        setProviders(
          view.providers.map((item) => ({
            name: item.name,
            base_url: item.base_url,
            model: item.model,
            api_key: undefined
          }))
        )
        setTiers(view.tiers ?? {})
        setSettingsPath(view.settings_path ?? '')
      } catch {
        setNotice({ tone: 'danger', text: '读取模型设置失败' })
      }
    })()
  }, [])

  function patch(name: string, patchValue: Partial<LlmProviderInput>): void {
    setProviders((current) =>
      current.map((item) => (item.name === name ? { ...item, ...patchValue } : item))
    )
  }

  async function save(): Promise<void> {
    setBusy(true)
    setNotice(null)
    try {
      const view = await saveLlmSettings(providers, tiers)
      setProviders(
        view.providers.map((item) => ({
          name: item.name,
          base_url: item.base_url,
          model: item.model,
          api_key: undefined
        }))
      )
      setTiers(view.tiers ?? {})
      setNotice({ tone: 'ok', text: '已保存' })
    } catch (error) {
      setNotice({ tone: 'danger', text: `保存失败:${(error as Error).message}` })
    } finally {
      setBusy(false)
    }
  }

  async function test(name: string): Promise<void> {
    setTesting(name)
    setNotice(null)
    try {
      const result = await testLlmProvider({ provider: providers.find((p) => p.name === name) })
      setNotice(
        result.ok
          ? { tone: 'ok', text: `${name} 可用 · ${result.model} · ${result.latency_ms}ms` }
          : { tone: 'danger', text: `${name} 不可用:${result.error || '未知错误'}` }
      )
    } catch (error) {
      setNotice({ tone: 'danger', text: `测试失败:${(error as Error).message}` })
    } finally {
      setTesting('')
    }
  }

  const names = providers.map((item) => item.name)

  return (
    <section className="flex h-full min-h-0 flex-col">
      <PageHeader
        title="挖洞设置"
        actions={
          <Button variant="primary" size="sm" disabled={busy} onClick={() => void save()}>
            {busy ? '保存中' : '保存'}
          </Button>
        }
      />

      {notice ? (
        <p
          role={notice.tone === 'danger' ? 'alert' : undefined}
          className={cn(
            'shrink-0 border-b border-line px-4 py-1.5 text-sm',
            notice.tone === 'ok' ? 'bg-ok/8 text-ok' : 'bg-danger/8 text-danger'
          )}
        >
          {notice.text}
        </p>
      ) : null}

      <div className="min-h-0 flex-1 overflow-y-auto">
        <h2 className="border-b border-line bg-raised/60 px-4 py-1.5 font-mono text-2xs tracking-wide text-fg-3">
          模型上游
        </h2>

        {providers.length ? (
          providers.map((provider) => (
            <div key={provider.name} className="border-b border-line px-4 py-4">
              <div className="flex items-center gap-3">
                <span className="font-mono text-sm text-fg">{provider.name}</span>
                <span className="flex-1" />
                <Button
                  variant="quiet"
                  size="sm"
                  disabled={testing === provider.name}
                  onClick={() => void test(provider.name)}
                >
                  {testing === provider.name ? '测试中' : '测通'}
                </Button>
              </div>

              <div className="mt-3 grid gap-3 md:grid-cols-2">
                <Field label="Base URL">
                  <MonoInput
                    value={provider.base_url}
                    onChange={(event) => patch(provider.name, { base_url: event.target.value })}
                    spellCheck={false}
                  />
                </Field>
                <Field label="模型">
                  <MonoInput
                    value={provider.model}
                    onChange={(event) => patch(provider.name, { model: event.target.value })}
                    spellCheck={false}
                  />
                </Field>
                <Field label="API Key" hint="留空表示不修改">
                  <Input
                    type="password"
                    autoComplete="off"
                    spellCheck={false}
                    placeholder="••••••••"
                    value={provider.api_key ?? ''}
                    onChange={(event) => patch(provider.name, { api_key: event.target.value })}
                  />
                </Field>
                <Field label="清除已存 Key">
                  <label className="flex h-9 items-center gap-2 text-sm text-fg-2">
                    <Switch
                      checked={Boolean(provider.clear_key)}
                      onCheckedChange={(checked) => patch(provider.name, { clear_key: checked })}
                    />
                    保存时删除该上游的密钥
                  </label>
                </Field>
              </div>
            </div>
          ))
        ) : (
          <EmptyState title="暂无上游配置" hint="加一个上游后才能给分层模型选具体模型" />
        )}

        <h2 className="border-y border-line bg-raised/60 px-4 py-1.5 font-mono text-2xs tracking-wide text-fg-3">
          分层模型
        </h2>
        <div className="grid gap-3 px-4 py-4 md:grid-cols-2">
          {Object.keys(TIER_LABEL).map((tier) => (
            <Field key={tier} label={TIER_LABEL[tier]}>
              <Popover>
                <PopoverTrigger asChild>
                  <button
                    type="button"
                    className="flex h-9 w-full items-center gap-2 rounded-md border border-line px-2.5 text-left font-mono text-xs text-fg-2 transition-colors hover:border-line-strong"
                  >
                    {tiers[tier] || '未指定'}
                    <span className="flex-1" />
                    {tiers[tier] ? <Badge tone="neutral">{tier}</Badge> : null}
                    {/* 触发器原来和输入框长得一样,没有任何"这是个下拉"的迹象 */}
                    <ChevronDown size={13} className="shrink-0 text-fg-4" />
                  </button>
                </PopoverTrigger>
                <PopoverContent className="w-[var(--radix-popover-trigger-width)]">
                  {names.map((name) => (
                    <MenuItem
                      key={name}
                      selected={tiers[tier] === name}
                      onClick={() => setTiers((current) => ({ ...current, [tier]: name }))}
                    >
                      {name}
                    </MenuItem>
                  ))}
                  <MenuItem selected={!tiers[tier]} onClick={() => setTiers((current) => ({ ...current, [tier]: '' }))}>
                    未指定
                  </MenuItem>
                </PopoverContent>
              </Popover>
            </Field>
          ))}
        </div>

        {/* 路径是"东西存在哪"的元信息,属于页脚;放在页头只是噪音 */}
        {settingsPath ? (
          <footer className="border-t border-line px-4 py-3">
            <span className="font-mono text-2xs text-fg-4">配置路径</span>
            <span className="ml-2 font-mono text-2xs break-all text-fg-3">{settingsPath}</span>
          </footer>
        ) : null}
      </div>
    </section>
  )
}

function Field({
  label,
  hint,
  children
}: {
  label: string
  hint?: string
  children: ReactNode
}) {
  return (
    <label className="block">
      <span className="flex items-baseline gap-2">
        <span className="font-mono text-2xs text-fg-4">{label}</span>
        {hint ? <span className="text-xs text-fg-4">{hint}</span> : null}
      </span>
      <span className="mt-1.5 block">{children}</span>
    </label>
  )
}
