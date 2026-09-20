import { ChevronsUpDown, FileUp, ShieldCheck } from 'lucide-react'
import { useRef, useState, type ReactNode } from 'react'

import { Badge } from '../ui/badge'
import { Button } from '../ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle
} from '../ui/dialog'
import { Input, MonoInput } from '../ui/input'
import { MenuItem, Popover, PopoverContent, PopoverTrigger } from '../ui/popover'
import { Switch } from '../ui/switch'
import { cn } from '../../lib/utils'
import { formatTimestamp } from '../../dashboard'
import { rejectLabel, scopePreviewRows } from '../../scopeDocument'
import { enabledOptionLabels, usePanels, type IntakeToggles } from '../../store/panels'

/** 开关的文案与分组:顺序即阅读顺序。 */
const TOGGLES: { key: keyof IntakeToggles; label: string }[] = [
  { key: 'asset_inventory', label: '资产清单' },
  { key: 'subdomain_enum', label: '子域枚举' },
  { key: 'fingerprint_precise', label: '精确指纹' },
  { key: 'scan_enabled', label: '主动扫描' },
  { key: 'nuclei', label: 'Nuclei 模板' },
  { key: 'tscan', label: 'TScan' },
  { key: 'intel', label: '情报关联' },
  { key: 'poc_research', label: 'PoC 检索' },
  { key: 'proxy_route', label: '代理路由' },
  { key: 'network_gate', label: '出站门' },
  { key: 'edge_human_gate', label: '边界人工门' }
]

/** 确认单的一行。宽度固定,免得两列在长 URL 上歪掉。 */
function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[76px_minmax(0,1fr)] items-baseline gap-3">
      <span className="font-mono text-2xs text-fg-4">{label}</span>
      <span className="min-w-0 break-all font-mono text-xs text-fg">{children}</span>
    </div>
  )
}

export default function NewProjectModal() {
  const open = usePanels((state) => state.newProjectOpen)
  const form = usePanels((state) => state.intakeForm)
  const options = usePanels((state) => state.profileOptions)
  const submitting = usePanels((state) => state.intakeSubmitting)
  const error = usePanels((state) => state.intakeError)
  const ok = usePanels((state) => state.intakeOk)
  const preview = usePanels((state) => state.intakePreview)
  const result = usePanels((state) => state.intakeResult)
  // 授权文档那条路。它和上面那条共用同一个待确认槽,所以两组状态不会同时有效。
  const scopePreview = usePanels((state) => state.scopePreview)
  const scopeResult = usePanels((state) => state.scopeResult)
  const scopeText = usePanels((state) => state.scopeText)
  const scopeFilename = usePanels((state) => state.scopeFilename)
  const scopeRejects = usePanels((state) => state.scopeRejects)
  const [profileOpen, setProfileOpen] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)

  const selected = options.find((option) => option.value === form.engagement_profile)
  const enabledLabels = preview ? enabledOptionLabels(preview.options) : []
  const scopeRows = scopePreview ? scopePreviewRows(scopePreview.summary) : []

  function toggle(key: keyof IntakeToggles, value: boolean): void {
    usePanels.getState().patchIntakeForm({ toggles: { ...form.toggles, [key]: value } })
  }

  /** 上传就是读成文本再走粘贴那条路 —— 所以只有一个判定、一道闸门。 */
  async function pickFile(file: File | undefined): Promise<void> {
    if (!file) return
    const text = await file.text()
    usePanels.getState().patchScopeText(text, file.name)
  }

  return (
    <Dialog open={open} onOpenChange={(next) => usePanels.getState().setNewProjectOpen(next)}>
      <DialogContent width={620}>
        <DialogHeader>
          <DialogTitle>
            {scopeResult ? '已落授权记录'
              : scopePreview ? '确认这份授权文档'
              : result ? '已建卡'
              : preview ? '确认后再建卡'
              : '新建项目'}
          </DialogTitle>
        </DialogHeader>

        <DialogBody>
          {scopeResult ? (
            <div className="grid gap-3">
              <div className="flex items-center gap-2">
                <Badge tone="ok">
                  <ShieldCheck size={11} />
                  已落盘
                </Badge>
                <span className="text-sm text-fg-3">授权记录是不可变的,一次 run 能指回它的原文</span>
              </div>
              <Row label="程序">{scopeResult.program}</Row>
              <Row label="授权记录">{scopeResult.authorization_id}</Row>
              <Row label="记录文件">{scopeResult.authorization_ref}</Row>
              <Row label="文档摘要">{scopeResult.document_digest.slice(0, 16)}…</Row>
              <Row label="授权主机">{scopeResult.hosts.length} 台</Row>
              {scopeResult.run ? (
                <>
                  <Row label="会话">{scopeResult.run.session_id}</Row>
                  <Row label="任务">{scopeResult.run.job_ids.length} 个</Row>
                </>
              ) : null}
              <p className="text-sm text-fg-4">{scopeResult.note}</p>
            </div>
          ) : scopePreview ? (
            <div className="grid gap-3">
              <div className="grid gap-3 rounded-sm border border-accent/40 bg-accent-soft/40 p-3.5">
                {scopeRows.map((row) => (
                  <Row key={row.label} label={row.label}>
                    <span className={row.warn ? 'text-warn' : undefined}>{row.value}</span>
                  </Row>
                ))}
                <Row label="确认单">{scopePreview.options_digest.slice(0, 16)}…</Row>
              </div>
              <p className="text-sm text-fg-4">
                确认之前不发起任何请求。确认后落授权记录,并按上面的台数开跑 ——{' '}
                {formatTimestamp(scopePreview.expires_at ?? null)} 之前有效。
              </p>
            </div>
          ) : result ? (
            <div className="grid gap-3">
              <div className="flex items-center gap-2">
                <Badge tone="ok">
                  <ShieldCheck size={11} />
                  已落盘
                </Badge>
                <span className="text-sm text-fg-3">确认单已写进不可变的 TargetCard</span>
              </div>
              <Row label="目标">{result.target}</Row>
              <Row label="target_id">{result.target_id}</Row>
              <Row label="卡文件">{result.target_card_ref}</Row>
              <Row label="卡摘要">{result.target_card_digest.slice(0, 16)}…</Row>
              {result.run ? (
                <>
                  <Row label="会话">{result.run.session_id}</Row>
                  <Row label="任务">{result.run.job_id}</Row>
                </>
              ) : null}
              <p className="text-sm text-fg-4">{result.note}</p>
            </div>
          ) : preview ? (
            <div className="grid gap-3">
              <div className="grid gap-3 rounded-sm border border-accent/40 bg-accent-soft/40 p-3.5">
                <Row label="目标">{preview.target}</Row>
                <Row label="主机">{preview.canonical_host}</Row>
                <Row label="入口">{preview.entrypoint}</Row>
                <Row label="策略档">{preview.profile_name}</Row>
                <Row label="说明">{preview.instruction}</Row>
                <Row label="开关">
                  {enabledLabels.length ? (
                    <span className="flex flex-wrap gap-1">
                      {enabledLabels.map((label) => (
                        <Badge key={label} tone="accent">
                          {label}
                        </Badge>
                      ))}
                    </span>
                  ) : (
                    '全部关闭'
                  )}
                </Row>
                <Row label="确认单">{preview.options_digest.slice(0, 16)}…</Row>
              </div>
              <p className="text-sm text-fg-4">
                到这里为止什么都没跑。确认后按这张单落卡并立刻开跑,{formatTimestamp(preview.expires_at)} 之前有效。
              </p>
            </div>
          ) : (
            <div className="grid gap-3.5">
              <label className="block">
                <span className="font-mono text-2xs text-fg-4">目标 URL</span>
                <MonoInput
                  className="mt-1.5"
                  value={form.target_url}
                  spellCheck={false}
                  placeholder="https://example.com"
                  onChange={(event) =>
                    usePanels.getState().patchIntakeForm({ target_url: event.target.value })
                  }
                />
              </label>

              <label className="block">
                <span className="font-mono text-2xs text-fg-4">这次要看什么</span>
                <Input
                  className="mt-1.5"
                  value={form.instruction}
                  placeholder="只看登录与权限校验"
                  onChange={(event) =>
                    usePanels.getState().patchIntakeForm({ instruction: event.target.value })
                  }
                />
              </label>

              <div>
                <span className="font-mono text-2xs text-fg-4">策略档</span>
                <Popover open={profileOpen} onOpenChange={setProfileOpen}>
                  <PopoverTrigger asChild>
                    <button
                      type="button"
                      className="mt-1.5 flex h-9 w-full items-center gap-2 rounded-md border border-line px-2.5 text-left font-mono text-xs text-fg-2 transition-colors hover:border-line-strong"
                    >
                      {selected?.label || form.engagement_profile || '未选择'}
                      <span className="flex-1" />
                      <ChevronsUpDown size={12} className="text-fg-4" />
                    </button>
                  </PopoverTrigger>
                  <PopoverContent className="w-[var(--radix-popover-trigger-width)]">
                    {options.map((option) => (
                      <MenuItem
                        key={option.value}
                        selected={option.value === form.engagement_profile}
                        onClick={() => {
                          usePanels.getState().patchIntakeForm({ engagement_profile: option.value })
                          setProfileOpen(false)
                        }}
                      >
                        {option.label}
                      </MenuItem>
                    ))}
                  </PopoverContent>
                </Popover>
              </div>

              <div>
                <span className="font-mono text-2xs text-fg-4">动作开关</span>
                <div className="mt-2 grid grid-cols-2 gap-x-6 gap-y-2 md:grid-cols-3">
                  {TOGGLES.map(({ key, label }) => (
                    <label key={key} className="flex items-center gap-2 text-sm text-fg-2">
                      <Switch checked={form.toggles[key]} onCheckedChange={(value) => toggle(key, value)} />
                      {label}
                    </label>
                  ))}
                </div>
              </div>

              <div className="border-t border-line pt-3.5">
                <span className="font-mono text-2xs text-fg-4">或者:贴一份授权文档(scope 文件)</span>
                <p className="mt-1.5 text-xs text-fg-4">
                  程序文档写的常是"所有流量 ≤ 3 req/s"加一长串精确主机名。贴**整份** JSON,
                  每台主机会各自起一个任务,共用一份预算。域名通配不收 —— 只收精确主机名。
                </p>
                <textarea
                  className="mt-2 h-24 w-full resize-y rounded-md border border-line bg-transparent p-2.5 font-mono text-xs text-fg outline-none transition-colors focus:border-line-strong"
                  spellCheck={false}
                  placeholder='{"program": "…", "authorization": "…", "allowed_hosts": ["api.example.com"]}'
                  value={scopeText}
                  onChange={(event) => usePanels.getState().patchScopeText(event.target.value)}
                />
                <div className="mt-2 flex items-center gap-2">
                  <input
                    ref={fileRef}
                    type="file"
                    accept=".json,application/json"
                    className="hidden"
                    onChange={(event) => void pickFile(event.target.files?.[0])}
                  />
                  <Button variant="outline" size="sm" onClick={() => fileRef.current?.click()}>
                    <FileUp size={12} />
                    选文件
                  </Button>
                  <span className="min-w-0 flex-1 truncate font-mono text-2xs text-fg-4">
                    {scopeFilename || (scopeText ? `已粘贴 ${scopeText.length} 字符` : '还没有内容')}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={submitting}
                    onClick={() => void usePanels.getState().submitScopeDocument()}
                  >
                    读这份文档
                  </Button>
                </div>
                {scopeRejects.length ? (
                  <ul className="mt-2 grid gap-1">
                    {scopeRejects.slice(-3).map((reject, index) => (
                      <li key={`${reject.file}-${index}`} className="text-xs text-warn">
                        {rejectLabel(reject)}
                      </li>
                    ))}
                  </ul>
                ) : null}
              </div>

              <p
                className={cn(
                  'min-h-5 text-sm',
                  error ? 'text-danger' : ok ? 'text-ok' : 'text-fg-4'
                )}
                role={error ? 'alert' : undefined}
              >
                {error || ok || '下一步只是预览:确认之前不会执行、也不会落卡。'}
              </p>
            </div>
          )}

          {preview || result ? (
            <p
              className={cn('mt-3 min-h-5 text-sm', error ? 'text-danger' : 'text-fg-4')}
              role={error ? 'alert' : undefined}
            >
              {error}
            </p>
          ) : null}
        </DialogBody>

        <DialogFooter>
          {scopeResult ? (
            <Button variant="outline" size="sm" onClick={() => usePanels.getState().setNewProjectOpen(false)}>
              完成
            </Button>
          ) : scopePreview ? (
            <>
              <Button
                variant="outline"
                size="sm"
                disabled={submitting}
                onClick={() => void usePanels.getState().discardScopeDocument()}
              >
                放弃
              </Button>
              <Button
                variant="primary"
                size="sm"
                disabled={submitting}
                onClick={() => void usePanels.getState().confirmScopeDocument()}
              >
                {submitting ? '开跑中' : '确认并开跑'}
              </Button>
            </>
          ) : result ? (
            <>
              <Button variant="outline" size="sm" onClick={() => usePanels.getState().setNewProjectOpen(false)}>
                完成
              </Button>
              {result.run ? (
                <Button variant="primary" size="sm" onClick={() => void usePanels.getState().openIntakeRun()}>
                  去看运行
                </Button>
              ) : null}
            </>
          ) : preview ? (
            <>
              <Button
                variant="outline"
                size="sm"
                disabled={submitting}
                onClick={() => void usePanels.getState().discardIntake()}
              >
                放弃
              </Button>
              <Button
                variant="primary"
                size="sm"
                disabled={submitting}
                onClick={() => void usePanels.getState().confirmIntake()}
              >
                {submitting ? '开跑中' : '确认并开跑'}
              </Button>
            </>
          ) : (
            <>
              <Button variant="outline" size="sm" onClick={() => usePanels.getState().setNewProjectOpen(false)}>
                取消
              </Button>
              <Button
                variant="primary"
                size="sm"
                disabled={submitting}
                onClick={() => void usePanels.getState().submitIntake()}
              >
                {submitting ? '预览中' : '预览确认单'}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
