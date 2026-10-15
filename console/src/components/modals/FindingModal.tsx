import { Download, RefreshCw, RotateCcw, Save } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'

import {
  ApiError, createFindingRetest, loadFindingDetail, recordFindingRetestResult, saveFindingReport,
  type FindingDetail, type FindingRetest, type FindingRow
} from '../../api'
import { formatTimestamp } from '../../dashboard'
import { downloadMarkdown, errorMessage, RETEST_LABEL, retestKey } from '../../findings'
import { useAuth } from '../../store/auth'
import { useChat } from '../../store/chat'
import { Badge, severityTone } from '../ui/badge'
import { Button } from '../ui/button'
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '../ui/dialog'
import { Input, Textarea } from '../ui/input'

type Tab = 'overview' | 'report' | 'retests'
const TABS: Array<[Tab, string]> = [['overview', '概览与证据'], ['report', '报告'], ['retests', '复测记录']]
const POLL_MS = 2_500

function TextBlock({ children }: { children: string }) {
  // Reports and remote response bodies are untrusted text. React escapes them;
  // no HTML renderer, remote image fetches, or executable Markdown links.
  return <pre className="rounded-md border border-line bg-raised/50 p-3 font-mono text-xs leading-relaxed break-words whitespace-pre-wrap text-fg-2">{children}</pre>
}

export default function FindingModal({ row, onClose, onChanged }: {
  row: FindingRow
  onClose: () => void
  onChanged: () => void
}) {
  const id = row.finding_id || ''
  const [tab, setTab] = useState<Tab>('overview')
  const [detail, setDetail] = useState<FindingDetail | null>(null)
  const [loading, setLoading] = useState(Boolean(id))
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [refresh, setRefresh] = useState(0)
  const [busy, setBusy] = useState(false)
  const busyRef = useRef(false)
  const mounted = useRef(true)
  const [draft, setDraft] = useState('')
  const draftDirty = useRef(false)
  const [digest, setDigest] = useState('')
  const [conflict, setConflict] = useState(false)
  const [editing, setEditing] = useState(false)
  const [notes, setNotes] = useState('')
  const [manualId, setManualId] = useState('')

  useEffect(() => {
    mounted.current = true
    return () => { mounted.current = false }
  }, [])

  useEffect(() => {
    if (!id) return
    const controller = new AbortController()
    let timer: number | undefined
    let disposed = false
    async function read() {
      try {
        const result = await loadFindingDetail(id, controller.signal)
        if (disposed) return
        setDetail(result)
        setError('')
        if (!draftDirty.current) {
          setDraft(result.report || result.report_template || '')
          setDigest(result.evidence_digest)
        }
        // Recursive timeout starts only after the prior request completes.
        // Recorded/manual and completed entries never start a polling loop.
        if (result.retests.some((item) => item.status === 'queued' || item.status === 'running')) {
          timer = window.setTimeout(() => void read(), POLL_MS)
        }
      } catch (problem) {
        if (!disposed) setError(errorMessage(problem))
      } finally {
        if (!disposed) setLoading(false)
      }
    }
    void read()
    return () => {
      disposed = true
      controller.abort()
      if (timer !== undefined) window.clearTimeout(timer)
    }
  }, [id, refresh])

  async function mutate(action: () => Promise<void>) {
    if (busyRef.current) return
    busyRef.current = true
    setBusy(true)
    setError('')
    setNotice('')
    try {
      await action()
      if (!mounted.current) return
      setRefresh((value) => value + 1)
      onChanged()
    } catch (problem) {
      if (!mounted.current) return
      if (problem instanceof ApiError && problem.status === 409 && tab === 'report') {
        setConflict(true)
        setError('证据或报告已更新，本次保存未覆盖新内容。草稿仍保留，可下载草稿后重新读取报告。')
      } else setError(errorMessage(problem))
    } finally {
      busyRef.current = false
      if (mounted.current) setBusy(false)
    }
  }

  async function startRetest(mode: 'automatic' | 'manual') {
    await mutate(async () => {
      const result = await createFindingRetest(id, { notes: notes.trim(), mode })
      if (!mounted.current) return
      setNotes('')
      setTab('retests')
      if (mode === 'manual') setManualId(result.retest.retest_id)
      setNotice(result.enqueued ? '已加入复测队列。' : result.retest.summary || '复测记录已保存。')
    })
  }

  async function saveReport() {
    await mutate(async () => {
      const result = await saveFindingReport(id, draft, digest)
      if (!mounted.current) return
      setDraft(result.report || result.report_template || '')
      setDigest(result.evidence_digest)
      draftDirty.current = false
      setConflict(false)
      setNotice('报告已保存。')
    })
  }

  async function openRun(sessionId: string) {
    await mutate(async () => {
      await useChat.getState().attach(sessionId)
      if (!mounted.current) return
      useAuth.getState().setRoute('chat')
      onClose()
    })
  }

  const finding = detail?.finding || row
  const summary = detail?.summary || detail?.finding.summary || ''
  const evidence = detail?.evidence || detail?.finding.evidence || ''
  const active = detail?.retests.some((item) => item.status === 'queued' || item.status === 'running') || false
  const retests = [...(detail?.retests || [])].sort((a, b) => b.created_at - a.created_at)
  const selectedManual = retests.find((item) => item.retest_id === manualId && item.source === 'manual' && !item.verdict)

  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose() }}>
      <DialogContent width={940}>
        <DialogHeader className="flex-col items-start gap-1.5">
          <DialogTitle className="break-words">{finding.title || '候选发现'}</DialogTitle>
          <DialogDescription className="max-w-full break-all">{finding.target || '未记录目标'} · {id || '旧记录未提供发现 ID'}</DialogDescription>
        </DialogHeader>
        <div className="flex shrink-0 items-center gap-1 border-b border-line px-4 py-2" aria-label="发现详情页面">
          {TABS.map(([key, label]) => <Button key={key} size="sm" variant={tab === key ? 'outline' : 'quiet'} aria-pressed={tab === key} onClick={() => setTab(key)}>{label}{key === 'retests' && retests.length ? ` (${retests.length})` : ''}</Button>)}
          <span className="flex-1" />
          <Button size="icon-sm" aria-label="刷新发现详情" disabled={loading || busy || !id} onClick={() => { setLoading(true); setRefresh((value) => value + 1) }}><RefreshCw size={13} className={loading ? 'animate-spin' : undefined} /></Button>
        </div>
        <DialogBody className="space-y-4">
          {error ? <p role="alert" className="text-sm text-danger">{error}</p> : null}
          {notice ? <p role="status" className="text-xs text-ok">{notice}</p> : null}
          {!id ? <p className="text-sm text-warn">此记录尚无稳定发现 ID，暂不能关联报告和复测。请刷新发现列表或重新运行采集。</p> : null}
          {loading && !detail ? <p className="text-sm text-fg-3">读取报告与复测记录…</p> : null}
          {tab === 'overview' ? <>
            <div className="flex flex-wrap items-center gap-2 text-xs text-fg-3">
              <Badge tone={severityTone(finding.severity)}>{finding.severity || '?'}</Badge>
              <span>{finding.rule || '未记录类型'}</span><span>·</span><span>任务 {finding.task}</span><span>·</span><span>{finding.ts ? formatTimestamp(finding.ts) : '未记录时间'}</span>
            </div>
            <section className="space-y-2"><h3 className="text-xs font-medium text-fg-3">发现摘要</h3><TextBlock>{summary || '未提供摘要。结论需要以原始证据和复测记录为准。'}</TextBlock></section>
            <section className="space-y-2"><h3 className="text-xs font-medium text-fg-3">原始证据</h3><TextBlock>{evidence || '未提供可展示的原始证据。'}</TextBlock></section>
            {detail ? <p className="text-xs leading-relaxed text-fg-3">{detail.auto_retest_reason || (detail.auto_retest_available ? '可依据已有证据启动自动复测。' : '当前缺少可自动重放的证据，可补充人工复测记录。')}</p> : null}
          </> : null}
          {tab === 'report' && detail ? <>
            <div className="flex flex-wrap items-center gap-2">
              <Button size="sm" variant="outline" onClick={() => setEditing(!editing)}>{editing ? '查看预览' : '编辑报告'}</Button>
              <Button size="sm" variant="quiet" disabled={!detail.report_template} onClick={() => downloadMarkdown(`${id}-template.md`, detail.report_template)}><Download size={13} />下载模板</Button>
              <Button size="sm" variant="quiet" disabled={!draft} onClick={() => downloadMarkdown(`${id}${draftDirty.current ? '-draft' : '-report'}.md`, draft)}><Download size={13} />{draftDirty.current ? '下载草稿' : '下载报告'}</Button>
              <span className="flex-1" />
              <Button size="sm" variant="primary" disabled={busy || !draft.trim() || !digest || conflict} onClick={() => void saveReport()}><Save size={13} />{busy ? '保存中…' : '保存报告'}</Button>
            </div>
            <p className="text-xs leading-relaxed text-fg-3">报告按证据生成，预览为 Markdown 文本。编辑报告不会改变复测结论或关闭发现。</p>
            {conflict ? <div className="flex flex-wrap items-center gap-2 rounded-md border border-warn/40 p-3 text-xs text-warn"><span className="flex-1">重新读取会替换当前草稿，请先下载需要保留的内容。</span><Button size="sm" variant="outline" disabled={busy || loading} onClick={() => { draftDirty.current = false; setConflict(false); setLoading(true); setRefresh((value) => value + 1) }}>重新读取报告</Button></div> : null}
            {editing ? <Textarea aria-label="编辑结构化报告" value={draft} onChange={(event) => { draftDirty.current = true; setDraft(event.target.value) }} disabled={busy} rows={22} maxLength={200_000} className="font-mono text-xs leading-relaxed" /> : <TextBlock>{draft || '尚未生成报告。'}</TextBlock>}
          </> : null}
          {tab === 'retests' && detail ? <>
            <p className="text-xs leading-relaxed text-fg-3">复测重放该发现的已有请求，经路由与请求体检查后可以使用 POST。删除行为始终阻断；含义或授权不明确时保留原因供复核。</p>
            <div className="space-y-2 rounded-md border border-line p-3">
              <label htmlFor="retest-notes" className="text-xs text-fg-3">本次复测备注（可选）</label>
              <Textarea id="retest-notes" rows={2} value={notes} onChange={(event) => setNotes(event.target.value)} placeholder="修复版本、环境差异或重点验证的现象" maxLength={8_000} disabled={busy} />
              <div className="flex flex-wrap items-center gap-2">
                <Button size="sm" variant="primary" disabled={busy || active || !detail.auto_retest_available} onClick={() => void startRetest('automatic')}><RotateCcw size={13} />{active ? '已有复测在运行' : '自动复测'}</Button>
                <Button size="sm" variant="outline" disabled={busy} onClick={() => void startRetest('manual')}>记录人工复测</Button>
                <span className="text-xs text-fg-3">只产生本次复测记录，不自动关闭发现。</span>
              </div>
              {detail.auto_retest_reason ? <p className="text-xs leading-relaxed text-fg-3">{detail.auto_retest_reason}</p> : null}
            </div>
            {selectedManual ? <ManualResultForm key={selectedManual.retest_id} retest={selectedManual} busy={busy} onCancel={() => setManualId('')} onSave={(payload) => mutate(async () => {
              await recordFindingRetestResult(id, selectedManual.retest_id, payload)
              if (!mounted.current) return
              setManualId('')
              setNotice('人工复测结果已保存，发现保持原有状态。')
            })} /> : null}
            {!retests.length ? <p className="py-5 text-center text-sm text-fg-3">暂无复测记录。每次复测将保留独立证据和结论。</p> : <ol className="space-y-3">
              {retests.map((item) => <li key={item.retest_id} className="space-y-2 rounded-md border border-line p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone={item.verdict === 'fixed' ? 'ok' : item.verdict === 'reproduced' ? 'warn' : item.status === 'running' ? 'accent' : 'neutral'}>{RETEST_LABEL[retestKey(item)] || item.status}</Badge>
                  <span className="text-xs text-fg-3">{item.source === 'automatic' ? '自动' : '人工'} · {formatTimestamp(item.created_at)}{item.finished_at ? ` → ${formatTimestamp(item.finished_at)}` : ''}</span>
                  <span className="flex-1" />
                  {item.session_id ? <Button size="sm" variant="quiet" disabled={busy} onClick={() => void openRun(item.session_id)}>查看运行</Button> : null}
                  {item.source === 'manual' && !item.verdict ? <Button size="sm" variant="outline" disabled={busy} onClick={() => setManualId(item.retest_id)}>填写结果</Button> : null}
                </div>
                <p className="font-mono text-2xs break-all text-fg-4">{item.retest_id}{item.job_id ? ` · ${item.job_id}` : ''}</p>
                {item.notes ? <p className="text-xs break-words whitespace-pre-wrap text-fg-3">备注：{item.notes}</p> : null}
                <p className="text-sm leading-relaxed break-words whitespace-pre-wrap text-fg-2">{item.summary || '等待结果记录。'}</p>
                {item.human_review_required ? <p className="text-xs break-words text-warn">需人工复核：{item.review_reason || '需要补充证据或确认本次结论。'}</p> : null}
                {item.evidence ? <details><summary className="cursor-pointer text-xs text-fg-3">查看复测证据</summary><div className="mt-2"><TextBlock>{item.evidence}</TextBlock></div></details> : null}
                {item.checks ? <dl className="grid gap-1 text-xs text-fg-3">{(['original', 'current', 'control'] as const).map((key) => item.checks?.[key] ? <div key={key} className="flex flex-wrap gap-2"><dt>{key === 'original' ? '原始复现' : key === 'current' ? '当前复测' : '正常对照'}</dt><dd className="break-all font-mono">{item.checks[key]?.reference}</dd></div> : null)}</dl> : null}
              </li>)}
            </ol>}
          </> : null}
        </DialogBody>
      </DialogContent>
    </Dialog>
  )
}

type ResultPayload = Parameters<typeof recordFindingRetestResult>[2]

function ManualResultForm({ retest, busy, onCancel, onSave }: {
  retest: FindingRetest
  busy: boolean
  onCancel: () => void
  onSave: (payload: ResultPayload) => Promise<void>
}) {
  const [verdict, setVerdict] = useState<ResultPayload['verdict']>('inconclusive')
  const [summary, setSummary] = useState('')
  const [evidence, setEvidence] = useState('')
  const [original, setOriginal] = useState('')
  const [current, setCurrent] = useState('')
  const [control, setControl] = useState('')
  const complete = Boolean(summary.trim() && evidence.trim() && (verdict !== 'fixed' || (original.trim() && current.trim() && control.trim())))
  return <form className="space-y-3 rounded-md border border-accent/40 p-3" onSubmit={(event) => {
    event.preventDefault()
    if (busy || !complete) return
    void onSave({ verdict, summary: summary.trim(), evidence: evidence.trim(), ...(verdict === 'fixed' ? {
      checks: { original: { reference: original.trim(), outcome: 'reproduced' }, current: { reference: current.trim(), outcome: 'not_reproduced' }, control: { reference: control.trim(), outcome: 'passed' } }
    } : {}) })
  }}>
    <h3 className="text-sm font-medium">填写人工复测结果</h3>
    <p className="font-mono text-2xs text-fg-4">{retest.retest_id}</p>
    <label className="grid gap-1 text-xs text-fg-3">复测结论<select value={verdict} disabled={busy} onChange={(event) => setVerdict(event.target.value as ResultPayload['verdict'])} className="h-9 rounded-md border border-line bg-surface px-2 text-fg">
      <option value="inconclusive">证据不足 / 无法确认</option><option value="reproduced">仍可复现</option><option value="fixed">修复证据齐全</option>
    </select></label>
    <label className="grid gap-1 text-xs text-fg-3">结果摘要<Textarea value={summary} onChange={(event) => setSummary(event.target.value)} rows={2} maxLength={8_000} required disabled={busy} /></label>
    <label className="grid gap-1 text-xs text-fg-3">复测证据<Textarea value={evidence} onChange={(event) => setEvidence(event.target.value)} rows={3} placeholder="请求、响应、观察结果及证据位置" maxLength={24_000} required disabled={busy} /></label>
    {verdict === 'fixed' ? <fieldset className="space-y-2 border-t border-line pt-3"><legend className="pr-2 text-xs text-fg-3">三方证据</legend>
      <p className="text-xs leading-relaxed text-fg-3">填写本地证据文件引用。服务端读取并校验内容哈希；原始可复现、当前不复现、正常对照通过必须同时成立。复测结论不会关闭发现。</p>
      <label className="grid gap-1 text-xs text-fg-3">原始复现证据<Input value={original} onChange={(event) => setOriginal(event.target.value)} placeholder="原始证据文件引用" required disabled={busy} maxLength={2_000} /></label>
      <label className="grid gap-1 text-xs text-fg-3">当前不复现证据<Input value={current} onChange={(event) => setCurrent(event.target.value)} placeholder="本次复测证据文件引用" required disabled={busy} maxLength={2_000} /></label>
      <label className="grid gap-1 text-xs text-fg-3">正常对照通过证据<Input value={control} onChange={(event) => setControl(event.target.value)} placeholder="同环境正常对照证据文件引用" required disabled={busy} maxLength={2_000} /></label>
    </fieldset> : null}
    <div className="flex justify-end gap-2"><Button size="sm" variant="quiet" disabled={busy} onClick={onCancel}>稍后填写</Button><Button size="sm" variant="primary" type="submit" disabled={busy || !complete}>{busy ? '保存中…' : '保存结果'}</Button></div>
  </form>
}
