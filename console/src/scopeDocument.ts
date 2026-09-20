/**
 * 授权文档在控制台上的纯展示逻辑。
 *
 * 判定**留在服务端** —— 这里没有 ``looksLikeScopeDocument`` 的镜像。两份判定会互相
 * 走样,而走样那一份就是会授权错东西的那一份。这个模块只把服务端给的 summary 摆成
 * 人能读的行,所以它是纯函数,可以在 node 里直接测(仓库里没有 jsdom,也不打算加)。
 */

export interface ScopeSummary {
  program?: string
  authorization?: string
  hosts?: string[]
  rejected?: [string, string][] | string[][]
  forbidden_hosts?: string[]
  allowed_methods?: string[]
  allow_request_body?: boolean
  requests_per_second?: number
  max_fanout?: number
}

export interface ScopePreview {
  schema?: string
  intake_id: string
  source?: string
  document?: Record<string, unknown>
  document_digest?: string
  summary: ScopeSummary
  instruction?: string
  options_digest: string
  scope_digest?: string
  created_at?: number
  expires_at?: number
}

export interface ScopeReject {
  file: string
  reason: string
  detail?: string
  ts?: number
}

export interface ScopeRow {
  label: string
  value: string
  /** 需要操作者多看一眼的行(被拦下的主机、超出上限的部分)。 */
  warn?: boolean
}

const REFUSAL_TEXT: Record<string, string> = {
  scope_document_domains_not_allowed:
    '它用 allowed_domains 授权 —— 那是整片域,连带所有子域。控制台只收精确主机名。',
  scope_document_ip_range_not_allowed:
    '它用 CIDR 网段授权 —— 那是一片地址,同样不是精确主机名。',
  surface_authorization_required: '它没有写 authorization(书面授权说明)那一栏。',
  surface_scope_required: '它没有写任何主机、域或地址。',
  scope_document_no_hosts: '它列出的主机里,没有一台是能打的公网 http(s) 主机。',
  scope_document_not_recognised:
    '这不是一份能识别的授权文档。整段内容必须是 JSON —— 前面后面别带说明文字。',
  scope_document_required: '没有收到任何内容。',
  pending_intake_exists: '待确认队列里已经有一份待确认的东西,先放弃它。',
  scope_inbox_unreadable: '这个文件读不出来(不是 UTF-8 文本,或者权限不对)。'
}

/** 服务端的原因码 → 给操作员的话。未知码原样露出,不吞。 */
export function refusalText(reason: string, detail = ''): string {
  const text = REFUSAL_TEXT[reason] || `它没通过授权文档的校验(${reason})。`
  return detail ? `${text}(${detail})` : text
}

/** How many jobs a confirmation would actually start. */
export function willRun(summary: ScopeSummary): number {
  const hosts = summary.hosts?.length ?? 0
  const cap = summary.max_fanout ?? hosts
  return Math.max(0, Math.min(hosts, cap))
}

export function scopePreviewRows(summary: ScopeSummary): ScopeRow[] {
  const hosts = summary.hosts ?? []
  const rows: ScopeRow[] = [{ label: '程序', value: summary.program || '未命名' }]
  rows.push({
    label: '授权主机',
    value: `${hosts.length} 台${hosts.length ? `(${hosts.slice(0, 4).join('、')}${hosts.length > 4 ? ' …' : ''})` : ''}`
  })
  const forbidden = summary.forbidden_hosts ?? []
  if (forbidden.length) rows.push({ label: '排除', value: `${forbidden.length} 台` })
  if (summary.requests_per_second) {
    rows.push({ label: '速率', value: `${summary.requests_per_second} req/s(所有任务共用一个预算)` })
  }
  const methods = summary.allowed_methods ?? []
  if (methods.length) {
    rows.push({
      label: '能力',
      value: `${methods.join('、')}(${summary.allow_request_body ? '可以带请求体' : '不允许带请求体'})`
    })
  }
  rows.push({ label: '本轮', value: fanoutNotice(summary) })
  const rejected = summary.rejected ?? []
  if (rejected.length) {
    rows.push({
      label: '被拦下',
      value: `${rejected.length} 台:${rejected.slice(0, 3).map((item) => item[0]).join('、')}`,
      warn: true
    })
  }
  return rows
}

/** What this confirmation starts, including the part the document's own cap drops. */
export function fanoutNotice(summary: ScopeSummary): string {
  const hosts = summary.hosts?.length ?? 0
  const run = willRun(summary)
  if (!hosts) return '没有可跑的主机'
  if (run === hosts) return `将起 ${run} 个任务(每台主机一个)`
  const cap = summary.max_fanout ?? hosts
  return `将起 ${run} 个任务;另有 ${hosts - run} 台超出文档写的上限 ${cap},这次不起`
}

/** One line for a file the drop folder refused, so a silent drop is never silent. */
export function rejectLabel(reject: ScopeReject): string {
  return `${reject.file}:${refusalText(reject.reason, reject.detail)}`
}
