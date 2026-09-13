// R1 对话台丝滑化:工具气泡三段渲染 + 长列表窗口化的纯函数(可单测,不依赖组件)。
export interface ToolKv { k: string; v: string }

const KV_VAL_MAX = 160
const RAW_MAX = 20000

// ---- 工具参数:JSON 可解析 → kv 表;否则 null(走原文段)。max 控制值截断(展开用全长) ----
export function parseToolArgs(raw?: string, max: number = KV_VAL_MAX): ToolKv[] | null {
  if (!raw || !raw.trim()) return null
  let obj: unknown
  try { obj = JSON.parse(raw) } catch { return null }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null
  const out: ToolKv[] = []
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    let s: string
    if (typeof v === 'string') s = v
    else { try { s = JSON.stringify(v) } catch { s = String(v) } }
    if (s.length > max) s = s.slice(0, max) + '…'
    out.push({ k, v: s })
  }
  return out.length ? out : null
}

// ---- 结果摘要:前 3 个非空行,超长截断并给行数 ----
export function summarizeToolOutput(raw?: string, max = 240): string {
  if (!raw) return ''
  const lines = raw.split('\n').map(l => l.trimEnd()).filter(l => l.trim())
  let s = lines.slice(0, 3).join('\n')
  if (s.length > max) s = s.slice(0, max) + '…'
  else if (lines.length > 3) s += `\n…(共 ${lines.length} 行)`
  return s
}

// ---- R-A P0-1:工具卡片摘要(精简一行:主参数 + 退出码/耗时)与"展开是否有新增信息"判定 ----
const ARG_SUMMARY_MAX = 120
const PRIMARY_ARG_KEYS = ['cmd', 'command', 'code', 'url', 'path', 'file_path', 'query', 'target']

function tryParseObj(raw?: string): Record<string, unknown> | null {
  if (!raw || !raw.trim()) return null
  try {
    const o: unknown = JSON.parse(raw)
    return o && typeof o === 'object' && !Array.isArray(o) ? o as Record<string, unknown> : null
  } catch { return null }
}
function oneLine(s: string, max = ARG_SUMMARY_MAX): string {
  const t = s.split('\n').map(x => x.trim()).filter(Boolean)[0] || ''
  return t.length > max ? t.slice(0, max) + '…' : t
}
function valStr(v: unknown): string {
  if (typeof v === 'string') return v
  try { return JSON.stringify(v) } catch { return String(v) }
}

// tool_call 摘要:主参数一行(cmd/url/...),多参数给计数
export function toolCallSummary(toolName: string | undefined, rawArgs?: string): string {
  const name = toolName || 'tool'
  const obj = tryParseObj(rawArgs)
  if (obj) {
    const keys = Object.keys(obj)
    if (!keys.length) return name
    const k = PRIMARY_ARG_KEYS.find(x => x in obj) ?? keys[0]
    const rest = keys.length - 1
    return `${name}  ${k}: ${oneLine(valStr(obj[k]))}${rest > 0 ? `  (+${rest} 参数)` : ''}`
  }
  const t = (rawArgs || '').trim()
  return t ? `${name}  ${oneLine(t)}` : name
}

// tool_call 展开判定:参数必须比摘要一行信息量更多(否则前端不渲染折叠按钮)
export function toolCallHasMore(rawArgs: string | undefined): boolean {
  const obj = tryParseObj(rawArgs)
  if (obj) {
    const keys = Object.keys(obj)
    if (keys.length > 1) return true
    if (!keys.length) return false
    const s = valStr(obj[keys[0]])
    return s.length > ARG_SUMMARY_MAX || s.trim().includes('\n')
  }
  const t = (rawArgs || '').trim()
  return t.length > ARG_SUMMARY_MAX || t.includes('\n')
}

// tool_result 元信息:退出码/成功失败/耗时/错误(提取不到 → '')
export function parseResultMeta(raw?: string): string {
  const obj = tryParseObj(raw)
  if (!obj) return ''
  const parts: string[] = []
  const ec = obj.exit_code ?? obj.exitCode ?? obj.returncode ?? obj.return_code
  if (typeof ec === 'number' || typeof ec === 'string') parts.push(`退出码 ${ec}`)
  if (typeof obj.success === 'boolean') parts.push(obj.success ? '成功' : '失败')
  const dur = obj.duration ?? obj.elapsed ?? obj.elapsed_seconds ?? obj.duration_seconds
  if (typeof dur === 'number') parts.push(`耗时 ${Math.round(dur * 10) / 10}s`)
  else if (typeof dur === 'string' && dur) parts.push(`耗时 ${dur}`)
  if (typeof obj.error === 'string' && obj.error) parts.push(`错误: ${oneLine(obj.error, 80)}`)
  return parts.join(' · ')
}

// tool_result 摘要:优先元信息一行;否则回退前 3 行文本摘要
export function summarizeToolResult(raw?: string): string {
  if (!raw || !raw.trim()) return ''
  return parseResultMeta(raw) || summarizeToolOutput(raw)
}

// tool_result 展开判定:原文必须比摘要信息量更多
export function toolResultHasMore(raw: string | undefined, summary: string): boolean {
  const t = (raw || '').trim()
  if (!t) return false
  return t.length > summary.trim().length
}

// ---- R-A P0-2:reasoning 的 [{"text":...}] 包装解析(兼容严格 JSON 与 Python repr)----
export function parseReasoningText(raw?: string): string {
  if (!raw) return ''
  const t = raw.trim()
  if (!t.startsWith('[')) return raw
  try {
    const arr: unknown = JSON.parse(t)
    if (Array.isArray(arr) && arr.length &&
      arr.every(x => x && typeof x === 'object' && 'text' in (x as Record<string, unknown>))) {
      const s = arr.map(x => String((x as Record<string, unknown>).text ?? '')).filter(Boolean).join('\n')
      if (s) return s
    }
  } catch { /* 非严格 JSON,走 repr 兜底 */ }
  const dq = [...t.matchAll(/"text":\s*"((?:[^"\\]|\\.)*)"/g)]
  if (dq.length) return dq.map(m => m[1]).join('\n')
  const sq = [...t.matchAll(/'text':\s*'((?:[^'\\]|\\.)*)'/g)]
  if (sq.length) return sq.map(m => m[1]).join('\n')
  return raw
}

// ---- 长列表窗口化:只渲染最近 count 条 ----
export function sliceRecent<T>(rows: T[], count: number): T[] {
  if (count <= 0) return []
  return rows.length > count ? rows.slice(rows.length - count) : rows.slice()
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

// ---- 原文轻量语法高亮(浅色底):JSON 先美化再高亮;非 JSON 原样转义 ----
export function highlightJson(raw: string): string {
  if (!raw) return ''
  let text = raw
  let truncated = false
  if (text.length > RAW_MAX) { text = text.slice(0, RAW_MAX); truncated = true }
  try { if (!truncated) text = JSON.stringify(JSON.parse(text), null, 2) } catch { /* 非 JSON 原样 */ }
  const esc = escapeHtml(text)
  const html = esc.replace(
    /("(\\u[0-9a-fA-F]{4}|\\[^u]|[^\\"])*")(\s*:)?|\b(true|false|null)\b|-?\d+(\.\d+)?([eE][+-]?\d+)?/g,
    (m, str: string | undefined, _u: unknown, colon: string | undefined) => {
      if (str) return colon ? `<span class="tk-k">${str}</span>${colon}` : `<span class="tk-s">${str}</span>`
      if (m === 'true' || m === 'false' || m === 'null') return `<span class="tk-b">${m}</span>`
      return `<span class="tk-n">${m}</span>`
    })
  return truncated ? html + '\n…(原文过长已截断)' : html
}
