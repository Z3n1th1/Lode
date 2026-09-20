import { describe, expect, it } from 'vitest'

import { fanoutNotice, refusalText, rejectLabel, scopePreviewRows, willRun } from './scopeDocument'
import type { ScopeSummary } from './scopeDocument'

function summary(over: Partial<ScopeSummary> = {}): ScopeSummary {
  return {
    program: 'nba-public',
    authorization: 'HackerOne managed program',
    hosts: ['api.nba.com', 'cdn.nba.com', 'login.nba.com'],
    rejected: [],
    forbidden_hosts: ['cms.nba.com'],
    allowed_methods: ['GET', 'HEAD'],
    allow_request_body: false,
    requests_per_second: 3,
    max_fanout: 30,
    ...over
  }
}

describe('willRun', () => {
  it('每台主机一个任务', () => {
    expect(willRun(summary())).toBe(3)
  })

  it('文档自己写的上限说了算 —— 它是授权的边界', () => {
    expect(willRun(summary({ max_fanout: 2 }))).toBe(2)
  })

  it('没有文档上限时不会凭空造一个', () => {
    expect(willRun(summary({ max_fanout: undefined }))).toBe(3)
  })

  it('没有主机就是零,不是"全部"', () => {
    expect(willRun(summary({ hosts: [] }))).toBe(0)
  })
})

describe('fanoutNotice', () => {
  it('全部能跑时只说将起几个', () => {
    expect(fanoutNotice(summary())).toBe('将起 3 个任务(每台主机一个)')
  })

  it('被上限截断时说清少了几台、那个上限是谁定的', () => {
    const text = fanoutNotice(summary({ hosts: ['a.com', 'b.com', 'c.com', 'd.com'], max_fanout: 2 }))
    expect(text).toContain('将起 2 个任务')
    expect(text).toContain('另有 2 台超出文档写的上限 2')
    expect(text).toContain('这次不起')
  })

  it('没有可跑的主机时直说', () => {
    expect(fanoutNotice(summary({ hosts: [] }))).toBe('没有可跑的主机')
  })
})

describe('scopePreviewRows', () => {
  it('速率那行说明预算是共享的 —— 这是最容易被误读的一行', () => {
    const rows = scopePreviewRows(summary())
    const rate = rows.find((row) => row.label === '速率')
    expect(rate?.value).toContain('3 req/s')
    expect(rate?.value).toContain('共用一个预算')
  })

  it('能力那行带上能不能带请求体', () => {
    const bare = scopePreviewRows(summary()).find((row) => row.label === '能力')
    expect(bare?.value).toBe('GET、HEAD(不允许带请求体)')
    const writable = scopePreviewRows(summary({ allowed_methods: ['GET', 'POST'], allow_request_body: true }))
      .find((row) => row.label === '能力')
    expect(writable?.value).toContain('可以带请求体')
  })

  it('被拦下的主机单独成行并标警', () => {
    const rows = scopePreviewRows(summary({ rejected: [['*.nba.com', 'scope_document_wildcard_not_allowed']] }))
    const rejected = rows.find((row) => row.label === '被拦下')
    expect(rejected?.warn).toBe(true)
    expect(rejected?.value).toContain('*.nba.com')
  })

  it('没有排除/没有速率就不摆空行', () => {
    const labels = scopePreviewRows(summary({ forbidden_hosts: [], requests_per_second: 0 }))
      .map((row) => row.label)
    expect(labels).not.toContain('排除')
    expect(labels).not.toContain('速率')
  })

  it('主机很多时只列前几台,但数目是完整的', () => {
    const hosts = Array.from({ length: 200 }, (_, i) => `h${i}.nba.com`)
    const row = scopePreviewRows(summary({ hosts })).find((item) => item.label === '授权主机')
    expect(row?.value).toContain('200 台')
    expect(row?.value).toContain('h0.nba.com')
    expect(row?.value).not.toContain('h50.nba.com')
  })
})

describe('refusalText', () => {
  it('域模式那条要点名是哪个域', () => {
    const text = refusalText('scope_document_domains_not_allowed', 'nba.com')
    expect(text).toContain('只收精确主机名')
    expect(text).toContain('nba.com')
  })

  it('未知原因码原样露出,不吞成一句空话', () => {
    expect(refusalText('something_new')).toContain('something_new')
  })
})

describe('rejectLabel', () => {
  it('拖进去没反应是最糟的反馈,所以一行里要有文件名和原因', () => {
    const label = rejectLabel({ file: 'nba.json', reason: 'scope_document_domains_not_allowed', detail: 'nba.com' })
    expect(label).toContain('nba.json')
    expect(label).toContain('只收精确主机名')
    expect(label).toContain('nba.com')
  })
})
