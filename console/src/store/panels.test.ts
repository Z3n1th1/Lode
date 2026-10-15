import { beforeEach, describe, expect, it, vi } from 'vitest'

// loadProjects/loadProjectIntakes 是这两个用例唯一的外部依赖;其余 export 保持真实,
// 免得为了测翻页把整个 api 模块的形状抄一遍(抄漏一个名字就是一条假失败)。
const { loadProjects, loadProjectIntakes } = vi.hoisted(() => ({
  loadProjects: vi.fn(),
  loadProjectIntakes: vi.fn()
}))

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>()
  return { ...actual, loadProjects, loadProjectIntakes }
})

import { PROJECT_PAGE_SIZE, type ProjectCard, type ProjectPage } from '../api'
import { usePanels } from './panels'

function card(overrides: Partial<ProjectCard> = {}): ProjectCard {
  return {
    project_id: 'p1',
    target: 'https://a.example/',
    profiles: [],
    session_count: 1,
    task_count: 1,
    finding_count: 0,
    verified_finding_count: 0,
    status: 'done',
    last_activity: 1,
    running_task_id: '',
    batch_index: 0,
    batch_size: 0,
    surface_paths: 0,
    surface_api: 0,
    surface_scripts: 0,
    http_status: 0,
    has_surface: false,
    ...overrides
  }
}

function page(overrides: Partial<ProjectPage> = {}): ProjectPage {
  return {
    projects: [card()],
    total: 1,
    offset: 0,
    limit: PROJECT_PAGE_SIZE,
    running: null,
    ...overrides
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  usePanels.setState({
    projects: [],
    projectTotal: 0,
    projectOffset: 0,
    projectPageSize: PROJECT_PAGE_SIZE,
    projectRunning: null,
    projectsMoreError: ''
  })
  loadProjectIntakes.mockResolvedValue({ intakes: [], status: 'available' })
})

describe('setProjectPage', () => {
  it('fetches the requested page and keeps what the server returned', async () => {
    loadProjects.mockResolvedValue(page({ offset: 20, limit: 20, total: 325 }))
    await usePanels.getState().setProjectPage(20, 20)

    expect(loadProjects).toHaveBeenCalledWith(20, 20)
    const state = usePanels.getState()
    expect(state.projectOffset).toBe(20)
    expect(state.projectPageSize).toBe(20)
    expect(state.projectTotal).toBe(325)
  })

  it('keeps the current page size when only the offset is given', async () => {
    loadProjects.mockResolvedValue(page())
    await usePanels.getState().setProjectPage(40)
    expect(loadProjects).toHaveBeenCalledWith(40, PROJECT_PAGE_SIZE)
  })

  it('goes back to the first page when the page size changes', async () => {
    loadProjects.mockResolvedValue(page({ limit: 50 }))
    await usePanels.getState().setProjectPage(40, 50)
    // 换页宽 = 换一套分页。留着旧 offset 会停在一个按新页宽毫无意义的位置上。
    expect(loadProjects).toHaveBeenCalledWith(0, 50)
  })

  it('ignores a page size the server would never accept, but keeps the offset', async () => {
    loadProjects.mockResolvedValue(page())
    await usePanels.getState().setProjectPage(40, 1000)
    expect(loadProjects).toHaveBeenCalledWith(40, PROJECT_PAGE_SIZE)
  })

  it('keeps the rows already on screen when the fetch fails', async () => {
    usePanels.setState({ projects: [card({ project_id: 'keep' })], projectTotal: 1 })
    loadProjects.mockRejectedValue(new Error('boom'))
    await usePanels.getState().setProjectPage(20)

    const state = usePanels.getState()
    // 翻页翻挂了不该把已经看到的列表清空 —— 那看起来像"什么都没了"。
    expect(state.projects.map((p) => p.project_id)).toEqual(['keep'])
    expect(state.projectsMoreError).toBe('加载失败')
  })
})

describe('load("projects")', () => {
  it('fetches the page the operator is on, not page one', async () => {
    usePanels.setState({ projectOffset: 40, projectPageSize: 50 })
    loadProjects.mockResolvedValue(page({ offset: 40, limit: 50 }))
    await usePanels.getState().load('projects')

    // 旧实现每轮都从 offset 0 重拉一遍,于是 20s 轮询会把视图从第 9 页拽回第一页。
    expect(loadProjects).toHaveBeenCalledWith(40, 50)
  })

  it('carries the global running summary through, so the banner ignores paging', async () => {
    const running = {
      project_id: 'p2',
      target: 'https://b.example/',
      task_id: 'T-9',
      batch_index: 137,
      batch_size: 325
    }
    loadProjects.mockResolvedValue(page({ running }))
    await usePanels.getState().load('projects')
    expect(usePanels.getState().projectRunning).toEqual(running)
  })
})
