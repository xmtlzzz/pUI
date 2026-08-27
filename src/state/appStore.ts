import { create } from 'zustand'
import { aggregateConversations } from '../aggregate/aggregateConversations'
import { filterConversations, collectFilterOptions } from '../filter/filterConversations'
import { openCapture, openSample, fetchHex, getTsharkVersion } from '../bridge/tauri'
import { emptyFilter } from '../model/types'
import { overlapRange } from '../stats/histogram'
import type { SortKey, SortDir } from '../app/sortConversations'
import type { CaptureMeta, Conversation, FilterCondition, FilterOptions, Packet } from '../model/types'

export interface TimeRange {
  start: number
  end: number
}

function deriveFiltered(conversations: Conversation[], filter: FilterCondition, timeRange: TimeRange | null): Conversation[] {
  const base = filterConversations(conversations, filter)
  return timeRange ? overlapRange(base, timeRange) : base
}

/** hexCache 条目上限:长会话反复浏览报文时内存只增不减,超过上限按 LRU 逐出最旧条目 */
const HEX_CACHE_LIMIT = 200
/** 时序图高亮的最大报文号数(与时序图 2000 抽稀护栏同档):高亮仅用于视觉定位,
 *  数量截断不影响列表定位语义——bestCount 仍用原始计数判断 */
const HIGHLIGHT_LIMIT = 2000
const hexOrder: number[] = [] // LRU 顺序:末尾为最近使用;与 hexCache 同步维护

function hexCachePut(cache: Record<number, string>, n: number, hex: string): Record<number, string> {
  const next = { ...cache, [n]: hex }
  const i = hexOrder.indexOf(n)
  if (i >= 0) hexOrder.splice(i, 1)
  hexOrder.push(n)
  while (hexOrder.length > HEX_CACHE_LIMIT) {
    const old = hexOrder.shift()!
    delete next[old]
  }
  return next
}

function resetHexCache(): Record<number, string> {
  hexOrder.length = 0
  return {}
}

/** 同一帧的并发 fetchHex 去重:重复请求复用同一个 in-flight Promise */
const hexInflight = new Map<number, Promise<string>>()

export interface AppState {
  meta: CaptureMeta | null
  packets: Packet[]
  conversations: Conversation[]
  filtered: Conversation[]
  options: FilterOptions
  filter: FilterCondition
  selectedId: string | null
  selectedPacket: number | null
  currentPath: string
  /** 加载序号:用于丢弃被新加载覆盖的过期异步结果 */
  loadSeq: number
  diagramStyle: 'A' | 'B'
  timeMode: 'relative' | 'absolute'
  sortKey: SortKey
  sortDir: SortDir
  loading: boolean
  error: string | null
  hexCache: Record<number, string>
  openFile: (path: string) => Promise<void>
  openExample: (name: string) => Promise<void>
  setFilter: (patch: Partial<FilterCondition>) => void
  clearFilter: () => void
  select: (id: string) => void
  selectPacket: (n: number) => void
  setDiagramStyle: (s: 'A' | 'B') => void
  setTimeMode: (m: 'relative' | 'absolute') => void
  setSort: (key: SortKey) => void
  searchQuery: string
  setSearchQuery: (q: string) => void
  /** 搜索命中待高亮的报文号(时序图定位跳转) */
  highlight: number[]
  setHighlight: (nums: number[]) => void
  /** 时间窗下钻:直方图点击桶后只显示与窗口重叠的会话 */
  timeRange: TimeRange | null
  setTimeRange: (r: TimeRange | null) => void
  /** 慢响应判定阈值(秒),可配置(默认 1.0);加载抓包时传给聚合器 */
  slowThreshold: number
  setSlowThreshold: (n: number) => void
  /** tshark 版本(顶部信息条展示),解析引擎就绪后置位 */
  tsharkVersion: string | null
  loadTsharkVersion: () => Promise<void>
  fetchHexFor: (n: number) => Promise<string>
  getHex: (n: number) => string | null
  /** M4 故障对照页:进入时记录会话 id;派生数据(事件/阶段)在渲染时按需重算,不入 store */
  compareFor: string | null
  /** 对照页内当前查看的事件下标(导航性 UI 状态;进入新对照时重置为 0) */
  compareEventIndex: number
  openCompare: (conversationId: string) => void
  closeCompare: () => void
  setCompareEventIndex: (i: number) => void
}

export const useApp = create<AppState>((set, get) => ({
  meta: null,
  packets: [],
  conversations: [],
  filtered: [],
  options: { protocols: [], srcIps: [], dstIps: [], ports: [] },
  filter: emptyFilter(),
  selectedId: null,
  selectedPacket: null,
  currentPath: '',
  loadSeq: 0,
  diagramStyle: 'A',
  timeMode: 'relative',
  sortKey: 'start',
  sortDir: 'asc',
  searchQuery: '',
  highlight: [],
  timeRange: null,
  tsharkVersion: null,
  slowThreshold: 1,
  loading: false,
  error: null,
  hexCache: {},
  compareFor: null,
  compareEventIndex: 0,

  openCompare: (conversationId) => set({ compareFor: conversationId, compareEventIndex: 0 }),
  closeCompare: () => set({ compareFor: null }),
  setCompareEventIndex: (i) => set({ compareEventIndex: Math.max(0, i) }),

  async openFile(path) {
    const seq = get().loadSeq + 1
    set({ loading: true, error: null, loadSeq: seq })
    const t0 = performance.now()
    try {
      const { meta, packets, path: realPath } = await openCapture(path)
      if (get().loadSeq !== seq) return // 已被更新的加载覆盖
      const conversations = aggregateConversations(packets, { slowResponseThreshold: get().slowThreshold })
      const filter = emptyFilter()
      set({
        meta: { ...meta, parseMs: performance.now() - t0 }, packets, conversations, options: collectFilterOptions(packets),
        filter, filtered: conversations, selectedId: null, selectedPacket: null,
        currentPath: realPath, hexCache: resetHexCache(), searchQuery: '', highlight: [], timeRange: null, loading: false,
      })
    } catch (e) {
      if (get().loadSeq !== seq) return
      set({ loading: false, error: String(e) })
    }
  },

  async openExample(name) {
    const seq = get().loadSeq + 1
    set({ loading: true, error: null, loadSeq: seq })
    const t0 = performance.now()
    try {
      const { meta, packets, path } = await openSample(name)
      if (get().loadSeq !== seq) return
      const conversations = aggregateConversations(packets, { slowResponseThreshold: get().slowThreshold })
      const filter = emptyFilter()
      set({
        meta: { ...meta, parseMs: performance.now() - t0 }, packets, conversations, options: collectFilterOptions(packets),
        filter, filtered: conversations, selectedId: null, selectedPacket: null,
        currentPath: path, hexCache: resetHexCache(), searchQuery: '', highlight: [], timeRange: null, loading: false,
      })
    } catch (e) {
      if (get().loadSeq !== seq) return
      set({ loading: false, error: String(e) })
    }
  },

  setFilter(patch) {
    const filter = { ...get().filter, ...patch }
    set({ filter, filtered: deriveFiltered(get().conversations, filter, get().timeRange) })
  },
  clearFilter() {
    const filter = emptyFilter()
    set({ filter, filtered: deriveFiltered(get().conversations, filter, get().timeRange) })
  },
  setTimeRange(r) {
    const s = get()
    const patch: Partial<AppState> = { timeRange: r, filtered: deriveFiltered(s.conversations, s.filter, r) }
    if (r) {
      // 定位语义:选中窗口内报文最多的会话,并在时序图上高亮窗口内报文。
      // 长会话区间横跨整个时间轴时,单纯的「区间重叠过滤」列表毫无变化——定位+高亮才是可见反应
      let best: Conversation | null = null
      let bestCount = 0
      let bestNums: number[] = []
      for (const c of s.conversations) {
        const nums = c.packets
          .filter((p) => p.time >= r.start && p.time <= r.end)
          .map((p) => p.number)
        if (nums.length > bestCount) {
          bestCount = nums.length
          best = c
          bestNums = nums
        }
      }
      if (best && bestCount > 0) {
        patch.selectedId = best.id
        patch.selectedPacket = null
        // 高亮仅用于视觉定位,窗口内命中报文超过上限时只保留前 2000 个报文号;
        // 截断只作用于写入 highlight 的数组,bestCount 判定仍用完整计数
        patch.highlight = bestNums.length > HIGHLIGHT_LIMIT ? bestNums.slice(0, HIGHLIGHT_LIMIT) : bestNums
      }
    } else {
      patch.highlight = [] // 清除区间时一并清掉高亮,避免残留
    }
    set(patch)
  },
  setSlowThreshold(n) {
    // 阈值可配置:)取合理区间,避免 0 或负值
    const v = Number.isFinite(n) ? Math.max(0.05, Math.min(60, n)) : 1
    set({ slowThreshold: v })
  },
  select(id) {
    set({ selectedId: id, selectedPacket: null })
  },
  selectPacket(n) {
    set({ selectedPacket: n })
  },
  setDiagramStyle(s) {
    set({ diagramStyle: s })
  },
  setTimeMode(m) {
    set({ timeMode: m })
  },
  setSort(key) {
    const s = get()
    if (s.sortKey === key) {
      // 同列再点:切换升降序(PRD F3 交互)
      set({ sortDir: s.sortDir === 'asc' ? 'desc' : 'asc' })
    } else {
      set({ sortKey: key, sortDir: 'asc' })
    }
  },
  setSearchQuery(q) {
    set({ searchQuery: q, highlight: [] })
  },
  setHighlight(nums) {
    set({ highlight: nums })
  },
  async loadTsharkVersion() {
    const v = await getTsharkVersion()
    set({ tsharkVersion: v })
  },
  async fetchHexFor(n) {
    const path = get().currentPath
    if (!path) return ''
    const cached = get().hexCache[n]
    if (cached) return cached
    const pending = hexInflight.get(n)
    if (pending) return pending
    const p = (async () => {
      const hex = await fetchHex(path, n)
      if (get().currentPath !== path) return '' // 已切换文件,丢弃过期结果
      set((s) => ({ hexCache: hexCachePut(s.hexCache, n, hex) }))
      return hex
    })().finally(() => {
      hexInflight.delete(n)
    })
    hexInflight.set(n, p)
    return p
  },
  getHex(n) {
    return get().hexCache[n] ?? null
  },
}))

// 派生选择器(返回稳定引用,可安全用于 useSyncExternalStore)
export const selectSelected = (s: AppState): Conversation | null =>
  s.conversations.find((c) => c.id === s.selectedId) ?? null
export const selectSelectedPacket = (s: AppState): Packet | null => {
  const conv = selectSelected(s)
  if (!conv) return null
  return conv.packets.find((p) => p.number === s.selectedPacket) ?? null
}
