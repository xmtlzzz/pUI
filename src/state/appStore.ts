import { create } from 'zustand'
import { aggregateConversations } from '../aggregate/aggregateConversations'
import { filterConversations, collectFilterOptions } from '../filter/filterConversations'
import { searchConversations } from '../search/searchPackets'
import { openCapture, openSample, fetchHex, getTsharkVersion, setTsharkPath as setTsharkPathCmd } from '../bridge/tauri'
import { cancelParse } from '../parse/parseAsync'
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

/** 搜索命中的跨会话扁平报文号数组:按帧号升序(帧号即抓包帧序/时间序),
 *  供「上一个/下一个命中」逐条导航与计数展示。空查询/无命中返回空数组。 */
function searchHitNumbers(conversations: Conversation[], query: string): number[] {
  const q = query.trim()
  if (!q) return []
  const out: number[] = []
  for (const m of searchConversations(conversations, q)) {
    for (const n of m.numbers) out.push(n)
  }
  return out.sort((a, b) => a - b)
}

/** 命中的报文号 → 所在会话 id + 报文号;会话按 packets 内的 number 归属查找
 *  (跨会话跳转不需要会话在当前筛选列表里)。无命中返回 null。 */
function locateHit(conversations: Conversation[], hits: number[], idx: number): { id: string; number: number } | null {
  const n = hits[idx]
  if (n == null) return null
  const conv = conversations.find((c) => c.packets.some((p) => p.number === n))
  return conv ? { id: conv.id, number: n } : null
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

/** 同一帧的并发 fetchHex 去重:重复请求复用同一个 in-flight Promise。
 *  键含文件标识 `${path}:${n}`:切换文件后同号报文必须重新发起,
 *  不得复用旧文件的 in-flight(其 resolve 会被 currentPath 守卫丢弃,导致新文件 hex 静默空白) */
const hexInflight = new Map<string, Promise<string>>()

/**
 * 跳回报文详情前保存的对照页位置(按分镜/阶段粒度,案例 openQuestion 裁定)。
 * 仅导航性 UI 状态;事件/阶段的派生数据仍由渲染时纯函数重算。
 */
export interface CompareResume {
  conversationId: string
  eventIndex: number
  /** 离开时的活动阶段下标(-1 = 尚无活动阶段) */
  stageIndex: number
}

/** 序号空间形态(C)单方向带的字节轴缩放窗口;null = 全轴。
 *  与 FaultCompare.ZoomRange 同构,值合法范围 [lane.axisMin, lane.axisMax]。 */
export interface SeqSpaceWindow {
  start: number
  end: number
}

/**
 * 时序图「阅读上下文」:跨形态共享的导航性 UI 状态(不入派生数据红线,与
 * compareFor/compareEventIndex 同先例)。四形态(A/B/C/D)切换时组件卸载重建,
 * 各自局部 state(C 的缩放窗口、A/B 的 segIdx)会全部丢失 —— 提升到 store 后,
 * 切形态回到原阅读位置。
 */
export interface DiagramContext {
  /** A/B 分段导航当前段下标;null = 全部(C/D 同用) */
  seqSegIdx: number | null
  /** C 形态每方向带的缩放窗口(key = `${lane.kind}-${lane.direction}-${li}`) */
  seqSpaceWindows: Record<string, SeqSpaceWindow | null>
}

/** 重置阅读上下文(切换会话/打开新文件/时间窗重新定位时调用) */
function resetDiagramContext(): DiagramContext {
  return { seqSegIdx: null, seqSpaceWindows: {} }
}

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
  /** 时序图形态:A=斜线 B=行式 C=序号空间(横向字节轴) D=时间流(纵轴时间,
   *  2026-09-02 用户要求加回:内容多时横线形态难辨交互先后,D 与 C 互补);默认 A 不变 */
  diagramStyle: 'A' | 'B' | 'C' | 'D'
  timeMode: 'relative' | 'absolute'
  sortKey: SortKey
  sortDir: SortDir
  loading: boolean
  /** 流式解析进度:已解析帧数(仅在 loading 期间有意义;0 = 尚无数据/非流式路径) */
  loadingFrames: number
  error: string | null
  hexCache: Record<number, string>
  openFile: (path: string) => Promise<void>
  openExample: (name: string) => Promise<void>
  setFilter: (patch: Partial<FilterCondition>) => void
  clearFilter: () => void
  /** 手动关闭错误 banner:保留 loading/error 语义,仅清空 error 文案 */
  dismissError: () => void
  select: (id: string) => void
  selectPacket: (n: number) => void
  setDiagramStyle: (s: 'A' | 'B' | 'C' | 'D') => void
  setTimeMode: (m: 'relative' | 'absolute') => void
  setSort: (key: SortKey) => void
  searchQuery: string
  setSearchQuery: (q: string) => void
  /** 当前搜索的命中报文号列表(按帧号升序,跨会话扁平);空查询/无命中 = 空数组 */
  searchHits: number[]
  /** 当前定位到 searchHits 的第几条(-1 = 无命中) */
  searchHitIndex: number
  /** 跳到下一条命中(循环);无命中时不动 */
  nextSearchHit: () => void
  /** 跳到上一条命中(循环);无命中时不动 */
  prevSearchHit: () => void
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
  /** 设置 tshark 可执行文件路径(Rust 侧强校验);成功后重拉版本号 */
  setTsharkPath: (path: string) => Promise<void>
  fetchHexFor: (n: number) => Promise<string>
  getHex: (n: number) => string | null
  /** M4 故障对照页:进入时记录会话 id;派生数据(事件/阶段)在渲染时按需重算,不入 store */
  compareFor: string | null
  /** 对照页内当前查看的事件下标(导航性 UI 状态;进入新对照时重置为 0) */
  compareEventIndex: number
  /** 跳回报文详情前的对照页位置,供报文详情侧「返回故障分析」恢复;新开文件清空 */
  compareResume: CompareResume | null
  openCompare: (conversationId: string) => void
  closeCompare: () => void
  setCompareEventIndex: (i: number) => void
  /** 跳包前记录来源(事件+阶段),closeCompare 不清除 —— 恢复入口消费后才消失 */
  jumpFromCompare: (r: CompareResume) => void
  /** 取走并清空 resume(读改一体,避免双渲染竞态);无则返回 null */
  consumeCompareResume: () => CompareResume | null
  clearCompareResume: () => void
  /** A/B 分段导航当前段下标(null = 全部;C/D 复用同一阅读上下文)。
   *  跨形态共享:切形态时组件卸载重建,段位置仍保留 */
  seqSegIdx: number | null
  /** C 序号空间形态每方向带的缩放窗口(byte 轴窗口;null = 全轴)。
   *  跨形态共享:切到 A/B/D 再切回 C 时回到原窗口位置 */
  seqSpaceWindows: Record<string, SeqSpaceWindow | null>
  setSeqSegIdx: (i: number | null) => void
  setSeqSpaceWindows: (w: Record<string, SeqSpaceWindow | null> | ((prev: Record<string, SeqSpaceWindow | null>) => Record<string, SeqSpaceWindow | null>)) => void
  /** 双点对照:副抓包(B 侧)元信息;null = 未加载 */
  dualMeta: CaptureMeta | null
  /** 副抓包报文;null = 未加载(与空数组区分:空数组是合法的空抓包) */
  dualPackets: Packet[] | null
  /** 副抓包路径/示例名(对照编排缓存键的一部分) */
  dualPath: string
  dualLoading: boolean
  /** 副抓包流式解析进度(仅 dualLoading 期间有意义) */
  dualLoadingFrames: number
  dualError: string | null
  /** 副抓包加载序号:独立于主 loadSeq —— 两侧加载互不干扰,各自防过期 */
  dualLoadSeq: number
  openDualFile: (path: string) => Promise<void>
  openDualExample: (name: string) => Promise<void>
  clearDual: () => void
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
  searchHits: [],
  searchHitIndex: -1,
  highlight: [],
  timeRange: null,
  tsharkVersion: null,
  slowThreshold: 1,
  loading: false,
  loadingFrames: 0,
  error: null,
  hexCache: {},
  compareFor: null,
  compareEventIndex: 0,
  compareResume: null,
  seqSegIdx: null,
  seqSpaceWindows: {},
  dualMeta: null,
  dualPackets: null,
  dualPath: '',
  dualLoading: false,
  dualLoadingFrames: 0,
  dualError: null,
  dualLoadSeq: 0,

  openCompare: (conversationId) => set({ compareFor: conversationId, compareEventIndex: 0 }),
  closeCompare: () => set({ compareFor: null }),
  setCompareEventIndex: (i) => set({ compareEventIndex: Math.max(0, i) }),
  jumpFromCompare: (r) => set({ compareResume: r }),
  consumeCompareResume: () => {
    const r = get().compareResume
    if (r) set({ compareResume: null })
    return r
  },
  clearCompareResume: () => set({ compareResume: null }),

  // ---- 时序图阅读上下文(跨形态保留;导航性 UI 状态,非派生数据) ----
  setSeqSegIdx: (i) => set({ seqSegIdx: i }),
  setSeqSpaceWindows: (w) =>
    set((s) => ({ seqSpaceWindows: typeof w === 'function' ? w(s.seqSpaceWindows) : w })),

  // ---- 双点对照:副抓包加载。模式与主抓包完全同构(独立 seq 防过期、流式进度),
  //      但不触碰主视图任何状态 —— 两侧是两个平行的观察点,加载互不干扰 ----
  async openDualFile(path) {
    const seq = get().dualLoadSeq + 1
    set({ dualLoading: true, dualLoadingFrames: 0, dualError: null, dualLoadSeq: seq })
    try {
      const { meta, packets, path: realPath } = await openCapture(path, (frames) => {
        if (get().dualLoadSeq === seq) set({ dualLoadingFrames: frames })
      })
      if (get().dualLoadSeq !== seq) return // 已被更新的副抓包加载覆盖
      set({
        dualMeta: { ...meta, parseMs: undefined },
        dualPackets: packets,
        dualPath: realPath,
        dualLoading: false,
      })
    } catch (e) {
      if (get().dualLoadSeq !== seq) return
      set({ dualLoading: false, dualError: String(e) })
    }
  },

  async openDualExample(name) {
    const seq = get().dualLoadSeq + 1
    set({ dualLoading: true, dualLoadingFrames: 0, dualError: null, dualLoadSeq: seq })
    try {
      const { meta, packets, path } = await openSample(name, (frames) => {
        if (get().dualLoadSeq === seq) set({ dualLoadingFrames: frames })
      })
      if (get().dualLoadSeq !== seq) return
      set({ dualMeta: meta, dualPackets: packets, dualPath: path, dualLoading: false })
    } catch (e) {
      if (get().dualLoadSeq !== seq) return
      set({ dualLoading: false, dualError: String(e) })
    }
  },

  clearDual() {
    set({ dualMeta: null, dualPackets: null, dualPath: '', dualLoading: false, dualLoadingFrames: 0, dualError: null })
  },

  async openFile(path) {
    // 切换文件:终止在途 Worker 解析(浏览器回退路径的 Worker 池;生产走主线程
    // 批解析不受影响),避免旧文件解析继续占用 CPU/内存、结果被 loadSeq 丢弃
    cancelParse()
    const seq = get().loadSeq + 1
    set({ loading: true, loadingFrames: 0, error: null, loadSeq: seq })
    const t0 = performance.now()
    try {
      const { meta, packets, path: realPath } = await openCapture(path, (frames) => {
        // 流式进度:仅在本次加载仍有效时更新(过期加载的回调静默丢弃)
        if (get().loadSeq === seq) set({ loadingFrames: frames })
      })
      if (get().loadSeq !== seq) return // 已被更新的加载覆盖
      const conversations = aggregateConversations(packets, { slowResponseThreshold: get().slowThreshold })
      const filter = emptyFilter()
      set({
        meta: { ...meta, parseMs: performance.now() - t0 }, packets, conversations, options: collectFilterOptions(packets),
        filter, filtered: conversations, selectedId: null, selectedPacket: null,
        currentPath: realPath, hexCache: resetHexCache(), searchQuery: '', searchHits: [], searchHitIndex: -1, highlight: [], timeRange: null, loading: false,
        // 换文件后旧对照上下文全部失效
        compareFor: null, compareEventIndex: 0, compareResume: null,
        // 换文件后时序图阅读上下文失效(旧会话的段位置/缩放窗口不再有意义)
        ...resetDiagramContext(),
        // 主抓包更换 → 副抓包必须重新提供(两侧必须同源同批,旧 B 侧与新 A 侧无可比性)
        dualMeta: null, dualPackets: null, dualPath: '', dualLoading: false, dualLoadingFrames: 0, dualError: null,
        // 递增 dualLoadSeq:让挂起中的 B 侧加载(其 seq 已被占用)自然过期,
        // 完成后被「seq !== 快照」挡住,不得写入新主抓包的对照上下文
        dualLoadSeq: get().dualLoadSeq + 1,
      })
    } catch (e) {
      if (get().loadSeq !== seq) return
      set({ loading: false, error: String(e) })
    }
  },

  async openExample(name) {
    cancelParse()
    const seq = get().loadSeq + 1
    set({ loading: true, loadingFrames: 0, error: null, loadSeq: seq })
    const t0 = performance.now()
    try {
      const { meta, packets, path } = await openSample(name, (frames) => {
        if (get().loadSeq === seq) set({ loadingFrames: frames })
      })
      if (get().loadSeq !== seq) return
      const conversations = aggregateConversations(packets, { slowResponseThreshold: get().slowThreshold })
      const filter = emptyFilter()
      set({
        meta: { ...meta, parseMs: performance.now() - t0 }, packets, conversations, options: collectFilterOptions(packets),
        filter, filtered: conversations, selectedId: null, selectedPacket: null,
        currentPath: path, hexCache: resetHexCache(), searchQuery: '', searchHits: [], searchHitIndex: -1, highlight: [], timeRange: null, loading: false,
        compareFor: null, compareEventIndex: 0, compareResume: null,
        // 示例同样替换主抓包:同源同批约束与 openFile 一致
        ...resetDiagramContext(),
        dualMeta: null, dualPackets: null, dualPath: '', dualLoading: false, dualLoadingFrames: 0, dualError: null,
        dualLoadSeq: get().dualLoadSeq + 1,
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
  dismissError() {
    set({ error: null })
  },
  clearFilter() {
    const filter = emptyFilter()
    set({ filter, filtered: deriveFiltered(get().conversations, filter, get().timeRange) })
  },
  setTimeRange(r) {
    const s = get()
    const filtered = deriveFiltered(s.conversations, s.filter, r)
    const patch: Partial<AppState> = { timeRange: r, filtered }
    if (r) {
      // 定位语义:选中窗口内报文最多的会话,并在时序图上高亮窗口内报文。
      // 长会话区间横跨整个时间轴时,单纯的「区间重叠过滤」列表毫无变化——定位+高亮才是可见反应
      // best 只在 filtered(筛选+时间窗)内扫描:被筛选掉的会话不得被选中/高亮
      let best: Conversation | null = null
      let bestCount = 0
      let bestNums: number[] = []
      for (const c of filtered) {
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
        // 时序图阅读上下文跟随定位的会话(时间窗下钻改变阅读对象)
        patch.seqSegIdx = null
        patch.seqSpaceWindows = {}
        // 高亮仅用于视觉定位,窗口内命中报文超过上限时只保留前 2000 个报文号;
        // 截断只作用于写入 highlight 的数组,bestCount 判定仍用完整计数
        patch.highlight = bestNums.length > HIGHLIGHT_LIMIT ? bestNums.slice(0, HIGHLIGHT_LIMIT) : bestNums
      } else {
        // 筛选/窗口内无命中会话:清空选中与高亮,避免时序图继续渲染
        // 不在当前列表/时间窗内的会话(列表空但图有内容的视觉分裂)
        patch.selectedId = null
        patch.selectedPacket = null
        patch.highlight = []
        patch.seqSegIdx = null
        patch.seqSpaceWindows = {}
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
    // 切换会话时重置时序图阅读上下文(段位置/缩放窗口跟随新会话);同会话再选保留
    set(get().selectedId === id ? { selectedId: id, selectedPacket: null } : { selectedId: id, selectedPacket: null, ...resetDiagramContext() })
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
    // 每次查询重算命中(对当前全量会话搜索,跨会话扁平、按帧号升序),命中时定位到第一条。
    // 无命中/空查询:沿用旧语义仅清空高亮,不触碰选中(与旧实现 set({ searchQuery, highlight: [] }) 对齐)
    const hits = searchHitNumbers(get().conversations, q)
    if (hits.length === 0) {
      set({ searchQuery: q, searchHits: [], searchHitIndex: -1, highlight: [] })
    } else {
      const hit = locateHit(get().conversations, hits, 0)
      set({ searchQuery: q, searchHits: hits, searchHitIndex: 0, highlight: [hits[0]] })
      if (hit) {
        get().select(hit.id) // 选中所在会话(复用现有会话切换联动)
        set({ selectedPacket: hit.number }) // 选中该报文触发详情
      }
    }
  },
  nextSearchHit() {
    const s = get()
    const n = s.searchHits.length
    if (n === 0) return
    const idx = (s.searchHitIndex + 1) % n // 循环:末尾 → 第一条
    const hit = locateHit(s.conversations, s.searchHits, idx)
    set({ searchHitIndex: idx, highlight: [s.searchHits[idx]] })
    if (hit) {
      get().select(hit.id)
      set({ selectedPacket: hit.number })
    }
  },
  prevSearchHit() {
    const s = get()
    const n = s.searchHits.length
    if (n === 0) return
    const idx = (s.searchHitIndex - 1 + n) % n // 循环:开头 → 最后一条
    const hit = locateHit(s.conversations, s.searchHits, idx)
    set({ searchHitIndex: idx, highlight: [s.searchHits[idx]] })
    if (hit) {
      get().select(hit.id)
      set({ selectedPacket: hit.number })
    }
  },
  setHighlight(nums) {
    set({ highlight: nums })
  },
  async loadTsharkVersion() {
    const v = await getTsharkVersion()
    set({ tsharkVersion: v })
  },
  async setTsharkPath(path) {
    await setTsharkPathCmd(path)
    // 设置成功后重新拉取版本(路径变化后旧版本号已不准确)
    await get().loadTsharkVersion()
  },
  async fetchHexFor(n) {
    const path = get().currentPath
    if (!path) return ''
    const cached = get().hexCache[n]
    if (cached) return cached
    const key = `${path}:${n}`
    const pending = hexInflight.get(key)
    if (pending) return pending
    const p = (async () => {
      const hex = await fetchHex(path, n)
      if (get().currentPath !== path) return '' // 已切换文件,丢弃过期结果
      set((s) => ({ hexCache: hexCachePut(s.hexCache, n, hex) }))
      return hex
    })().finally(() => {
      hexInflight.delete(key)
    })
    hexInflight.set(key, p)
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
