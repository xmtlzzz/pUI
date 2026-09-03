// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach } from 'vitest'

vi.mock('../bridge/tauri', () => ({
  openCapture: vi.fn(),
  openSample: vi.fn(),
  fetchHex: vi.fn(),
  getTsharkVersion: vi.fn(),
  setTsharkPath: vi.fn(),
}))

import { openCapture, openSample, fetchHex, getTsharkVersion, setTsharkPath } from '../bridge/tauri'
import { useApp } from './appStore'
import type { Conversation, Packet } from '../model/types'

function pkt(n: number, proto: string, srcIp: string, srcPort: number, dstIp: string, dstPort: number): Packet {
  return { number: n, time: n, len: 60, transport: 'tcp', proto, srcIp, dstIp, srcPort, dstPort, direction: 'other' }
}

function meta(fileName: string) {
  return { fileName, packetCount: 1, interfaces: 1, timeStart: 0, timeEnd: 0, fileSize: 10 }
}

describe('appStore 加载一致性', () => {
  beforeEach(() => {
    useApp.setState({
      meta: null, packets: [], conversations: [], filtered: [], options: { protocols: [], srcIps: [], dstIps: [], ports: [] },
      filter: { protocol: [], srcIp: [], dstIp: [], srcPort: [], dstPort: [], negate: false, issueOnly: false },
      selectedId: null, selectedPacket: null, currentPath: '', loadSeq: 0, diagramStyle: 'A', loading: false, error: null, hexCache: {},
    })
  })

  it('打开新文件时清空 hexCache,避免跨文件显示旧报文的 hex', async () => {
    const packets = [pkt(1, 'http', '1.1.1.1', 5000, '2.2.2.2', 80)]
    vi.mocked(openCapture).mockImplementation((p: string) => Promise.resolve({ meta: meta(p), packets, path: p }))
    useApp.setState({ hexCache: { 5: 'AA' }, currentPath: 'a.pcap' })

    await useApp.getState().openFile('b.pcap')

    expect(useApp.getState().currentPath).toBe('b.pcap')
    expect(useApp.getState().hexCache).toEqual({})
    expect(useApp.getState().packets).toHaveLength(1)
  })

  it('openFile 记录解析耗时 parseMs', async () => {
    const packets = [pkt(1, 'http', '1.1.1.1', 5000, '2.2.2.2', 80)]
    vi.mocked(openCapture).mockImplementation((p: string) => Promise.resolve({ meta: meta(p), packets, path: p }))
    await useApp.getState().openFile('b.pcap')
    const m = useApp.getState().meta
    expect(m).not.toBeNull()
    expect(typeof m?.parseMs).toBe('number')
    expect((m?.parseMs ?? -1) >= 0).toBe(true)
  })

  it('慢加载不覆盖已完成的较新加载', async () => {
    const slowPackets = [pkt(1, 'http', '1.1.1.1', 5000, '2.2.2.2', 80)]
    const fastPackets = [pkt(1, 'dns', '1.1.1.1', 5000, '8.8.8.8', 53)]
    let resolveSlow!: (v: { meta: ReturnType<typeof meta>; packets: Packet[]; path: string }) => void
    vi.mocked(openCapture).mockImplementation((p: string) =>
      p === 'slow'
        ? new Promise((r) => {
            resolveSlow = r
          })
        : Promise.resolve({ meta: meta('fast.pcap'), packets: fastPackets, path: 'fast.pcap' }),
    )

    const slowLoad = useApp.getState().openFile('slow') // 先发起慢加载
    await useApp.getState().openFile('fast') // 后发起快加载,先完成
    expect(useApp.getState().conversations[0]?.protocol).toBe('dns')

    resolveSlow({ meta: meta('slow.pcap'), packets: slowPackets, path: 'slow.pcap' })
    await slowLoad
    expect(useApp.getState().conversations[0]?.protocol).toBe('dns') // 未被慢加载覆盖
    expect(useApp.getState().currentPath).toBe('fast.pcap')
  })

  it('fetchHexFor 并发请求同一帧只调用一次 fetchHex(去重)', async () => {
    vi.mocked(fetchHex).mockResolvedValue('AA')
    useApp.setState({ currentPath: 'x.pcap' })
    const [a, b] = await Promise.all([useApp.getState().fetchHexFor(1), useApp.getState().fetchHexFor(1)])
    expect(a).toBe('AA')
    expect(b).toBe('AA')
    expect(fetchHex).toHaveBeenCalledTimes(1)
  })

  it('setTimeRange 只保留与时间窗重叠的会话(区间下钻)', async () => {
    const early = [pkt(1, 'http', '1.1.1.1', 5000, '2.2.2.2', 80), { ...pkt(2, 'http', '2.2.2.2', 80, '1.1.1.1', 5000) } as Packet]
    const late = [pkt(3, 'dns', '1.1.1.1', 5000, '8.8.8.8', 53), { ...pkt(4, 'dns', '8.8.8.8', 53, '1.1.1.1', 5000) } as Packet]
    vi.mocked(openCapture).mockImplementation((p: string) => Promise.resolve({ meta: meta(p), packets: [...early, ...late], path: p }))
    await useApp.getState().openFile('x.pcap')
    expect(useApp.getState().filtered).toHaveLength(2)
    useApp.getState().setTimeRange({ start: 2.5, end: 10 })
    expect(useApp.getState().filtered).toHaveLength(1)
    expect(useApp.getState().filtered[0].protocol).toBe('dns')
    useApp.getState().setTimeRange(null)
    expect(useApp.getState().filtered).toHaveLength(2)
  })

  it('setTimeRange 自动定位窗口内报文最多的会话并高亮其窗口内报文', async () => {
    // 模拟真实:长会话横跨全部时间轴,单纯区间过滤列表不变;定位+高亮才是「能看到反应」的语义
    const a = [
      { ...pkt(101, 'http', '1.1.1.1', 5000, '2.2.2.2', 80), time: 0.1 },
      { ...pkt(102, 'http', '2.2.2.2', 80, '1.1.1.1', 5000), time: 0.2 },
    ] as Packet[]
    const b = [
      { ...pkt(201, 'dns', '1.1.1.1', 5000, '8.8.8.8', 53), time: 5.1 },
      { ...pkt(202, 'dns', '8.8.8.8', 53, '1.1.1.1', 5000), time: 5.2 },
      { ...pkt(203, 'dns', '1.1.1.1', 5000, '8.8.8.8', 53), time: 5.3 },
    ] as Packet[]
    vi.mocked(openCapture).mockImplementation((p: string) =>
      Promise.resolve({ meta: meta(p), packets: [...a, ...b], path: p }),
    )
    await useApp.getState().openFile('x.pcap')
    useApp.setState({ selectedId: null })
    // 窗口 [5,6):b 会话 3 报文命中,a 会话 0 → 应选中 b 会话并高亮其 3 个报文
    useApp.getState().setTimeRange({ start: 5, end: 6 })
    const st = useApp.getState()
    expect(st.selectedId).toBe(st.conversations.find((c) => c.protocol === 'dns')?.id)
    expect(st.highlight.length).toBe(3)
    expect(st.highlight).toEqual([201, 202, 203])
    // filtered 仍按区间重叠
    expect(st.filtered.map((c) => c.protocol)).toEqual(['dns'])
  })

  it('setTimeRange 高亮报文号超过 2000 时截断(仅保留前 2000),选中与计数仍用完整报文', async () => {
    const many = Array.from({ length: 2500 }, (_, i) => ({
      ...pkt(i + 1, 'http', '1.1.1.1', 5000, '2.2.2.2', 80),
      time: i * 0.001,
    }) as Packet)
    vi.mocked(openCapture).mockImplementation((p: string) => Promise.resolve({ meta: meta(p), packets: many, path: p }))
    await useApp.getState().openFile('x.pcap')
    const big = useApp.getState().conversations[0]
    expect(big.packets.length).toBe(2500)
    // 窗口覆盖全部包:命中 2500 > 2000,高亮截断到前 2000,但选中仍指向该会话(bestCount 用原始计数)
    useApp.getState().setTimeRange({ start: 0, end: 3 })
    const st = useApp.getState()
    expect(st.selectedId).toBe(big.id)
    expect(st.highlight.length).toBeLessThanOrEqual(2000)
    expect(st.highlight).toEqual(many.slice(0, 2000).map((p) => p.number))
  })

  it('setTimeRange 下钻遵循筛选:best 只在筛选后可见的会话中选择(被过滤掉的会话不得被选中)', async () => {
    const httpPackets = [
      { ...pkt(1, 'http', '1.1.1.1', 5000, '2.2.2.2', 80), time: 5.0 },
      { ...pkt(2, 'http', '2.2.2.2', 80, '1.1.1.1', 5000), time: 5.01 },
      { ...pkt(3, 'http', '1.1.1.1', 5000, '2.2.2.2', 80), time: 5.02 },
    ] as Packet[]
    const dnsPackets = [
      { ...pkt(4, 'dns', '1.1.1.1', 5000, '8.8.8.8', 53), time: 5.1 },
    ] as Packet[]
    vi.mocked(openCapture).mockImplementation((p: string) =>
      Promise.resolve({ meta: meta(p), packets: [...httpPackets, ...dnsPackets], path: p }),
    )
    await useApp.getState().openFile('x.pcap')
    // 激活筛选:只看 dns 会话(http 会话被过滤掉)
    useApp.getState().setFilter({ protocol: ['dns'] })
    expect(useApp.getState().filtered.map((c) => c.protocol)).toEqual(['dns'])
    // 窗口 [5,6]:http 会话窗口内 3 包(最多),但已被筛选掉;若 best 扫全部会话会错选它
    useApp.getState().setTimeRange({ start: 5, end: 6 })
    const st = useApp.getState()
    const dnsId = st.conversations.find((c) => c.protocol === 'dns')?.id
    expect(st.selectedId).toBe(dnsId)
    expect(st.filtered.map((c) => c.protocol)).toEqual(['dns'])
    expect(st.highlight).toEqual([4])
  })

  it('setTimeRange 筛选无命中(filtered 为空)时清空 selectedId/highlight,不残留窗口外会话', async () => {
    const packets = [pkt(1, 'http', '1.1.1.1', 5000, '2.2.2.2', 80)]
    vi.mocked(openCapture).mockImplementation((p: string) => Promise.resolve({ meta: meta(p), packets, path: p }))
    await useApp.getState().openFile('x.pcap')
    const convId = useApp.getState().conversations[0].id
    useApp.getState().select(convId)
    useApp.getState().setHighlight([1])
    // 激活筛选把唯一会话过滤掉 → filtered 为空(筛选本身不清选中)
    useApp.getState().setFilter({ protocol: ['dns'] })
    expect(useApp.getState().filtered).toHaveLength(0)
    expect(useApp.getState().selectedId).toBe(convId)
    // 下钻时间窗:filtered 为空无从定位 → 选中与高亮必须清空,时序图不得继续渲染窗口外会话
    useApp.getState().setTimeRange({ start: 0, end: 10 })
    const st = useApp.getState()
    expect(st.selectedId).toBeNull()
    expect(st.highlight).toEqual([])
    expect(st.selectedPacket).toBeNull()
  })

  it('setTimeRange 窗口内无命中报文(best 为空)时清空 selectedId/highlight', async () => {
    // 会话时间跨 [1,5],窗口 [2.5,3.5] 与区间重叠(filtered 非空)但无报文落在窗口内 → best 为空
    const packets = [
      { ...pkt(1, 'http', '1.1.1.1', 5000, '2.2.2.2', 80), time: 1 },
      { ...pkt(2, 'http', '2.2.2.2', 80, '1.1.1.1', 5000), time: 5 },
    ] as Packet[]
    vi.mocked(openCapture).mockImplementation((p: string) => Promise.resolve({ meta: meta(p), packets, path: p }))
    await useApp.getState().openFile('x.pcap')
    const convId = useApp.getState().conversations[0].id
    useApp.getState().select(convId)
    useApp.getState().setHighlight([1])
    // 窗口 [2.5,3.5]:会话区间重叠被保留,但窗口内无报文 → best==null,bestCount==0
    useApp.getState().setTimeRange({ start: 2.5, end: 3.5 })
    const st = useApp.getState()
    expect(st.filtered).toHaveLength(1)
    expect(st.selectedId).toBeNull()
    expect(st.highlight).toEqual([])
    expect(st.selectedPacket).toBeNull()
  })

  it('hexCache 超过上限按 LRU 逐出最旧条目', async () => {
    vi.mocked(fetchHex).mockImplementation((_p: string, n: number) => Promise.resolve(`hex${n}`))
    useApp.setState({ currentPath: 'x.pcap' })
    const N = 205 // HEX_CACHE_LIMIT=200,超出 5 条触发逐出
    for (let i = 1; i <= N; i++) {
      await useApp.getState().fetchHexFor(i)
    }
    const cache = useApp.getState().hexCache
    expect(Object.keys(cache).length).toBeLessThanOrEqual(200)
    expect(cache[1]).toBeUndefined() // 最早的被逐出
    expect(cache[N]).toBe(`hex${N}`) // 最新的保留
  })

  it('fetchHexFor 在切换文件后丢弃旧文件的 hex 结果', async () => {
    vi.mocked(fetchHex).mockResolvedValue('STALE')
    useApp.setState({ currentPath: 'old.pcap' })
    const p = useApp.getState().fetchHexFor(1) // 挂起中(未 resolve)
    useApp.setState({ currentPath: 'new.pcap' })
    await p
    expect(useApp.getState().hexCache[1]).toBeUndefined() // 旧结果未写入新文件缓存
  })

  it('fetchHexFor 旧文件取 #N 挂起时切换文件:新文件同号报文必须重新发起,不被旧 in-flight 复用', async () => {
    // 旧文件 #1 的 hex 请求挂起(永不立即 resolve)
    let resolveOld!: (v: string) => void
    vi.mocked(fetchHex).mockImplementationOnce(
      (_p: string, _n: number) => new Promise<string>((r) => { resolveOld = r }),
    )
    useApp.setState({ currentPath: 'old.pcap' })
    const oldFetch = useApp.getState().fetchHexFor(1)

    // 切换文件后立即选中同号报文 #1:新请求必须拿到新文件的 hex
    useApp.setState({ currentPath: 'new.pcap' })
    vi.mocked(fetchHex).mockResolvedValueOnce('NEWHEX')
    const newFetch = useApp.getState().fetchHexFor(1)
    const newRes = await newFetch
    expect(newRes).toBe('NEWHEX')
    expect(useApp.getState().hexCache[1]).toBe('NEWHEX')

    // 旧 promise 最终 resolve:不得污染新文件的缓存
    resolveOld('OLDHEX')
    await oldFetch
    expect(useApp.getState().hexCache[1]).toBe('NEWHEX')
    expect(useApp.getState().hexCache[1]).not.toBe('OLDHEX')
  })
})

describe('时序图阅读上下文(跨形态保留)', () => {
  beforeEach(() => {
    useApp.setState({ selectedId: null, selectedPacket: null, seqSegIdx: null, seqSpaceWindows: {} })
  })

  it('select 切换会话时重置 segIdx/缩放窗口;同会话保留', () => {
    useApp.setState({ selectedId: 'a', seqSegIdx: 2, seqSpaceWindows: { 'tcp-c2s-0': { start: 1, end: 2 } } })
    useApp.getState().select('b')
    expect(useApp.getState().seqSegIdx).toBeNull()
    expect(useApp.getState().seqSpaceWindows).toEqual({})
    expect(useApp.getState().selectedPacket).toBeNull()

    // 同会话再次 select:阅读上下文保留(切换 A/B/C/D 形态依赖)
    useApp.setState({ seqSegIdx: 1, seqSpaceWindows: { 'tcp-c2s-0': { start: 5, end: 9 } } })
    useApp.getState().select('b')
    expect(useApp.getState().seqSegIdx).toBe(1)
    expect(useApp.getState().seqSpaceWindows).toEqual({ 'tcp-c2s-0': { start: 5, end: 9 } })
  })

  it('setSeqSegIdx/setSeqSpaceWindows 更新状态,窗口支持函数式更新与 null(全轴)', () => {
    useApp.getState().setSeqSegIdx(2)
    expect(useApp.getState().seqSegIdx).toBe(2)
    useApp.getState().setSeqSegIdx(null)
    expect(useApp.getState().seqSegIdx).toBeNull()

    useApp.getState().setSeqSpaceWindows({ 'tcp-c2s-0': { start: 5, end: 9 } })
    expect(useApp.getState().seqSpaceWindows).toEqual({ 'tcp-c2s-0': { start: 5, end: 9 } })
    // 函数式更新:滚轮缩放以 prev 为基础增量写入
    useApp.getState().setSeqSpaceWindows((prev) => ({ ...prev, 'tcp-s2c-1': { start: 0, end: 3 } }))
    expect(useApp.getState().seqSpaceWindows).toEqual({ 'tcp-c2s-0': { start: 5, end: 9 }, 'tcp-s2c-1': { start: 0, end: 3 } })
    // null 值 = 该带回到全轴(双击复位后逐带清空)
    useApp.getState().setSeqSpaceWindows({ 'tcp-c2s-0': null })
    expect(useApp.getState().seqSpaceWindows['tcp-c2s-0']).toBeNull()
  })

  it('openFile 打开新文件时重置阅读上下文', async () => {
    useApp.setState({ selectedId: 'a', seqSegIdx: 1, seqSpaceWindows: { 'tcp-c2s-0': { start: 1, end: 2 } } })
    vi.mocked(openCapture).mockImplementation((p: string) =>
      Promise.resolve({ meta: meta(p), packets: [pkt(1, 'http', '1.1.1.1', 5000, '2.2.2.2', 80)], path: p }),
    )
    await useApp.getState().openFile('b.pcap')
    expect(useApp.getState().seqSegIdx).toBeNull()
    expect(useApp.getState().seqSpaceWindows).toEqual({})
  })

  it('setTimeRange 自动定位到新会话时重置阅读上下文', async () => {
    const early = [pkt(1, 'http', '1.1.1.1', 5000, '2.2.2.2', 80)]
    const late = [pkt(3, 'dns', '1.1.1.1', 5000, '8.8.8.8', 53), pkt(4, 'dns', '8.8.8.8', 53, '1.1.1.1', 5000)]
    vi.mocked(openCapture).mockImplementation((p: string) =>
      Promise.resolve({ meta: meta(p), packets: [...early, ...late], path: p }),
    )
    await useApp.getState().openFile('x.pcap')
    const dns = useApp.getState().conversations.find((c) => c.protocol === 'dns')!
    useApp.getState().select(dns.id)
    useApp.getState().setSeqSegIdx(3)
    // 时间窗定位到 http 会话(selectedId 变化)→ 阅读上下文重置
    useApp.getState().setTimeRange({ start: 0, end: 2 })
    expect(useApp.getState().selectedId).not.toBe(dns.id)
    expect(useApp.getState().seqSegIdx).toBeNull()
    expect(useApp.getState().seqSpaceWindows).toEqual({})
  })

  it('setDiagramStyle 切换形态不清空阅读上下文(跨形态保留的核心)', () => {
    useApp.setState({ seqSegIdx: 1, seqSpaceWindows: { 'tcp-c2s-0': { start: 5, end: 9 } } })
    useApp.getState().setDiagramStyle('A')
    useApp.getState().setDiagramStyle('C')
    useApp.getState().setDiagramStyle('D')
    useApp.getState().setDiagramStyle('B')
    expect(useApp.getState().seqSegIdx).toBe(1)
    expect(useApp.getState().seqSpaceWindows).toEqual({ 'tcp-c2s-0': { start: 5, end: 9 } })
  })
})

describe('M4 对照页导航状态', () => {
  const R = {
    conversationId: 'conv-1',
    eventIndex: 2,
    stageIndex: 3,
  }

  it('openCompare 重置事件下标;jumpFromCompare 记录来源且 closeCompare 不清除', () => {
    useApp.setState({ compareFor: 'old', compareEventIndex: 5, compareResume: null })
    useApp.getState().openCompare('conv-1')
    expect(useApp.getState().compareEventIndex).toBe(0)
    useApp.getState().setCompareEventIndex(4)
    expect(useApp.getState().compareEventIndex).toBe(4)
    // 负数钳制到 0
    useApp.getState().setCompareEventIndex(-3)
    expect(useApp.getState().compareEventIndex).toBe(0)

    useApp.getState().jumpFromCompare(R)
    useApp.getState().closeCompare()
    expect(useApp.getState().compareResume).toEqual(R) // 恢复入口仍可用
  })

  it('consumeCompareResume 读改一体:取走后为 null,再次取走返回 null', () => {
    useApp.setState({ compareResume: R })
    expect(useApp.getState().consumeCompareResume()).toEqual(R)
    expect(useApp.getState().compareResume).toBeNull()
    expect(useApp.getState().consumeCompareResume()).toBeNull()
  })

  it('clearCompareResume 兜底清除', () => {
    useApp.setState({ compareResume: R })
    useApp.getState().clearCompareResume()
    expect(useApp.getState().compareResume).toBeNull()
  })
})

describe('双点对照 store(副抓包状态)', () => {
  beforeEach(() => {
    useApp.setState({
      meta: null, packets: [], conversations: [], filtered: [], currentPath: '', loadSeq: 0,
      dualMeta: null, dualPackets: null, dualPath: '', dualLoading: false, dualLoadingFrames: 0, dualError: null, dualLoadSeq: 0,
    })
  })

  it('openDualExample 成功载入 dualPackets 与 dualMeta', async () => {
    const dualPackets: Packet[] = [
      { number: 1, time: 1.5, timeEpoch: 1700000001.5, len: 60, transport: 'tcp', proto: 'tcp', srcIp: '10.0.0.8', dstIp: '10.0.0.9', srcPort: 61000, dstPort: 8080, direction: 'request' },
    ]
    vi.mocked(openSample).mockImplementation(() =>
      Promise.resolve({ meta: meta('dual-b.pcapng'), packets: dualPackets, path: 'dual-b' }),
    )
    await useApp.getState().openDualExample('dual-b')
    const s = useApp.getState()
    expect(s.dualPackets).toEqual(dualPackets)
    expect(s.dualMeta?.fileName).toBe('dual-b.pcapng')
    expect(s.dualPath).toBe('dual-b')
    expect(s.dualLoading).toBe(false)
    expect(s.dualError).toBeNull()
  })

  it('openDualExample 失败时写 dualError 且不清空旧数据', async () => {
    vi.mocked(openSample).mockImplementation(() => Promise.reject(new Error('missing example: nope')))
    await useApp.getState().openDualExample('nope')
    const s = useApp.getState()
    expect(s.dualError).toContain('missing example: nope')
    expect(s.dualLoading).toBe(false)
    expect(s.dualPackets).toBeNull()
  })

  it('openDualExample 过期加载(loadSeq 已被更新)不写入状态', async () => {
    let resolveSlow!: (v: { meta: ReturnType<typeof meta>; packets: Packet[]; path: string }) => void
    vi.mocked(openSample).mockImplementation(
      () => new Promise((r) => { resolveSlow = r }),
    )
    const slow = useApp.getState().openDualExample('slow-b')
    // 期间又发起一次 dual 加载(dualLoadSeq 递增),先让它立即完成
    vi.mocked(openSample).mockImplementation(() =>
      Promise.resolve({ meta: meta('fast-b.pcapng'), packets: [], path: 'fast-b' }),
    )
    await useApp.getState().openDualExample('fast-b')
    resolveSlow({ meta: meta('slow-b.pcapng'), packets: [], path: 'slow-b' })
    await slow
    // 慢加载的结果被丢弃,仍是快加载的
    expect(useApp.getState().dualPath).toBe('fast-b')
  })

  it('openFile(主抓包)清空 dual 状态:两侧必须同源同批', async () => {
    // 先装上 dual 状态
    useApp.setState({
      dualMeta: meta('dual-b.pcapng'),
      dualPackets: [],
      dualPath: 'dual-b',
      dualError: 'stale',
    })
    vi.mocked(openCapture).mockImplementation((p: string) =>
      Promise.resolve({ meta: meta(p), packets: [pkt(1, 'http', '1.1.1.1', 5000, '2.2.2.2', 80)], path: p }),
    )
    await useApp.getState().openFile('new-main.pcap')
    const s = useApp.getState()
    expect(s.dualMeta).toBeNull()
    expect(s.dualPackets).toBeNull()
    expect(s.dualPath).toBe('')
    expect(s.dualError).toBeNull()
  })

  it('openFile 递增 dualLoadSeq:挂起中的 B 侧加载完成后不得写入新主抓包上下文', async () => {
    // 慢 B 侧加载挂起(dualLoading=true,dualLoadSeq 已占位)
    let resolveDual!: (v: { meta: ReturnType<typeof meta>; packets: Packet[]; path: string }) => void
    vi.mocked(openSample).mockImplementation(
      () => new Promise((r) => { resolveDual = r }),
    )
    const dualLoad = useApp.getState().openDualExample('slow-b')
    expect(useApp.getState().dualLoading).toBe(true)

    // 挂起期间切换主抓包:dual 状态被清零,且 dualLoadSeq 必须递增使挂起加载过期
    vi.mocked(openCapture).mockImplementation((p: string) =>
      Promise.resolve({ meta: meta(p), packets: [pkt(1, 'http', '1.1.1.1', 5000, '2.2.2.2', 80)], path: p }),
    )
    await useApp.getState().openFile('new-main.pcap')
    expect(useApp.getState().dualLoading).toBe(false)
    expect(useApp.getState().dualPackets).toBeNull()

    // 挂起的 B 侧最终 resolve:结果必须被丢弃,不得写入新 A 侧抓包的对照上下文
    resolveDual({ meta: meta('slow-b.pcapng'), packets: [pkt(99, 'tcp', '9.9.9.9', 100, '8.8.8.8', 53)], path: 'slow-b' })
    await dualLoad
    const s = useApp.getState()
    expect(s.dualPackets).toBeNull()
    expect(s.dualMeta).toBeNull()
    expect(s.dualPath).toBe('')
  })

  it('clearDual 清空副抓包状态', async () => {
    useApp.setState({ dualMeta: meta('dual-b.pcapng'), dualPackets: [], dualPath: 'dual-b', dualError: 'x' })
    useApp.getState().clearDual()
    const s = useApp.getState()
    expect(s.dualMeta).toBeNull()
    expect(s.dualPackets).toBeNull()
    expect(s.dualPath).toBe('')
    expect(s.dualError).toBeNull()
  })

  it('openDualExample 流式进度写入 dualLoadingFrames', async () => {
    vi.mocked(openSample).mockImplementation((_n: string, onProgress?: (f: number) => void) => {
      onProgress?.(123)
      return Promise.resolve({ meta: meta('dual-b.pcapng'), packets: [], path: 'dual-b' })
    })
    await useApp.getState().openDualExample('dual-b')
    expect(useApp.getState().dualLoadingFrames).toBe(123)
  })

  it('setTsharkPath 调用桥接并成功后重拉版本号', async () => {
    vi.mocked(setTsharkPath).mockResolvedValue(undefined)
    vi.mocked(getTsharkVersion).mockResolvedValue('4.6.6')
    useApp.setState({ tsharkVersion: null })
    await useApp.getState().setTsharkPath('C:/Wireshark/tshark.exe')
    expect(setTsharkPath).toHaveBeenCalledWith('C:/Wireshark/tshark.exe')
    // 设置成功后重拉版本(路径变化后旧版本号已不准确)
    expect(getTsharkVersion).toHaveBeenCalled()
    expect(useApp.getState().tsharkVersion).toBe('4.6.6')
  })
})

describe('搜索命中逐条导航', () => {
  /** c1 命中 #1 #4,c2 命中 #3:跨会话 + 全局帧号排序(3 在 4 前)都覆盖 */
  function navConvs(): Conversation[] {
    const c1: Conversation = {
      id: 'c1', client: 'a', server: 'b', protocol: 'http', packetCount: 3, bytes: 180,
      start: 0, end: 0.3, duration: 0.3, packets: [], issues: [],
    }
    c1.packets = [
      { ...pkt(1, 'http', '1.1.1.1', 5000, '2.2.2.2', 80), info: 'GET /alpha' } as Packet,
      { ...pkt(2, 'http', '1.1.1.1', 5000, '2.2.2.2', 80) } as Packet,
      { ...pkt(4, 'http', '1.1.1.1', 5000, '2.2.2.2', 80), info: 'POST /alpha' } as Packet,
    ]
    const c2: Conversation = {
      id: 'c2', client: 'x', server: 'y', protocol: 'http', packetCount: 2, bytes: 120,
      start: 0, end: 0.2, duration: 0.2, packets: [], issues: [],
    }
    c2.packets = [
      { ...pkt(3, 'http', '1.1.1.1', 5000, '2.2.2.2', 80), info: 'GET /alpha' } as Packet,
      { ...pkt(5, 'http', '1.1.1.1', 5000, '2.2.2.2', 80) } as Packet,
    ]
    return [c1, c2]
  }

  it('setSearchQuery 重算命中并按帧号升序,index 置 0 并定位到第一条命中', () => {
    useApp.setState({ conversations: navConvs(), selectedId: null, selectedPacket: null, highlight: [99] })
    useApp.getState().setSearchQuery('alpha')
    const s = useApp.getState()
    expect(s.searchHits).toEqual([1, 3, 4]) // 跨会话后仍按帧号排序(3 在 4 前)
    expect(s.searchHitIndex).toBe(0)
    expect(s.selectedId).toBe('c1') // 定位:第一条命中所在会话
    expect(s.selectedPacket).toBe(1) // 并选中该报文触发详情
    expect(s.highlight).toEqual([1]) // 新查询把旧高亮替换为当前命中
  })

  it('setSearchQuery 空查询/无命中清空 hits 并置 index=-1', () => {
    useApp.setState({ conversations: navConvs() })
    useApp.getState().setSearchQuery('alpha')
    useApp.getState().setSearchQuery('zzz')
    expect(useApp.getState().searchHits).toEqual([])
    expect(useApp.getState().searchHitIndex).toBe(-1)
  })

  it('nextSearchHit 逐条前进,跨会话定位命中报文所在会话并联动高亮', () => {
    useApp.setState({ conversations: navConvs(), selectedId: null, selectedPacket: null, highlight: [] })
    useApp.getState().setSearchQuery('alpha') // index=0 → #1(c1)
    useApp.getState().nextSearchHit() // → #3(c2):跨会话跳转
    let s = useApp.getState()
    expect(s.searchHitIndex).toBe(1)
    expect(s.selectedId).toBe('c2')
    expect(s.selectedPacket).toBe(3)
    expect(s.highlight).toEqual([3])
    useApp.getState().nextSearchHit() // → #4(c1)
    s = useApp.getState()
    expect(s.searchHitIndex).toBe(2)
    expect(s.selectedId).toBe('c1')
    expect(s.selectedPacket).toBe(4)
    expect(s.highlight).toEqual([4])
  })

  it('nextSearchHit 到末尾后循环回第一条', () => {
    useApp.setState({ conversations: navConvs(), selectedId: null, selectedPacket: null, highlight: [] })
    useApp.getState().setSearchQuery('alpha') // 0
    useApp.getState().nextSearchHit() // 1
    useApp.getState().nextSearchHit() // 2
    useApp.getState().nextSearchHit() // 回绕到 0
    const s = useApp.getState()
    expect(s.searchHitIndex).toBe(0)
    expect(s.selectedPacket).toBe(1)
    expect(s.highlight).toEqual([1])
  })

  it('prevSearchHit 从第一条循环回最后一条,并定位', () => {
    useApp.setState({ conversations: navConvs(), selectedId: null, selectedPacket: null, highlight: [] })
    useApp.getState().setSearchQuery('alpha') // 0
    useApp.getState().prevSearchHit() // → 2(循环到最后一条)
    let s = useApp.getState()
    expect(s.searchHitIndex).toBe(2)
    expect(s.selectedId).toBe('c1')
    expect(s.selectedPacket).toBe(4)
    expect(s.highlight).toEqual([4])
    useApp.getState().prevSearchHit() // → 1
    s = useApp.getState()
    expect(s.searchHitIndex).toBe(1)
    expect(s.selectedId).toBe('c2')
    expect(s.selectedPacket).toBe(3)
  })

  it('无命中时 next/prev 不动 index 也不定位', () => {
    useApp.setState({ conversations: navConvs(), selectedId: null, selectedPacket: null, highlight: [] })
    useApp.getState().setSearchQuery('zzz')
    useApp.getState().nextSearchHit()
    useApp.getState().prevSearchHit()
    const s = useApp.getState()
    expect(s.searchHitIndex).toBe(-1)
    expect(s.selectedPacket).toBeNull()
    expect(s.highlight).toEqual([])
  })

  it('打开新文件清空搜索命中导航状态', async () => {
    useApp.setState({ conversations: navConvs(), searchQuery: 'alpha', searchHits: [1, 3, 4], searchHitIndex: 2 })
    vi.mocked(openCapture).mockImplementation((p: string) =>
      Promise.resolve({ meta: meta(p), packets: [pkt(1, 'http', '1.1.1.1', 5000, '2.2.2.2', 80)], path: p }),
    )
    await useApp.getState().openFile('new.pcap')
    const s = useApp.getState()
    expect(s.searchQuery).toBe('')
    expect(s.searchHits).toEqual([])
    expect(s.searchHitIndex).toBe(-1)
  })
})
