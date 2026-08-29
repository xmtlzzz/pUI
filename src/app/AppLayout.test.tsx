// @vitest-environment jsdom
import { describe, expect, it, vi, afterEach } from 'vitest'
import { render, fireEvent, waitFor, cleanup, act } from '@testing-library/react'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { AppLayout } from './AppLayout'
import { useApp, selectSelected } from '../state/appStore'
import { parsePackets } from '../parse/parsePackets'
import { aggregateConversations } from '../aggregate/aggregateConversations'
import { collectFilterOptions } from '../filter/filterConversations'

afterEach(cleanup)

function loadHttpFixture() {
  const raw = readFileSync(resolve(process.cwd(), 'public/fixtures/examples/parsed/http.json'), 'utf-8')
  const packets = parsePackets(raw)
  const conversations = aggregateConversations(packets)
  const conv = conversations[0]
  return { packets, conversations, conv }
}

describe('AppLayout smoke (real http fixture)', () => {
  it('renders conversation list, sequence diagram, and packet detail from real data', async () => {
    // 阻止浏览器回退路径的真实 fetch(jsdom 无服务器)
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('no server in jsdom'))))

    const { packets, conversations, conv } = loadHttpFixture()
    useApp.setState({
      packets,
      conversations,
      filtered: conversations,
      options: collectFilterOptions(packets),
      meta: { fileName: 'http.pcapng', packetCount: packets.length, interfaces: 1, timeStart: 0, timeEnd: 0.26, fileSize: 936 },
      filter: { protocol: [], srcIp: [], dstIp: [], srcPort: [], dstPort: [], negate: false, issueOnly: false },
      selectedId: conv.id,
      diagramStyle: 'A',
    })

    const { container, getByText } = render(<AppLayout />)

    // 会话列表显示 HTTP 会话(协议 badge)
    await waitFor(() => expect(container.querySelector('.cl-row .badge')?.textContent).toBe('http'))
    expect(container.querySelectorAll('.cl-row')).toHaveLength(1)

    // 时序图渲染全部报文
    const msgs = container.querySelectorAll('.msg')
    expect(msgs).toHaveLength(packets.length)

    // 点击第一个报文 → 详情条出现帧号
    fireEvent.click(msgs[0])
    await waitFor(() => expect(getByText(/报文详情 · #1/)).toBeTruthy())
    expect(selectSelected(useApp.getState())?.packets.length).toBe(packets.length)

    vi.unstubAllGlobals()
  })

  it('打开文件后未选中会话 → 点击会话列表选中 → 时序图渲染且不白屏(真实路径回归)', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('no server in jsdom'))))

    const { packets, conversations } = loadHttpFixture()
    useApp.setState({
      packets,
      conversations,
      filtered: conversations,
      options: collectFilterOptions(packets),
      meta: { fileName: 'http.pcapng', packetCount: packets.length, interfaces: 1, timeStart: 0, timeEnd: 0.26, fileSize: 936 },
      filter: { protocol: [], srcIp: [], dstIp: [], srcPort: [], dstPort: [], negate: false, issueOnly: false },
      selectedId: null, // 未选中:时序图空态
      diagramStyle: 'A',
      searchQuery: '', highlight: [],
    })

    const { container } = render(<AppLayout />)
    expect(container.querySelector('.empty')?.textContent).toContain('选择一个会话')

    // 模拟点击会话列表行 → 选中 → 时序图必须在 hooks 数量一致的前提下正常渲染
    useApp.setState({ selectedId: conversations[0].id })
    await waitFor(() => expect(container.querySelectorAll('.msg').length).toBeGreaterThan(0))
    expect(container.querySelector('.boundary-err')).toBeNull()

    vi.unstubAllGlobals()
  })
})

describe('M4 故障分析整页板块(用户要求:整页切换,非右侧局部替换)', () => {
  it('进入故障分析时筛选/列表/时序/详情全部让位;返回后恢复', () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('no server in jsdom'))))
    const { packets, conversations, conv } = loadHttpFixture()
    useApp.setState({
      packets,
      conversations,
      filtered: conversations,
      options: collectFilterOptions(packets),
      selectedId: conv.id,
      compareFor: null,
      compareEventIndex: 0,
    })

    const { container } = render(<AppLayout />)
    // 常规视图:四面板齐全
    expect(container.querySelector('.pane.filter')).toBeTruthy()
    expect(container.querySelector('.pane.list')).toBeTruthy()

    // 进入故障分析 → 整页板块(筛选/列表让位);http 会话无 TCP 事件 → 空态
    act(() => {
      useApp.getState().openCompare(conv.id)
    })
    expect(container.querySelector('.pane.filter')).toBeNull()
    expect(container.querySelector('.pane.list')).toBeNull()
    expect(container.querySelector('[data-testid="fault-compare-empty"]')).toBeTruthy()
    // 对照页顶栏不挂主视图专属的「导出 PNG / 导出叙述」按钮——
    // 它们绑定主视图时序图 svgRef(对照页已卸载),点了会静默空导出;
    // 对照页的导出走 FaultCompare 的「导出报告 / 导出证据 JSON」
    expect(container.querySelector('.toolbar')!.textContent).not.toContain('导出叙述')
    expect(container.querySelector('.toolbar')!.textContent).not.toContain('导出 PNG')

    // 返回 → 面板恢复,主视图导出按钮回归
    fireEvent.click(container.querySelector('[data-testid="fc-back"]')!)
    expect(container.querySelector('.pane.filter')).toBeTruthy()
    expect(container.querySelector('.toolbar')!.textContent).toContain('导出叙述')
    expect(useApp.getState().compareFor).toBeNull()
    vi.unstubAllGlobals()
  })

  it('多事件会话:左栏切换器列出全部检出事件,点击切换后 headline/关键报文随之更换', () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('no server in jsdom'))))
    // 构造两个可解释事件的链:
    //  ① 缺口事件(seq=101–201 未被回补,未恢复优先排序置顶)
    //  ② 缺口之外的纯重复重发(伪重传/疑似 ACK 丢失)
    const pkt = (o: Record<string, unknown>) => ({ transport: 'tcp', proto: 'tcp', len: 54 + Number(o.tcpLen ?? 0), direction: 'other', tcpStream: 0, ...o }) as never
    const c2s = (o: Record<string, unknown>) => pkt({ srcIp: '10.0.0.1', dstIp: '10.0.0.2', srcPort: 1234, dstPort: 80, ...o })
    const s2c = (o: Record<string, unknown>) => pkt({ srcIp: '10.0.0.2', dstIp: '10.0.0.1', srcPort: 80, dstPort: 1234, ...o })
    const SYN = '0x0002'
    const SYNACK = '0x0012'
    const PSHACK = '0x0018'
    const packets = [
      c2s({ number: 1, time: 0, tcpFlags: SYN, tcpSeq: 0, tcpLen: 0 }),
      s2c({ number: 2, time: 0.01, tcpFlags: SYNACK, tcpSeq: 0, tcpAck: 1, tcpLen: 0 }),
      c2s({ number: 3, time: 0.02, tcpFlags: '0x0010', tcpSeq: 1, tcpAck: 1, tcpLen: 0 }),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100 }),
      s2c({ number: 5, time: 0.04, tcpFlags: '0x0010', tcpSeq: 1, tcpAck: 101, tcpLen: 0 }),
      c2s({ number: 6, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100 }), // 越过缺口到达
      s2c({ number: 7, time: 0.06, tcpFlags: '0x0010', tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpSackBlocks: [[201, 301]], tcpDupAckNum: 1 }),
      // 重发已完整见过的 [201,301):序列空间无对应缺口 → 独立的伪重传事件
      c2s({ number: 8, time: 0.30, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100, tcpAnalysis: ['retransmission'] }),
    ]
    const conversations = aggregateConversations(packets)
    const conv = conversations[0]
    useApp.setState({
      packets,
      conversations,
      filtered: conversations,
      options: collectFilterOptions(packets),
      selectedId: conv.id,
      compareFor: null,
      compareEventIndex: 0,
    })

    const { container } = render(<AppLayout />)
    act(() => {
      useApp.getState().openCompare(conv.id)
    })

    // 切换器出现且含两条事件;默认选中引擎序第一条(未恢复的缺口事件)
    const list = container.querySelector('[data-testid="fc-event-list"]')!
    expect(list).toBeTruthy()
    const tabs = [...list.querySelectorAll('.fc-evbtn')]
    expect(tabs).toHaveLength(2)
    expect(tabs[0].className).toContain('active')
    expect(container.querySelector('.fc-headline')!.textContent).toMatch(/疑似丢包 \/ 延迟到达/)
    expect(container.querySelector('.fc-headline')!.textContent).toContain('101–201')
    const headline0 = container.querySelector('.fc-headline')!.textContent

    // 点击第二条(伪重传)→ headline 更换,视图模型整体重建
    act(() => {
      useApp.getState().setCompareEventIndex(1)
    })
    expect(container.querySelector('.fc-headline')!.textContent).toMatch(/疑似 ACK 丢失 \/ 冗余重传/)
    expect(container.querySelectorAll('.fc-evbtn')[1].className).toContain('active')

    // 缓存路径:切回事件 0 时走 vmCache,内容与首次构建一致(确定性),不重跑全量分析
    act(() => {
      useApp.getState().setCompareEventIndex(0)
    })
    expect(container.querySelector('.fc-headline')!.textContent).toBe(headline0)
    expect(container.querySelectorAll('.fc-evbtn')[0].className).toContain('active')
    vi.unstubAllGlobals()
  })

  it('跳包→详情→返回恢复:事件与阶段按分镜粒度还原,报文详情提供「查看事件上下文」入口', () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('no server in jsdom'))))
    const c2s = (o: Record<string, unknown>) => ({ transport: 'tcp', proto: 'tcp', len: 54 + Number(o.tcpLen ?? 0), direction: 'other', tcpStream: 0, srcIp: '10.0.0.1', dstIp: '10.0.0.2', srcPort: 1234, dstPort: 80, ...o }) as never
    const s2c = (o: Record<string, unknown>) => ({ transport: 'tcp', proto: 'tcp', len: 54 + Number(o.tcpLen ?? 0), direction: 'other', tcpStream: 0, srcIp: '10.0.0.2', dstIp: '10.0.0.1', srcPort: 80, dstPort: 1234, ...o }) as never
    const PSHACK = '0x0018'
    const packets = [
      c2s({ number: 1, time: 0, tcpFlags: '0x0002', tcpSeq: 0, tcpLen: 0 }),
      s2c({ number: 2, time: 0.01, tcpFlags: '0x0012', tcpSeq: 0, tcpAck: 1, tcpLen: 0 }),
      c2s({ number: 3, time: 0.02, tcpFlags: '0x0010', tcpSeq: 1, tcpAck: 1, tcpLen: 0 }),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100 }),
      s2c({ number: 5, time: 0.04, tcpFlags: '0x0010', tcpSeq: 1, tcpAck: 101, tcpLen: 0 }),
      c2s({ number: 6, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100 }),
      s2c({ number: 7, time: 0.06, tcpFlags: '0x0010', tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpSackBlocks: [[201, 301]], tcpDupAckNum: 1 }),
      c2s({ number: 8, time: 0.07, tcpFlags: PSHACK, tcpSeq: 301, tcpAck: 1, tcpLen: 100 }),
      s2c({ number: 9, time: 0.08, tcpFlags: '0x0010', tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpSackBlocks: [[201, 401]], tcpDupAckNum: 2 }),
    ]
    const conversations = aggregateConversations(packets)
    const conv = conversations[0]
    useApp.setState({
      packets,
      conversations,
      filtered: conversations,
      options: collectFilterOptions(packets),
      selectedId: conv.id,
      compareFor: null,
      compareEventIndex: 0,
      compareResume: null,
    })

    const { container } = render(<AppLayout />)

    // 报文详情「查看事件上下文」入口:选中证据链报文 #7 后点击 → 直达对照页
    act(() => {
      useApp.getState().selectPacket(7)
    })
    const entryBtn = container.querySelector('[data-testid="pd-view-events"]')!
    expect(entryBtn).toBeTruthy()
    act(() => {
      fireEvent.click(entryBtn)
    })
    expect(container.querySelector('[data-testid="fault-compare"]')).toBeTruthy()
    expect(container.querySelector('.fc-headline')!.textContent).toMatch(/疑似丢包 \/ 延迟到达/)

    // 对照页内选中「重复确认」阶段(下标 2)再跳包 #9 → 回主视图,resume 已记录
    // (两个独立 act:确保第一次点击的状态先落盘,第二次点击携带的是刷新后的上下文)
    act(() => {
      const dupCard = [...container.querySelectorAll('.fc-stage-card')].find((b) =>
        b.textContent?.includes('重复确认'),
      ) as HTMLButtonElement
      fireEvent.click(dupCard)
    })
    act(() => {
      const chip = [...container.querySelectorAll('.fc-keypkt')].find((b) => b.textContent?.includes('#9')) as HTMLButtonElement
      fireEvent.click(chip)
    })
    expect(useApp.getState().compareFor).toBeNull()
    const resumeState = useApp.getState().compareResume!
    expect(resumeState.conversationId).toBe(conv.id)
    expect(resumeState.stageIndex).toBe(2)

    // 主视图出现「返回故障分析(事件 1 · 阶段 3)」按钮;点击后事件、阶段、播放位置全部还原
    const resumeBtn = container.querySelector('[data-testid="fault-analyze-resume"]') as HTMLButtonElement
    expect(resumeBtn.textContent).toContain('事件 1 · 阶段 3')
    act(() => {
      fireEvent.click(resumeBtn)
    })
    expect(container.querySelector('[data-testid="fault-compare"]')).toBeTruthy()
    expect((container.querySelector('[data-testid="fc-stage-panel"]') as HTMLElement).textContent).toContain('阶段 3/')
    // resume 消费即清除;播放游标停在所恢复阶段起点(t0>0)
    expect(useApp.getState().compareResume).toBeNull()
    const cursor = container.querySelector('.fc-timeband-cursor') as HTMLElement
    expect(Number.parseFloat(cursor.style.left)).toBeGreaterThan(0)
    vi.unstubAllGlobals()
  })

  // 对抗审查发现的下标覆盖回归:openCompare 会把 compareEventIndex 重置为 0,
  // 任何"先设下标再 openCompare"的路径都会把命中结果覆盖成事件 1。
  const mk = (o: Record<string, unknown>) => ({ transport: 'tcp', proto: 'tcp', len: 54 + Number(o.tcpLen ?? 0), direction: 'other', tcpStream: 0, ...o }) as never
  const c2s = (o: Record<string, unknown>) => mk({ srcIp: '10.0.0.1', dstIp: '10.0.0.2', srcPort: 1234, dstPort: 80, ...o })
  const s2c = (o: Record<string, unknown>) => mk({ srcIp: '10.0.0.2', dstIp: '10.0.0.1', srcPort: 80, dstPort: 1234, ...o })
  const SYN = '0x0002'
  const SYNACK = '0x0012'
  const PSHACK = '0x0018'
  const twoEventPackets = () => [
    c2s({ number: 1, time: 0, tcpFlags: SYN, tcpSeq: 0, tcpLen: 0 }),
    s2c({ number: 2, time: 0.01, tcpFlags: SYNACK, tcpSeq: 0, tcpAck: 1, tcpLen: 0 }),
    c2s({ number: 3, time: 0.02, tcpFlags: '0x0010', tcpSeq: 1, tcpAck: 1, tcpLen: 0 }),
    c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100 }),
    s2c({ number: 5, time: 0.04, tcpFlags: '0x0010', tcpSeq: 1, tcpAck: 101, tcpLen: 0 }),
    c2s({ number: 6, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100 }),
    s2c({ number: 7, time: 0.06, tcpFlags: '0x0010', tcpSeq: 1, tcpAck: 101, tcpLen: 0, tcpSackBlocks: [[201, 301]], tcpDupAckNum: 1 }),
    c2s({ number: 8, time: 0.30, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100, tcpAnalysis: ['retransmission'] }),
  ]
  const setupTwoEvents = () => {
    const packets = twoEventPackets()
    const conversations = aggregateConversations(packets)
    const conv = conversations[0]
    useApp.setState({
      packets,
      conversations,
      filtered: conversations,
      options: collectFilterOptions(packets),
      selectedId: conv.id,
      compareFor: null,
      compareEventIndex: 0,
      compareResume: null,
    })
    return conv
  }

  it('「查看事件上下文」命中第 2 个事件时打开对应事件,而非被 openCompare 重置回事件 1', () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('no server in jsdom'))))
    setupTwoEvents()
    const { container } = render(<AppLayout />)

    act(() => {
      useApp.getState().selectPacket(8) // 伪重传事件的证据报文
    })
    act(() => {
      fireEvent.click(container.querySelector('[data-testid="pd-view-events"]')!)
    })
    expect(container.querySelector('[data-testid="fault-compare"]')).toBeTruthy()
    // 事件下标 1(第二条)处于激活态;旧行为会落在事件 0
    expect(useApp.getState().compareEventIndex).toBe(1)
    expect(container.querySelectorAll('.fc-evbtn')[1].className).toContain('active')
    expect(container.querySelector('.fc-headline')!.textContent).toMatch(/疑似 ACK 丢失 \/ 冗余重传/)
    vi.unstubAllGlobals()
  })

  it('「返回故障分析」恢复事件 2:openCompare 的下标重置不得覆盖恢复下标', () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('no server in jsdom'))))
    const conv = setupTwoEvents()
    useApp.setState({ compareResume: { conversationId: conv.id, eventIndex: 1, stageIndex: 0 } })
    const { container } = render(<AppLayout />)

    const resumeBtn = container.querySelector('[data-testid="fault-analyze-resume"]') as HTMLButtonElement
    expect(resumeBtn.textContent).toContain('事件 2')
    act(() => {
      fireEvent.click(resumeBtn)
    })
    expect(container.querySelector('[data-testid="fault-compare"]')).toBeTruthy()
    expect(useApp.getState().compareEventIndex).toBe(1)
    expect(container.querySelectorAll('.fc-evbtn')[1].className).toContain('active')
    expect(useApp.getState().compareResume).toBeNull()
    vi.unstubAllGlobals()
  })
})

describe('解析遮罩(emotion-ball 官方球,emotion 32 处理中忙碌)', () => {
  it('loading=true 时渲染解析遮罩,帧数进度实时可见;loading=false 移除', () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('no server in jsdom'))))
    act(() => {
      useApp.setState({ loading: true, loadingFrames: 1234, error: null })
    })
    const { container } = render(<AppLayout />)
    const overlay = container.querySelector('[data-testid="parse-overlay"]')!
    expect(overlay).toBeTruthy()
    expect(overlay.textContent).toContain('解析中')
    expect(overlay.textContent).toContain('1,234')
    // 引擎缺席时降级占位仍在(不白屏)
    expect(overlay.querySelector('.eb-loader-fallback') || overlay.querySelector('.eb-loader')).toBeTruthy()

    act(() => {
      useApp.setState({ loading: false, loadingFrames: 0 })
    })
    expect(container.querySelector('[data-testid="parse-overlay"]')).toBeNull()
    vi.unstubAllGlobals()
  })
})
