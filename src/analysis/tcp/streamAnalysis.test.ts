import { describe, expect, it } from 'vitest'
import type { Packet } from '../../model/types'
import { analyzeStream } from './streamAnalysis'
import { detectTcpEvents } from './events'

/** 构造一个 TCP 报文;只填分析引擎关心的字段 */
function pkt(o: Partial<Packet> & { number: number; time: number }): Packet {
  return {
    transport: 'tcp',
    proto: 'tcp',
    len: (o.tcpLen ?? 0) + 54,
    direction: 'other',
    srcIp: '10.0.0.1',
    dstIp: '10.0.0.2',
    srcPort: 1234,
    dstPort: 80,
    tcpStream: 0,
    ...o,
  } as Packet
}

/** 客户端 → 服务端(数据方向) */
const c2s = (o: Partial<Packet> & { number: number; time: number }) =>
  pkt({ srcIp: '10.0.0.1', dstIp: '10.0.0.2', srcPort: 1234, dstPort: 80, ...o })
/** 服务端 → 客户端(ACK 方向) */
const s2c = (o: Partial<Packet> & { number: number; time: number }) =>
  pkt({ srcIp: '10.0.0.2', dstIp: '10.0.0.1', srcPort: 80, dstPort: 1234, ...o })

const SYN = '0x0002'
const SYNACK = '0x0012'
const ACK = '0x0010'
const PSHACK = '0x0018'
const FINACK = '0x0011'

/** 完整握手(seq 从 0 开始,ACK 后数据从 1 开始) */
const handshake = () => [
  c2s({ number: 1, time: 0, tcpFlags: SYN, tcpSeq: 0, tcpLen: 0 }),
  s2c({ number: 2, time: 0.01, tcpFlags: SYNACK, tcpSeq: 0, tcpAck: 1, tcpLen: 0 }),
  c2s({ number: 3, time: 0.02, tcpFlags: ACK, tcpSeq: 1, tcpAck: 1, tcpLen: 0 }),
]

describe('analyzeStream — 序列空间与 Gap 生命周期', () => {
  it('连续传输无 Gap', () => {
    const packets = [
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100 }),
      s2c({ number: 5, time: 0.04, tcpFlags: ACK, tcpSeq: 1, tcpAck: 101, tcpLen: 0 }),
      c2s({ number: 6, time: 0.05, tcpFlags: PSHACK, tcpSeq: 101, tcpAck: 1, tcpLen: 100 }),
      s2c({ number: 7, time: 0.06, tcpFlags: ACK, tcpSeq: 1, tcpAck: 201, tcpLen: 0 }),
    ]
    const a = analyzeStream(packets)
    expect(a.gaps).toEqual([])
    expect(a.midStream).toBe(false)
  })

  it('缺一段数据形成 Gap,记录起止与字节数', () => {
    const packets = [
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100 }), // 1..101
      c2s({ number: 5, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100 }), // 201..301,缺 101..201
    ]
    const a = analyzeStream(packets)
    expect(a.gaps).toHaveLength(1)
    expect(a.gaps[0].start).toBe(101)
    expect(a.gaps[0].end).toBe(201)
    expect(a.gaps[0].byteCount).toBe(100)
    expect(a.gaps[0].firstObservedPacket).toBe(5) // 由 #5 的到达才暴露出空洞
  })

  it('Gap 被后续重传填补:记录填补报文、时刻与存续时长', () => {
    const packets = [
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100 }),
      c2s({ number: 5, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100 }),
      c2s({ number: 6, time: 0.25, tcpFlags: PSHACK, tcpSeq: 101, tcpAck: 1, tcpLen: 100 }), // 填补
    ]
    const a = analyzeStream(packets)
    expect(a.gaps).toHaveLength(1)
    expect(a.gaps[0].filled).toBe(true)
    expect(a.gaps[0].filledByPacket).toBe(6)
    expect(a.gaps[0].durationSeconds).toBeCloseTo(0.2, 5)
  })

  it('未被填补的 Gap 标记为 unfilled 且无填补报文', () => {
    const packets = [
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100 }),
      c2s({ number: 5, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100 }),
    ]
    const a = analyzeStream(packets)
    expect(a.gaps[0].filled).toBe(false)
    expect(a.gaps[0].filledByPacket).toBeUndefined()
  })

  it('SYN 消耗一个序列号,不产生 Gap', () => {
    // SYN seq=0,数据从 1 开始;若把 SYN 当零长度会认为 0..1 缺失
    const a = analyzeStream([
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100 }),
    ])
    expect(a.gaps).toEqual([])
    // 直接断言序列空间占用,而不是只看"没有 Gap"——后者在去掉 SYN 消耗时同样成立(假通过)
    const syn = a.segments.find((s) => s.packetNumber === 1)
    expect(syn?.seqLen).toBe(1)
    expect(syn?.payloadLen).toBe(0)
  })

  it('SYN 占用的序列号使随后的数据紧邻而非重叠', () => {
    // 若 SYN 不消耗序列号,则 SYN(0) 与数据(1..101)之间会留下 0..1 的空档,
    // 且已见区间会从 1 而非 0 开始 —— 用已见字节总数把这一点钉住
    const a = analyzeStream([
      c2s({ number: 1, time: 0, tcpFlags: SYN, tcpSeq: 0, tcpLen: 0 }),
      c2s({ number: 2, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100 }),
    ])
    expect(a.gaps).toEqual([])
    expect(a.seenBytes.c2s).toBe(101) // SYN 的 1 字节 + 载荷 100
  })

  it('FIN 消耗一个序列号,不产生 Gap', () => {
    const a = analyzeStream([
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100 }),
      c2s({ number: 5, time: 0.04, tcpFlags: FINACK, tcpSeq: 101, tcpAck: 1, tcpLen: 0 }),
      c2s({ number: 6, time: 0.05, tcpFlags: ACK, tcpSeq: 102, tcpAck: 1, tcpLen: 0 }),
    ])
    expect(a.gaps).toEqual([])
    const fin = a.segments.find((s) => s.packetNumber === 5)
    expect(fin?.seqLen).toBe(1) // FIN 自身占一个序列号
    // 末尾纯 ACK(seq=102)紧接 FIN 之后:若 FIN 不占序列号,102 会越过空洞
    expect(a.segments.find((s) => s.packetNumber === 6)?.classification).toBe('no-payload')
  })

  it('纯 ACK(零长度)不占序列空间', () => {
    const a = analyzeStream([
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: ACK, tcpSeq: 1, tcpAck: 1, tcpLen: 0 }),
      c2s({ number: 5, time: 0.04, tcpFlags: ACK, tcpSeq: 1, tcpAck: 1, tcpLen: 0 }),
      c2s({ number: 6, time: 0.05, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100 }),
    ])
    expect(a.gaps).toEqual([])
  })

  it('完全重复的段被识别为 pure-duplicate,不算新数据', () => {
    const a = analyzeStream([
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100 }),
      c2s({ number: 5, time: 0.30, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100 }), // 原样重发
    ])
    const seg = a.segments.find((s) => s.packetNumber === 5)
    expect(seg?.classification).toBe('pure-duplicate')
    expect(a.gaps).toEqual([])
  })

  it('部分重叠重传被识别为 overlapping-retransmit', () => {
    const a = analyzeStream([
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100 }), // 1..101
      c2s({ number: 5, time: 0.30, tcpFlags: PSHACK, tcpSeq: 51, tcpAck: 1, tcpLen: 100 }), // 51..151,前半重叠
    ])
    const seg = a.segments.find((s) => s.packetNumber === 5)
    expect(seg?.classification).toBe('overlapping-retransmit')
  })

  it('乱序补齐被识别为 out-of-order-fill', () => {
    const a = analyzeStream([
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100 }), // A
      c2s({ number: 5, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100 }), // C
      c2s({ number: 6, time: 0.052, tcpFlags: PSHACK, tcpSeq: 101, tcpAck: 1, tcpLen: 100 }), // B 补齐
    ])
    const seg = a.segments.find((s) => s.packetNumber === 6)
    expect(seg?.classification).toBe('out-of-order-fill')
    expect(a.gaps[0].filled).toBe(true)
  })

  it('SACK 块记入接收端已收到的非连续数据', () => {
    const a = analyzeStream([
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100 }),
      c2s({ number: 5, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100 }),
      s2c({
        number: 6,
        time: 0.06,
        tcpFlags: ACK,
        tcpSeq: 1,
        tcpAck: 101,
        tcpLen: 0,
        tcpSackBlocks: [[201, 301]],
      }),
    ])
    expect(a.gaps).toHaveLength(1)
    expect(a.gaps[0].sackCovered).toBe(true) // 后续数据已由 SACK 报告到达
  })

  it('多块 SACK 揭示多个 Gap', () => {
    const a = analyzeStream([
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100 }),
      c2s({ number: 5, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100 }),
      c2s({ number: 6, time: 0.07, tcpFlags: PSHACK, tcpSeq: 401, tcpAck: 1, tcpLen: 100 }),
    ])
    expect(a.gaps).toHaveLength(2)
    expect(a.gaps.map((g) => [g.start, g.end])).toEqual([
      [101, 201],
      [301, 401],
    ])
  })

  it('中途抓包:首段不是 SYN 时不得从 0 到首序列号造出幻影 Gap', () => {
    const a = analyzeStream([
      c2s({ number: 1, time: 0, tcpFlags: PSHACK, tcpSeq: 500001, tcpAck: 1, tcpLen: 100, tcpCompleteness: 12 }),
      s2c({ number: 2, time: 0.01, tcpFlags: ACK, tcpSeq: 1, tcpAck: 500101, tcpLen: 0, tcpCompleteness: 12 }),
    ])
    expect(a.midStream).toBe(true)
    expect(a.gaps).toEqual([]) // 不能因为"没见过 0..500001"就报 Gap
  })

  it('中途抓包仍能检出真实 Gap', () => {
    const a = analyzeStream([
      c2s({ number: 1, time: 0, tcpFlags: PSHACK, tcpSeq: 500001, tcpAck: 1, tcpLen: 100, tcpCompleteness: 12 }),
      c2s({ number: 2, time: 0.02, tcpFlags: PSHACK, tcpSeq: 500201, tcpAck: 1, tcpLen: 100, tcpCompleteness: 12 }),
    ])
    expect(a.midStream).toBe(true)
    expect(a.gaps).toHaveLength(1)
    expect(a.gaps[0].start).toBe(500101)
  })

  it('缺 tcp.len 时按不可用处理,不猜测长度', () => {
    const a = analyzeStream([
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: undefined, len: 154 }),
      c2s({ number: 5, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: undefined, len: 154 }),
    ])
    // 不能用 frame.len 冒充载荷长度去推进序列号
    expect(a.gaps).toEqual([])
    expect(a.lengthUnavailable).toBe(true)
    // 关键保证:缺长度的段不占序列空间(否则会按帧长推进、造出不存在的 Gap)
    expect(a.segments.find((s) => s.packetNumber === 4)?.seqLen).toBe(0)
    expect(a.seenBytes.c2s).toBe(1) // 只有 SYN 占的 1 字节
  })

  it('跨 2^32 回绕的连续传输不产生 Gap', () => {
    const W = 4294967200
    const a = analyzeStream([
      c2s({ number: 1, time: 0, tcpFlags: SYN, tcpSeq: W - 1, tcpLen: 0 }),
      s2c({ number: 2, time: 0.01, tcpFlags: SYNACK, tcpSeq: 0, tcpAck: W, tcpLen: 0 }),
      c2s({ number: 3, time: 0.02, tcpFlags: ACK, tcpSeq: W, tcpAck: 1, tcpLen: 0 }),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: W, tcpAck: 1, tcpLen: 60 }),
      // W+60 = 4294967260,再 60 字节跨过 2^32 到 24
      c2s({ number: 5, time: 0.04, tcpFlags: PSHACK, tcpSeq: 4294967260, tcpAck: 1, tcpLen: 60 }),
    ])
    expect(a.gaps).toEqual([])
  })

  it('跨回绕时的真实 Gap 仍被检出且边界正确', () => {
    const W = 4294967200
    const a = analyzeStream([
      c2s({ number: 1, time: 0, tcpFlags: SYN, tcpSeq: W - 1, tcpLen: 0 }),
      s2c({ number: 2, time: 0.01, tcpFlags: SYNACK, tcpSeq: 0, tcpAck: W, tcpLen: 0 }),
      c2s({ number: 3, time: 0.02, tcpFlags: ACK, tcpSeq: W, tcpAck: 1, tcpLen: 0 }),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: W, tcpAck: 1, tcpLen: 60 }), // W..W+60
      c2s({ number: 5, time: 0.04, tcpFlags: PSHACK, tcpSeq: 100, tcpAck: 1, tcpLen: 60 }), // 缺 W+60..100
    ])
    expect(a.gaps).toHaveLength(1)
    expect(a.gaps[0].start).toBe(4294967260)
    expect(a.gaps[0].end).toBe(100)
  })

  it('两个方向的序列空间彼此独立', () => {
    const a = analyzeStream([
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100 }),
      // 服务端方向也有数据,且自己有个洞
      s2c({ number: 5, time: 0.04, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 101, tcpLen: 50 }),
      s2c({ number: 6, time: 0.05, tcpFlags: PSHACK, tcpSeq: 151, tcpAck: 101, tcpLen: 50 }),
    ])
    // 客户端方向无洞,服务端方向一个洞
    expect(a.gaps.filter((g) => g.direction === 'c2s')).toEqual([])
    expect(a.gaps.filter((g) => g.direction === 's2c')).toHaveLength(1)
  })

  it('确定性:同一输入两次分析结果完全一致', () => {
    const build = () => [
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100 }),
      c2s({ number: 5, time: 0.05, tcpFlags: PSHACK, tcpSeq: 201, tcpAck: 1, tcpLen: 100 }),
    ]
    expect(JSON.stringify(analyzeStream(build()))).toBe(JSON.stringify(analyzeStream(build())))
  })
})

describe('analyzeStream — 回绕排序、不可信输入与部分填补去重(M2 加固)', () => {
  // 每步 256MB,24 跳累计约 6.17GB > 2^32:必然跨回绕,且相邻步距远小于 2^31(展开坐标精确)
  const STEP = 0x1000_0000

  const wrappedStream = (): Packet[] => {
    const ps: Packet[] = []
    let seq = 0
    for (let i = 0; i < 24; i++) {
      ps.push(
        c2s({ number: i + 1, time: (i + 1) * 0.001, tcpFlags: PSHACK, tcpSeq: seq >>> 0, tcpLen: 1000, tcpCompleteness: 15 }),
      )
      seq += STEP
    }
    return ps
  }

  it('跨回绕长流:Gap 按传输顺序(绝对坐标)排列,输入数组反序后顺序不变', () => {
    const base = wrappedStream()
    const f1 = analyzeStream(base)
    const f2 = analyzeStream([...base].reverse())

    // 24 段之间恰 23 个空洞,每洞 STEP-1000 字节;两份输入产出完全相同的记录集合
    expect(f1.gaps).toHaveLength(23)
    expect(f2.gaps.map((g) => [g.start, g.end])).toEqual(f1.gaps.map((g) => [g.start, g.end]))

    // 语义正确序 = 发送顺序:第 i 个空洞起于第 i 段末尾、止于第 i+1 段开头(均对 2^32 取模)。
    // 注意第 16 洞的 32 位起点回到 1000(已回绕)——这正是按原始序号排序必然出错的原因
    const expected = Array.from({ length: 23 }, (_, i) => [
      ((i * STEP + 1000) % 4294967296) >>> 0,
      (((i + 1) * STEP) % 4294967296) >>> 0,
    ])
    expect(f1.gaps.map((g) => [g.start, g.end])).toEqual(expected)

    // startAbs 必须严格递增(跨回绕处原始序号从 0xF00003E8 跳回 1000,seqDiff 序在此反转)
    const abss = f1.gaps.map((g) => g.startAbs)
    expect(abss[0]).toBe(1000)
    expect(abss[22]).toBe(22 * STEP + 1000)
    for (let i = 1; i < abss.length; i++) expect(abss[i]!).toBeGreaterThan(abss[i - 1]!)

    // 缺失总量如实:23 × (STEP - 1000)
    expect(f1.gaps.reduce((n, g) => n + g.byteCount, 0)).toBe(23 * (STEP - 1000))
  })

  it('外来 ISN(相距 ≥2^31)被拒收:不产生巨型幻影 Gap,且 unorderableInput 如实上报', () => {
    const packets = [
      ...handshake(),
      c2s({ number: 4, time: 0.03, tcpFlags: PSHACK, tcpSeq: 1, tcpAck: 1, tcpLen: 100 }),
      c2s({ number: 5, time: 0.04, tcpFlags: PSHACK, tcpSeq: 2_500_000_000, tcpAck: 1, tcpLen: 100 }),
    ]
    const f = analyzeStream(packets)
    // 出现无法定序的输入必须浮出水面,由上层降级并附限制说明,而不是默默吞掉
    expect(f.unorderableInput).toBe(true)
    // 任何位置都不得出现十亿字节级幻影空洞;本例中该段整体被拒收,连普通空洞也没有
    expect(f.gaps.every((g) => g.byteCount <= 0x4000_0000)).toBe(true)
    expect(f.gaps).toHaveLength(0)
  })

  it('部分填补去重回归:宽空洞被缩小而非残留重复记录,缺失量如实为 700B', () => {
    const packets = [
      c2s({ number: 1, time: 0.0, tcpFlags: PSHACK, tcpSeq: 1000, tcpAck: 1, tcpLen: 100 }),
      c2s({ number: 2, time: 0.01, tcpFlags: PSHACK, tcpSeq: 1500, tcpAck: 1, tcpLen: 100 }), // 暴露 [1100,1500)
      c2s({ number: 3, time: 0.05, tcpFlags: PSHACK, tcpSeq: 1200, tcpAck: 1, tcpLen: 100 }), // 填中段 → [1100,1200)+[1300,1500)
      c2s({ number: 4, time: 0.06, tcpFlags: PSHACK, tcpSeq: 2000, tcpAck: 1, tcpLen: 100 }), // 再暴露 [1600,2000)
    ]
    const f = analyzeStream(packets)
    // 恰 3 条记录,同一段字节绝不重复计入缺失
    expect(f.gaps.map((g) => [g.start, g.end])).toEqual([
      [1100, 1200],
      [1300, 1500],
      [1600, 2000],
    ])
    expect(f.gaps.reduce((n, g) => n + g.byteCount, 0)).toBe(700)
    // 缩小后的记录继承原宽空洞的首次观察信息([1100,1500) 由 #2 首次暴露;缩小 ≠ 重新发现)
    expect(f.gaps.map((g) => g.firstObservedPacket)).toEqual([2, 2, 4])
    // 事件引擎消费同一份事实:3 条记录 → 恰 3 个事件,不再重复报告
    expect(detectTcpEvents(f, packets)).toHaveLength(3)
  })
})
