import { describe, expect, it } from 'vitest'
import type { Packet } from '../../model/types'
import { analyzeStream } from './streamAnalysis'

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
