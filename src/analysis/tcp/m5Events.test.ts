import { describe, expect, it } from 'vitest'
import type { Packet } from '../../model/types'
import { detectZeroWindowEvents, detectFullWindowEvents, detectRstEvents, detectSynRetransmissionEvents } from './m5Events'

/**
 * M5 事件扩展(每项可独立关闭):Zero/Full Window、RST、SYN 重传。
 * 与 M3 引擎解耦(独立文件/独立函数),检测器只消费 Packet 字段,
 * 不依赖 M2 序列空间 —— 输入无法排序时同样可用。
 */

function pkt(o: Partial<Packet> & { number: number; time: number }): Packet {
  return { transport: 'tcp', proto: 'tcp', len: (o.tcpLen ?? 0) + 54, direction: 'other', tcpStream: 0, ...o } as Packet
}
const c2s = (o: Partial<Packet> & { number: number; time: number }) =>
  pkt({ srcIp: '10.0.0.1', dstIp: '10.0.0.2', srcPort: 1234, dstPort: 80, ...o })
const s2c = (o: Partial<Packet> & { number: number; time: number }) =>
  pkt({ srcIp: '10.0.0.2', dstIp: '10.0.0.1', srcPort: 80, dstPort: 1234, ...o })

const PSHACK = '0x0018'
const ACK = '0x0010'
const RST = '0x0004'
const RSTACK = '0x0014'

describe('detectZeroWindowEvents — 零窗口(接收方缓冲区满,单观察点直接可见)', () => {
  // 对向视角:接收方 10.0.0.2 通告 window=0
  const zwChain = (): Packet[] => [
    c2s({ number: 1, time: 1.0, tcpFlags: PSHACK, tcpSeq: 1000, tcpAck: 5000, tcpLen: 100 }),
    // window 缺失的旧抓包:不得误报(undefined ≠ 0)
    s2c({ number: 2, time: 1.01, tcpFlags: ACK, tcpSeq: 5000, tcpAck: 1100, tcpLen: 0, tcpWindow: undefined }),
    c2s({ number: 3, time: 1.5, tcpFlags: PSHACK, tcpSeq: 1100, tcpAck: 5000, tcpLen: 100 }),
    s2c({ number: 4, time: 1.51, tcpFlags: ACK, tcpSeq: 5000, tcpAck: 1200, tcpLen: 0, tcpWindow: 0 }),
    s2c({ number: 5, time: 1.6, tcpFlags: ACK, tcpSeq: 5000, tcpAck: 1200, tcpLen: 0, tcpWindow: 0 }),
    s2c({ number: 6, time: 1.7, tcpFlags: ACK, tcpSeq: 5000, tcpAck: 1200, tcpLen: 0, tcpWindow: 0 }),
    c2s({ number: 7, time: 1.9, tcpFlags: ACK, tcpSeq: 1200, tcpAck: 5000, tcpLen: 0 }),
    // 窗口重新打开,零窗口期结束
    s2c({ number: 8, time: 2.0, tcpFlags: ACK, tcpSeq: 5000, tcpAck: 1200, tcpLen: 0, tcpWindow: 8760 }),
  ]

  it('零窗口通告产出事件:含方向/起止时刻/通告包号;窗口重开即恢复', () => {
    const packets = zwChain()
    const events = detectZeroWindowEvents(packets)
    expect(events).toHaveLength(1)
    const ev = events[0]
    expect(ev.kind).toBe('zero-window')
    expect(ev.direction).toBe('s2c') // 通告方是接收方向
    expect(ev.startPacket).toBe(4)
    expect(ev.reopenPacket).toBe(8)
    expect(ev.durationSeconds).toBeCloseTo(0.49, 5) // 1.51 → 2.00(重开 ACK 时刻差)
    // 不过度归因:不断言对端状态异常("卡死/死机/宕机"式结论),只描述机制与值得关注的点
    expect(ev.inference.statement).toMatch(/流量控制|零窗口本身/)
    expect(ev.inference.statement).not.toMatch(/对端.{0,6}(死机|宕机|崩溃)|卡死/)
    expect(ev.limitations.length).toBeGreaterThan(0)
  })

  it('未重开的零窗口持续到抓包结束,severity 提高', () => {
    const packets = zwChain().slice(0, 7) // 无 #8 重开
    const events = detectZeroWindowEvents(packets)
    expect(events).toHaveLength(1)
    expect(events[0].reopenPacket).toBeUndefined()
    expect(events[0].severity).toBe('high')
  })

  it('窗口缺失(undefined)不构成零窗口;纯 ACK 才参与检测', () => {
    const packets = [
      c2s({ number: 1, time: 1.0, tcpFlags: PSHACK, tcpSeq: 1000, tcpAck: 5000, tcpLen: 100 }),
      s2c({ number: 2, time: 1.01, tcpFlags: ACK, tcpSeq: 5000, tcpAck: 1100, tcpLen: 0, tcpWindow: 0 }),
      c2s({ number: 3, time: 1.02, tcpFlags: PSHACK, tcpSeq: 1100, tcpAck: 5000, tcpLen: 100, tcpWindow: 0 }), // 数据报文不检测
    ]
    const events = detectZeroWindowEvents(packets)
    expect(events).toHaveLength(1)
    expect(events[0].startPacket).toBe(2)
  })

  it('空输入返回空数组;同输入两次结果一致', () => {
    expect(detectZeroWindowEvents([])).toEqual([])
    expect(JSON.stringify(detectZeroWindowEvents(zwChain()))).toBe(JSON.stringify(detectZeroWindowEvents(zwChain())))
  })
})

describe('detectFullWindowEvents — 对端窗口耗尽(发送方视角的停滞解释)', () => {
  it('未确认字节逼近对端通告窗口时产出提示事件', () => {
    const packets = [
      c2s({ number: 1, time: 1.0, tcpFlags: PSHACK, tcpSeq: 1000, tcpAck: 5000, tcpLen: 100 }),
      // 对端 ACK 前进 100,通告 window=100 → 在途 0,不触发
      s2c({ number: 2, time: 1.01, tcpFlags: ACK, tcpSeq: 5000, tcpAck: 1100, tcpLen: 0, tcpWindow: 100 }),
      // 发送方连发 200B:最高未确认=1100+200=1300,窗口右沿=1100+100=1200 → 超限
      c2s({ number: 3, time: 1.02, tcpFlags: PSHACK, tcpSeq: 1100, tcpAck: 5000, tcpLen: 100 }),
      c2s({ number: 4, time: 1.03, tcpFlags: PSHACK, tcpSeq: 1200, tcpAck: 5000, tcpLen: 100 }),
      // 对端仍 ACK 1100(未确认 200 > window 100)
      s2c({ number: 5, time: 1.5, tcpFlags: ACK, tcpSeq: 5000, tcpAck: 1100, tcpLen: 0, tcpWindow: 100 }),
    ]
    const events = detectFullWindowEvents(packets)
    expect(events).toHaveLength(1)
    expect(events[0].kind).toBe('full-window')
    expect(events[0].direction).toBe('c2s') // 被窗口限制的数据方向(c2s 发送方),而非通告方
    expect(events[0].unackedBytes).toBe(200)
    expect(events[0].advertisedWindow).toBe(100)
    // 措辞限定:这是发送方被窗口限制的观察,不是丢包
    expect(events[0].inference.statement).toMatch(/窗口/)
  })

  it('无 TCP window 字段的输入直接返回空(守卫:字段缺失不做推测)', () => {
    const packets = [
      c2s({ number: 1, time: 1.0, tcpFlags: PSHACK, tcpSeq: 1000, tcpAck: 5000, tcpLen: 100 }),
      s2c({ number: 2, time: 1.01, tcpFlags: ACK, tcpSeq: 5000, tcpAck: 1100, tcpLen: 0 }),
    ]
    expect(detectFullWindowEvents(packets)).toEqual([])
  })
})

describe('detectRstEvents — 连接重置', () => {
  it('RST 产出事件:含方向与发起方;正常关闭(FIN 握手)不产出', () => {
    const rstPackets: Packet[] = [
      c2s({ number: 1, time: 1.0, tcpFlags: PSHACK, tcpSeq: 1000, tcpAck: 5000, tcpLen: 100 }),
      s2c({ number: 2, time: 1.01, tcpFlags: ACK, tcpSeq: 5000, tcpAck: 1100, tcpLen: 0 }),
      // 服务端发 RST(携带合法 ack,表明它认为连接存在)
      s2c({ number: 3, time: 1.5, tcpFlags: RSTACK, tcpSeq: 5000, tcpAck: 1100, tcpLen: 0 }),
    ]
    const events = detectRstEvents(rstPackets)
    expect(events).toHaveLength(1)
    expect(events[0].kind).toBe('rst')
    expect(events[0].direction).toBe('s2c')
    expect(events[0].startPacket).toBe(3)
    // 单观察点:无法区分主动拒绝/进程崩溃/中间设备注入
    expect(events[0].inference.statement).toMatch(/无法/)
    // 正常关闭:FIN 交换不产出
    const finPackets: Packet[] = [
      c2s({ number: 1, time: 1.0, tcpFlags: '0x0011', tcpSeq: 1000, tcpAck: 5000, tcpLen: 0 }), // FIN·ACK
      s2c({ number: 2, time: 1.01, tcpFlags: '0x0011', tcpSeq: 5000, tcpAck: 1001, tcpLen: 0 }),
      c2s({ number: 3, time: 1.02, tcpFlags: ACK, tcpSeq: 1001, tcpAck: 5001, tcpLen: 0 }),
    ]
    expect(detectRstEvents(finPackets)).toEqual([])
  })

  it('中途抓包的 RST:事件保留但限制注明前提缺失', () => {
    const packets = [
      c2s({ number: 1, time: 1.0, tcpFlags: PSHACK, tcpSeq: 1000, tcpAck: 5000, tcpLen: 100 }),
      s2c({ number: 2, time: 1.01, tcpFlags: RST, tcpSeq: 5000, tcpAck: 1100, tcpLen: 0 }),
    ]
    const events = detectRstEvents(packets)
    expect(events).toHaveLength(1)
    expect(events[0].limitations.join(' ')).toMatch(/中途|握手/)
  })
})

describe('detectSynRetransmissionEvents — SYN 无响应/重传(连接建立困难)', () => {
  it('同一源端口的 SYN 重复出现且无 SYN-ACK:产出事件并计数', () => {
    const packets = [
      c2s({ number: 1, time: 1.0, tcpFlags: '0x0002', tcpSeq: 100, tcpLen: 0 }),
      c2s({ number: 2, time: 1.5, tcpFlags: '0x0002', tcpSeq: 100, tcpLen: 0 }), // 0.5s 后重传
      c2s({ number: 3, time: 3.0, tcpFlags: '0x0002', tcpSeq: 100, tcpLen: 0 }),
      // 换 seq 的新 SYN 是新的连接尝试,不计入上一个事件
      c2s({ number: 4, time: 9.0, tcpFlags: '0x0002', tcpSeq: 9000, tcpLen: 0 }),
    ]
    const events = detectSynRetransmissionEvents(packets)
    expect(events).toHaveLength(1) // (1,2,3) 同 seq 重传一组;#4 新 seq 单次尝试(无重传)不构成事件
    const first = events[0]
    expect(first.kind).toBe('syn-retransmission')
    expect(first.retransPackets).toEqual([2, 3])
    expect(first.direction).toBe('c2s')
    // 未收到 SYN-ACK:限制必须说明无法区分丢包/防火墙静默丢弃/对端不可达
    expect(first.limitations.join(' ')).toMatch(/静默|不可达|丢包/)
  })

  it('收到 SYN-ACK 的重传 SYN:正常建立,不产出事件(或标注已恢复)', () => {
    const packets = [
      c2s({ number: 1, time: 1.0, tcpFlags: '0x0002', tcpSeq: 100, tcpLen: 0 }),
      c2s({ number: 2, time: 1.5, tcpFlags: '0x0002', tcpSeq: 100, tcpLen: 0 }),
      s2c({ number: 3, time: 1.6, tcpFlags: '0x0012', tcpSeq: 500, tcpAck: 101, tcpLen: 0 }), // SYN-ACK
    ]
    const events = detectSynRetransmissionEvents(packets)
    expect(events).toHaveLength(1)
    expect(events[0].synAckPacket).toBe(3)
    expect(events[0].severity).toBe('low') // 最终建立了,严重度低
  })

  it('SYN+数据(如 TFO)或重传 ACK 不误入;空输入返回空', () => {
    expect(detectSynRetransmissionEvents([])).toEqual([])
    const packets = [
      c2s({ number: 1, time: 1.0, tcpFlags: ACK, tcpSeq: 100, tcpAck: 1, tcpLen: 0 }),
      c2s({ number: 2, time: 1.5, tcpFlags: ACK, tcpSeq: 100, tcpAck: 1, tcpLen: 0 }),
    ]
    expect(detectSynRetransmissionEvents(packets)).toEqual([])
  })
})
