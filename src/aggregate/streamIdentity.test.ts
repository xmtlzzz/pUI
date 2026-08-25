import { describe, expect, it } from 'vitest'
import type { Packet } from '../model/types'
import { aggregateConversations, flowKey } from './aggregateConversations'

function pkt(o: Partial<Packet> & { number: number; time: number }): Packet {
  return {
    transport: 'tcp',
    proto: 'tcp',
    len: 60,
    direction: 'other',
    srcIp: '10.0.0.1',
    dstIp: '10.0.0.2',
    srcPort: 5000,
    dstPort: 80,
    ...o,
  } as Packet
}

const SYN = '0x0002'
const SYNACK = '0x0012'
const ACK = '0x0010'
const PSHACK = '0x0018'
const FINACK = '0x0011'

/**
 * plan M1 验收:同一端点对的不同 tcp.stream 不得被错误合并。
 *
 * 实测 tshark 对"同一 4 元组的先后两条连接"给出 stream=0 / stream=1,
 * 而按端点对聚合会把它们并成一个会话 —— 于是两条连接的握手、序列号、异常统计全部混在一起,
 * TCP 状态机在这种会话上运行毫无意义。
 */
describe('会话身份:tcp.stream 优先', () => {
  it('同一端点对的两条 tcp.stream 被拆成两个会话', () => {
    const packets = [
      // 连接 1(stream 0):完整建连、传输、关闭
      pkt({ number: 1, time: 0, tcpFlags: SYN, tcpSeq: 0, tcpStream: 0 }),
      pkt({ number: 2, time: 0.01, tcpFlags: SYNACK, tcpSeq: 0, tcpAck: 1, tcpStream: 0, srcIp: '10.0.0.2', dstIp: '10.0.0.1', srcPort: 80, dstPort: 5000 }),
      pkt({ number: 3, time: 0.02, tcpFlags: FINACK, tcpSeq: 1, tcpAck: 1, tcpStream: 0 }),
      // 连接 2(stream 1):同一 4 元组复用,不同 ISN
      pkt({ number: 4, time: 1.0, tcpFlags: SYN, tcpSeq: 9000, tcpStream: 1 }),
      pkt({ number: 5, time: 1.01, tcpFlags: SYNACK, tcpSeq: 7000, tcpAck: 9001, tcpStream: 1, srcIp: '10.0.0.2', dstIp: '10.0.0.1', srcPort: 80, dstPort: 5000 }),
      pkt({ number: 6, time: 1.02, tcpFlags: PSHACK, tcpSeq: 9001, tcpAck: 7001, tcpStream: 1, tcpLen: 10 }),
    ]
    const convs = aggregateConversations(packets)
    expect(convs).toHaveLength(2)
    expect(convs.map((c) => c.packetCount)).toEqual([3, 3])
  })

  it('flowKey 在有 tcp.stream 时把它纳入身份', () => {
    const a = pkt({ number: 1, time: 0, tcpStream: 0 })
    const b = pkt({ number: 2, time: 1, tcpStream: 1 })
    expect(flowKey(a)).not.toBe(flowKey(b))
  })

  it('同一 stream 的双向报文仍归入同一会话', () => {
    const packets = [
      pkt({ number: 1, time: 0, tcpFlags: SYN, tcpSeq: 0, tcpStream: 7 }),
      pkt({ number: 2, time: 0.01, tcpFlags: SYNACK, tcpSeq: 0, tcpAck: 1, tcpStream: 7, srcIp: '10.0.0.2', dstIp: '10.0.0.1', srcPort: 80, dstPort: 5000 }),
      pkt({ number: 3, time: 0.02, tcpFlags: ACK, tcpSeq: 1, tcpAck: 1, tcpStream: 7 }),
    ]
    const convs = aggregateConversations(packets)
    expect(convs).toHaveLength(1)
    expect(convs[0].packetCount).toBe(3)
  })

  it('无 tcp.stream 时退回端点对聚合(旧抓包兼容)', () => {
    const packets = [
      pkt({ number: 1, time: 0, tcpFlags: SYN, tcpSeq: 0 }),
      pkt({ number: 2, time: 0.01, tcpFlags: SYNACK, tcpSeq: 0, tcpAck: 1, srcIp: '10.0.0.2', dstIp: '10.0.0.1', srcPort: 80, dstPort: 5000 }),
    ]
    const convs = aggregateConversations(packets)
    expect(convs).toHaveLength(1)
  })

  it('非 TCP 流量不受 tcp.stream 影响', () => {
    const packets = [
      pkt({ number: 1, time: 0, transport: 'udp', proto: 'dns', srcPort: 5353, dstPort: 53, tcpStream: undefined }),
      pkt({ number: 2, time: 0.01, transport: 'udp', proto: 'dns', srcIp: '10.0.0.2', dstIp: '10.0.0.1', srcPort: 53, dstPort: 5353 }),
    ]
    const convs = aggregateConversations(packets)
    expect(convs).toHaveLength(1)
  })

  it('混合:有 stream 的 TCP 与无 stream 的 UDP 各自独立聚合', () => {
    const packets = [
      pkt({ number: 1, time: 0, tcpFlags: SYN, tcpSeq: 0, tcpStream: 0 }),
      pkt({ number: 2, time: 0.1, transport: 'udp', proto: 'dns', srcPort: 5353, dstPort: 53 }),
    ]
    expect(aggregateConversations(packets)).toHaveLength(2)
  })
})
