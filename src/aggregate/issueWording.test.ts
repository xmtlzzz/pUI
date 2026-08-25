import { describe, expect, it } from 'vitest'
import type { Conversation, Packet } from '../model/types'
import { analyzeConversationIssues } from './issues'

function pkt(o: Partial<Packet> & { number: number; time: number }): Packet {
  return {
    transport: 'tcp',
    proto: 'tcp',
    len: 60,
    direction: 'request',
    srcIp: '10.0.0.1',
    dstIp: '10.0.0.2',
    srcPort: 5000,
    dstPort: 80,
    ...o,
  } as Packet
}

function conv(packets: Packet[]): Conversation {
  return {
    id: 'c1',
    client: '10.0.0.1:5000',
    server: '10.0.0.2:80',
    protocol: 'tcp',
    packetCount: packets.length,
    bytes: 0,
    start: packets[0]?.time ?? 0,
    end: packets[packets.length - 1]?.time ?? 0,
    duration: 0,
    packets,
    issues: [],
  }
}

const SYN = '0x0002'
const SYNACK = '0x0012'
const ACK = '0x0010'
const PSHACK = '0x0018'

/** 断言文案不含未经证据支持的因果断言 */
function expectNoPrematureLossClaim(message: string): void {
  // 「可能存在丢包」这类措辞把"重传/丢段"标签直接等价成网络丢包,
  // 而指南第 6 节明确 Retransmission ≠ 丢包、Lost Segment ≠ 真实网络丢包
  expect(message).not.toMatch(/可能存在丢包|可能有丢包|可能丢包/)
}

describe('issues 文案:观察与推断分离(plan M1)', () => {
  const withHandshake = (extra: Packet[]) => [
    pkt({ number: 1, time: 0, tcpFlags: SYN, tcpSeq: 0 }),
    pkt({ number: 2, time: 0.01, tcpFlags: SYNACK, tcpSeq: 0, tcpAck: 1, direction: 'response', srcIp: '10.0.0.2', dstIp: '10.0.0.1', srcPort: 80, dstPort: 5000 }),
    pkt({ number: 3, time: 0.02, tcpFlags: ACK, tcpSeq: 1, tcpAck: 1 }),
    ...extra,
  ]

  it('重传只陈述观察到的现象,不直接断言丢包', () => {
    const issues = analyzeConversationIssues(
      conv(withHandshake([pkt({ number: 4, time: 0.1, tcpFlags: PSHACK, tcpSeq: 1, tcpLen: 10, tcpAnalysis: ['retransmission'] })])),
    )
    const r = issues.find((i) => i.type === 'retransmission')
    expect(r).toBeDefined()
    expectNoPrematureLossClaim(r!.message)
    // 应如实说明"观察到 N 次重传",把是否丢包留给证据链
    expect(r!.message).toMatch(/重传/)
  })

  it('丢段标签只陈述 tshark 的推断来源,不升级为结论', () => {
    const issues = analyzeConversationIssues(
      conv(withHandshake([pkt({ number: 4, time: 0.1, tcpFlags: PSHACK, tcpSeq: 201, tcpLen: 10, tcpAnalysis: ['lost-segment'] })])),
    )
    const l = issues.find((i) => i.type === 'lost-segment')
    expect(l).toBeDefined()
    expectNoPrematureLossClaim(l!.message)
  })

  it('慢响应不把延迟归因为丢包', () => {
    const issues = analyzeConversationIssues(
      conv(withHandshake([pkt({ number: 4, time: 0.1, proto: 'http', httpTime: 3.5, httpCode: '200', direction: 'response' })])),
    )
    const s = issues.find((i) => i.type === 'slow-response')
    expect(s).toBeDefined()
    expectNoPrematureLossClaim(s!.message)
  })

  it('单向会话不直接断言丢包', () => {
    const issues = analyzeConversationIssues(
      conv([pkt({ number: 1, time: 0, tcpFlags: PSHACK, tcpSeq: 1, tcpLen: 10, direction: 'request' })]),
    )
    const o = issues.find((i) => i.type === 'one-way')
    expect(o).toBeDefined()
    expectNoPrematureLossClaim(o!.message)
  })

  it('所有 issue 文案都不含未经证据支持的丢包断言', () => {
    const issues = analyzeConversationIssues(
      conv(
        withHandshake([
          pkt({ number: 4, time: 0.1, tcpFlags: PSHACK, tcpSeq: 1, tcpLen: 10, tcpAnalysis: ['retransmission', 'lost-segment', 'duplicate-ack', 'out-of-order'] }),
          pkt({ number: 5, time: 0.2, proto: 'http', httpTime: 5, httpCode: '200', direction: 'response' }),
        ]),
      ),
    )
    expect(issues.length).toBeGreaterThan(0)
    for (const i of issues) expectNoPrematureLossClaim(i.message)
  })

  it('中途抓包时不产生确定性丢包结论', () => {
    // 首包不是纯 SYN:tshark 在流起始给首个数据段打 lost-segment 是公认假阳性
    const issues = analyzeConversationIssues(
      conv([
        pkt({ number: 1, time: 0, tcpFlags: PSHACK, tcpSeq: 500001, tcpLen: 100, tcpAnalysis: ['lost-segment'], tcpCompleteness: 12 }),
        pkt({ number: 2, time: 0.01, tcpFlags: ACK, tcpSeq: 1, tcpAck: 500101, direction: 'response', srcIp: '10.0.0.2', dstIp: '10.0.0.1', srcPort: 80, dstPort: 5000 }),
      ]),
    )
    expect(issues.find((i) => i.type === 'lost-segment')).toBeUndefined()
    for (const i of issues) expectNoPrematureLossClaim(i.message)
  })

  it('保留既有 issue type 取值(旧筛选与导出兼容)', () => {
    const issues = analyzeConversationIssues(
      conv(
        withHandshake([
          pkt({ number: 4, time: 0.1, tcpFlags: PSHACK, tcpSeq: 1, tcpLen: 10, tcpAnalysis: ['retransmission', 'duplicate-ack', 'out-of-order'] }),
        ]),
      ),
    )
    const types = issues.map((i) => i.type)
    // 类型集合不变,只改文案 —— 否则 FilterPanel 的类型筛选与旧导出会失配
    for (const t of types) {
      expect(['syn-no-reply', 'unanswered', 'one-way', 'no-close', 'retransmission', 'slow-response', 'rst', 'lost-segment', 'out-of-order', 'dup-ack']).toContain(t)
    }
    expect(types).toContain('retransmission')
    expect(types).toContain('dup-ack')
  })
})
