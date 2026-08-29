import { describe, expect, it } from 'vitest'
import { exportTranscript } from './exportTranscript'
import type { Conversation, Packet } from '../model/types'

const SYN = (n: number): Packet => ({ number: n, time: n * 0.5, len: 60, transport: 'tcp', proto: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request', info: 'TCP SYN' })
const ACK_REQ = (n: number): Packet => ({ number: n, time: n * 0.5, len: 60, transport: 'tcp', proto: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request', info: 'TCP ACK' })
const RETX = (n: number): Packet => ({ number: n, time: n * 0.5, len: 1400, transport: 'tcp', proto: 'tcp', srcIp: '1.1.1.1', dstIp: '2.2.2.2', direction: 'request', info: 'TCP PSH-ACK', tcpAnalysis: ['retransmission'] })

describe('exportTranscript 仅异常包模式(mode=anomalies)', () => {
  const mixed: Packet[] = [SYN(1), ACK_REQ(2), RETX(3), RETX(4), ACK_REQ(5)]
  const conv3: Conversation = { id: 'k3', client: '1.1.1.1:54321', server: '2.2.2.2:80', protocol: 'tcp', packetCount: 5, bytes: 100, start: 0, end: 2.5, duration: 2.5, packets: mixed, issues: [] }

  it('仅保留带分析标记的报文,丢弃正常握手/ACK;模式行标注', () => {
    const md = exportTranscript(conv3, null, 'anomalies')
    expect(md).toContain('模式: 仅异常包')
    // 保留异常(#3/#4 重传行)
    expect(md).toContain('| 3 | 1.500')
    expect(md).toContain('| 4 | 2.000')
    expect(md).toContain('retransmission')
    // 丢弃正常 SYN / ACK(1/2/5 不得出现)
    expect(md).not.toContain('| 1 | 0.000')
    expect(md).not.toContain('| 2 |')
    expect((md.match(/\| 5 \|/g) ?? []).length).toBe(0)
  })

  it('仅异常+紧凑:相邻重传合并为区间 #3–#4', () => {
    const md = exportTranscript(conv3, true, 'anomalies')
    expect(md).toContain('#3\u2013#4')
  })

  it('会话无异常标记时给明确提示,不渲染空表', () => {
    const clean: Packet[] = [SYN(1), ACK_REQ(2)]
    const conv4: Conversation = { id: 'k4', client: '1.1.1.1:54321', server: '2.2.2.2:80', protocol: 'tcp', packetCount: 2, bytes: 120, start: 0, end: 1, duration: 1, packets: clean, issues: [] }
    const md = exportTranscript(conv4, null, 'anomalies')
    expect(md).toContain('无异常报文可列')
    expect(md).not.toContain('| 报文区间 |')
  })

  it('全量模式(mode=full)不受影响,仍含正常握手', () => {
    const md = exportTranscript(conv3, null, 'full')
    expect(md).toContain('TCP SYN')
    expect(md).toContain('| 1 | 0.500')
  })
})