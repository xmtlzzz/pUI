// 临时端到端验证(验证后删除):模拟 Rust run_capture 新参数的真实输出 → 前端解析聚合全链路
import { describe, expect, it } from 'vitest'
import { execFileSync } from 'node:child_process'
import { resolve } from 'node:path'
import { parsePackets } from './parsePackets'
import { aggregateConversations } from '../aggregate/aggregateConversations'
import { CAPTURE_FIELDS } from './captureFields'

const TSHARK = process.env.TSHARK ?? (process.platform === 'win32' ? 'C:\\Program Files\\Wireshark\\tshark.exe' : 'tshark')
const tsharkAvailable = (() => {
  try {
    execFileSync(TSHARK, ['-v'], { stdio: 'ignore' })
    return true
  } catch {
    return false
  }
})()

describe('端到端:tshark -e 新参数输出 → parsePackets → aggregateConversations', () => {
  it.skipIf(!tsharkAvailable)('lossy.pcapng 真实解析出重传会话与 HTTP GET', () => {
    const pcap = resolve(process.cwd(), 'public/fixtures/examples/lossy.pcapng')
    const eArgs = CAPTURE_FIELDS.flatMap((f) => ['-e', f])
    const json = execFileSync(TSHARK, ['-r', pcap, '-T', 'json', ...eArgs], { encoding: 'utf-8' })
    const packets = parsePackets(json)
    expect(packets).toHaveLength(5)
    const convs = aggregateConversations(packets)
    expect(convs).toHaveLength(1)
    const c = convs[0]
    expect(c.protocol).toBe('http')
    expect(c.client).toBe('192.168.1.10:54321')
    expect(c.server).toBe('93.184.216.34:80')
    // 重传标签(-e 下划线命名)与未应答请求都要识别
    expect(c.issues.map((i) => i.type)).toContain('retransmission')
    expect(c.issues.map((i) => i.type)).toContain('unanswered')
    // HTTP GET 概要与 TCP SYN 标志解析正确
    const get = packets.find((p) => p.httpMethod === 'GET')
    expect(get?.httpUri).toBe('/')
    const syn = packets.find((p) => p.tcpFlags === '0x0002')
    expect(syn?.info).toBe('TCP SYN')
  })
})
