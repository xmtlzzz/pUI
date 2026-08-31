// 端到端验证:模拟 Rust run_capture 平铺输出 → 前端解析聚合全链路;
// 兼含抓包格式识别矩阵(.cap/.cap.gz/.pcapng.gz —— tshark 按内容魔数识别,
// 与扩展名无关,M6 后格式扩展的回归锚点)
import { describe, expect, it } from 'vitest'
import { execFileSync } from 'node:child_process'
import { resolve } from 'node:path'
import { parsePackets } from './parsePackets'
import { aggregateConversations } from '../aggregate/aggregateConversations'
import { CAPTURE_FIELDS } from './captureFields'

const TSHARK = process.env.TSHARK ?? (process.platform === 'win32' ? 'C:\\Program Files\\Wireshark\\tshark.exe' : 'tshark')
const EDITCAP = process.env.EDITCAP ?? (process.platform === 'win32' ? 'C:\\Program Files\\Wireshark\\editcap.exe' : 'editcap')
const tsharkAvailable = (() => {
  try {
    execFileSync(TSHARK, ['-v'], { stdio: 'ignore' })
    return true
  } catch {
    return false
  }
})()

/** 把示例 pcapng 转成指定格式临时文件,执行后自动清理;返回绝对路径 */
function convertTo(format: string, ext: string): string {
  const out = resolve(process.cwd(), `node_modules/.cache/format-probe.${ext}`)
  execFileSync(EDITCAP, ['-F', format, resolve(process.cwd(), 'public/fixtures/examples/lossy.pcapng'), out], { stdio: 'ignore' })
  return out
}

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

  // 格式识别矩阵:同一内容的三种载体(经典 .cap / gzip 压缩)解析结果必须与
  // .pcapng 完全一致 —— 现网 .cap 抓包的支持回归锚点(2026-08-31 用户要求)。
  // tshark 按内容魔数识别格式,扩展名无关;editcap 生成临时文件,用后即删。
  const eArgs = CAPTURE_FIELDS.flatMap((f) => ['-e', f])
  const parseVia = (path: string): ReturnType<typeof aggregateConversations> => {
    const json = execFileSync(TSHARK, ['-r', path, '-T', 'json', ...eArgs], { encoding: 'utf-8', maxBuffer: 64 * 1024 * 1024 })
    return aggregateConversations(parsePackets(json))
  }
  const expectLossyShape = (convs: ReturnType<typeof aggregateConversations>): void => {
    expect(convs).toHaveLength(1)
    expect(convs[0].protocol).toBe('http')
    expect(convs[0].client).toBe('192.168.1.10:54321')
    expect(convs[0].packetCount).toBe(5)
  }

  it.skipIf(!tsharkAvailable)('.cap(经典 libpcap,tcpdump/现网设备导出常用后缀)全链路', () => {
    const cap = convertTo('pcap', 'cap')
    try {
      expectLossyShape(parseVia(cap))
    } finally {
      execFileSync('node', ['-e', `require('fs').rmSync(${JSON.stringify(cap)})`])
    }
  })

  it.skipIf(!tsharkAvailable)('.cap.gz(gzip 透明解压)全链路', () => {
    const cap = convertTo('pcap', 'cap')
    execFileSync(
      'node',
      ['-e', `const fs=require('fs'),zlib=require('zlib');fs.writeFileSync(${JSON.stringify(cap + '.gz')}, zlib.gzipSync(fs.readFileSync(${JSON.stringify(cap)})))`],
      { stdio: 'ignore' },
    )
    try {
      expectLossyShape(parseVia(cap + '.gz'))
    } finally {
      execFileSync('node', ['-e', `require('fs').rmSync(${JSON.stringify(cap + '.gz')})`])
      execFileSync('node', ['-e', `require('fs').rmSync(${JSON.stringify(cap)})`])
    }
  })
})
