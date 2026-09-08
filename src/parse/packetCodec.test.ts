import { describe, expect, it } from 'vitest'
import { packetColumns, columnsToPackets } from './packetCodec'
import { parsePackets } from './parsePackets'
import type { Packet } from '../model/types'

/** 与 parsePackets.test.ts 同构的最小平铺帧构造 */
function flatFrame(fields: Record<string, string>): string {
  return JSON.stringify({ _source: { layers: fields } })
}

/** 造一个全字段覆盖的 Packet(列式打包必须无损承载每个契约字段) */
function fullPacket(n: number): Packet {
  return {
    number: n,
    time: n * 0.1,
    timeEpoch: 1700000000 + n,
    interfaceId: '1',
    len: 60 + n,
    capLen: 60,
    transport: 'tcp',
    proto: n % 2 === 0 ? 'http' : 'tls',
    srcIp: `10.0.0.${n}`,
    dstIp: '192.168.1.1',
    srcMac: 'aa:bb:cc:dd:ee:01',
    dstMac: 'aa:bb:cc:dd:ee:02',
    srcPort: 10000 + n,
    dstPort: 443,
    tcpFlags: '0x0018',
    tcpSeq: 100 * n,
    tcpAck: 200 * n,
    tcpStream: n % 3,
    tcpWindow: 64240,
    tcpLen: n % 5,
    tcpCompleteness: 0x1f,
    tcpSackBlocks: [[1000, 2000], [3000, 4000]],
    tcpDupAckNum: 2,
    tcpAnalysis: ['retransmission', 'duplicate-ack'],
    httpTime: 0.05,
    httpMethod: 'GET',
    httpUri: `/api/${n}`,
    httpCode: '200',
    dnsQuery: 'example.com',
    tlsType: '1',
    sshProtocol: 'SSH-2.0-OpenSSH_9.6',
    sshChannelType: 'session',
    rdpNegProtocols: '0x00000003',
    rdpClientName: 'PC-01',
    vncProtoVer: '003.008',
    smb2Cmd: '0',
    smb2Response: true,
    smb2Tree: '\\\\server\\share',
    info: 'HTTP GET /',
    direction: 'request',
  }
}

describe('packetColumns / columnsToPackets(Worker 传输瘦身,PacketLens 借鉴 #1)', () => {
  it('往返:全字段覆盖的 Packet[] → 列式 → 逐字段深度相等', () => {
    const packets = [fullPacket(1), fullPacket(2), fullPacket(3)]
    const cols = packetColumns(packets)
    const restored = columnsToPackets(cols)
    expect(restored).toEqual(packets)
  })

  it('最简报文(TCP 纯 ACK):仅必填字段,往返仍相等', () => {
    const minimal: Packet = {
      number: 1,
      time: 0,
      len: 54,
      transport: 'tcp',
      proto: 'tcp',
      tcpFlags: '0x0010',
      direction: 'other',
    }
    const restored = columnsToPackets(packetColumns([minimal]))
    expect(restored).toEqual([minimal])
  })

  it('undefined 字段不产生列(undefined ≠ 缺键,往返后 getOwnPropertyNames 一致)', () => {
    const p = fullPacket(1)
    delete p.httpUri
    delete p.tcpSackBlocks
    const restored = columnsToPackets(packetColumns([p]))
    expect(restored[0].httpUri).toBeUndefined()
    expect(restored[0].tcpSackBlocks).toBeUndefined()
    // 「键不存在」与「值为 undefined」在结构化克隆里都变 undefined,语义兼容;
    // 这里钉住的是:稀疏列不会给缺字段的报文编造 0/''/null
    expect(Object.keys(restored[0])).not.toContain('httpUri')
  })

  it('零包:空数组往返为空数组(空抓包不炸)', () => {
    expect(columnsToPackets(packetColumns([]))).toEqual([])
  })

  it('确定性:同一输入两次打包,深度相等(纯函数)', () => {
    const packets = [fullPacket(1), fullPacket(2)]
    expect(packetColumns(packets)).toEqual(packetColumns(packets))
  })

  it('真实解析产物往返:parsePackets 结果 → 列式 → 深度相等(端到端契约)', () => {
    const json = JSON.stringify([
      { _source: { layers: flatFrame({ 'frame.number': '1', 'frame.protocols': 'eth:ethertype:ip:tcp', 'ip.src': '10.0.0.1', 'tcp.flags': '0x0012' }) } },
      { _source: { layers: flatFrame({ 'frame.number': '2', 'frame.protocols': 'eth:ethertype:ip:tcp', 'ip.src': '10.0.0.2', 'tcp.flags': '0x0018' }) } },
    ])
    const parsed = parsePackets(json)
    expect(columnsToPackets(packetColumns(parsed))).toEqual(parsed)
  })

  it('结构化克隆通道保真:postMessage 往返(JSON 模拟)后仍深度相等', () => {
    const packets = [fullPacket(1), fullPacket(2)]
    // Worker 通道传输的是结构化克隆:数组/嵌套数组/布尔都会保真,
    // 这里用 JSON 序列化模拟通道(比 structuredClone 更严——它连 undefined 键都丢弃)
    const through = JSON.parse(JSON.stringify(packetColumns(packets)))
    expect(columnsToPackets(through)).toEqual(packets)
  })
})
