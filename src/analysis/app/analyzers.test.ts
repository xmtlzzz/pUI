import { describe, expect, it } from 'vitest'
import type { Packet } from '../../model/types'
import {
  APPLICATION_ANALYZERS,
  countAppEvents,
  dnsAnalyzer,
  httpAnalyzer,
  rdpAnalyzer,
  runApplicationAnalyzers,
  smbAnalyzer,
  sshAnalyzer,
  tlsAnalyzer,
  vncAnalyzer,
} from './analyzers'

function pkt(o: Partial<Packet> & { number: number; time: number }): Packet {
  return {
    transport: 'tcp',
    proto: 'tcp',
    len: 100,
    direction: 'other',
    tcpStream: 0,
    ...o,
  } as Packet
}

describe('M6 ApplicationAnalyzer — HTTP/DNS/TLS 插件', () => {
  it('HTTP:请求与响应各自成事件,响应携带 http.time 耗时观察;URI 超长截断', () => {
    const evs = httpAnalyzer.analyze([
      pkt({ number: 1, time: 0, proto: 'http', httpMethod: 'GET', httpUri: '/api/data?x=1' }),
      pkt({ number: 2, time: 0.4, proto: 'http', httpCode: '200', httpTime: 0.4 }),
      pkt({ number: 3, time: 1, proto: 'http', httpMethod: 'GET', httpUri: `/${'a'.repeat(80)}` }),
    ])
    expect(evs).toHaveLength(3)
    expect(evs[0].summary).toBe('HTTP GET /api/data?x=1')
    expect(evs[1].summary).toBe('HTTP 响应 200')
    expect(evs[1].durationSeconds).toBe(0.4)
    expect(evs[2].summary!.length).toBeLessThan(60)
    expect(evs[2].summary).toContain('…')
  })

  it('HTTP:无 http 字段的报文不产出事件(不臆造)', () => {
    expect(httpAnalyzer.analyze([pkt({ number: 1, time: 0 }), pkt({ number: 2, time: 1, tcpFlags: '0x0018' })])).toEqual([])
  })

  it('DNS:查询与响应按 info 区分;响应/查询措辞分明', () => {
    const evs = dnsAnalyzer.analyze([
      pkt({ number: 1, time: 0, proto: 'dns', dnsQuery: 'example.com', info: 'query' }),
      pkt({ number: 2, time: 0.05, proto: 'dns', dnsQuery: 'example.com', info: 'response' }),
    ])
    expect(evs.map((e) => e.summary)).toEqual(['DNS 查询 example.com', 'DNS 响应 example.com'])
  })

  it('TLS:handshake.type 映射常见握手名,未知的按编号如实显示', () => {
    const evs = tlsAnalyzer.analyze([
      pkt({ number: 1, time: 0, tlsType: '1' }),
      pkt({ number: 2, time: 0.02, tlsType: '2' }),
      pkt({ number: 3, time: 0.03, tlsType: '99' }),
    ])
    expect(evs.map((e) => e.summary)).toEqual(['TLS 握手 ClientHello', 'TLS 握手 ServerHello', 'TLS 握手 type=99'])
  })

  it('runApplicationAnalyzers:全插件按时间合并排序,确定性(同输入同输出)', () => {
    const packets = [
      pkt({ number: 1, time: 0, proto: 'dns', dnsQuery: 'a.com', info: 'query' }),
      pkt({ number: 2, time: 0.01, tlsType: '1' }),
      pkt({ number: 3, time: 0.02, proto: 'http', httpMethod: 'GET', httpUri: '/' }),
      pkt({ number: 4, time: 0.03, proto: 'ssh', sshProtocol: 'SSH-2.0-OpenSSH_9.6' }),
      pkt({ number: 5, time: 0.04, proto: 'rdp', rdpNegProtocols: '0x00000003' }),
      pkt({ number: 6, time: 0.05, proto: 'vnc', vncProtoVer: '003.008' }),
      pkt({ number: 7, time: 0.06, proto: 'smb2', smb2Cmd: '0' }),
      pkt({ number: 8, time: 0.3, proto: 'http', httpCode: '200', httpTime: 0.28 }),
    ]
    const a = runApplicationAnalyzers(packets)
    expect(a.map((e) => e.app)).toEqual(['dns', 'tls', 'http', 'ssh', 'rdp', 'vnc', 'smb', 'http'])
    expect(JSON.stringify(runApplicationAnalyzers(packets))).toBe(JSON.stringify(a))
  })

  it('插件注册表含两批共七协议且顺序固定;计数器按 app×kind 汇总(含新 kind session)', () => {
    expect(APPLICATION_ANALYZERS.map((a) => a.id)).toEqual(['http', 'dns', 'tls', 'ssh', 'rdp', 'vnc', 'smb'])
    const counts = countAppEvents(runApplicationAnalyzers([
      pkt({ number: 1, time: 0, proto: 'http', httpMethod: 'GET', httpUri: '/' }),
      pkt({ number: 2, time: 0.3, proto: 'http', httpCode: '200' }),
      pkt({ number: 3, time: 0, proto: 'dns', dnsQuery: 'x.com', info: 'query' }),
      pkt({ number: 4, time: 0.01, proto: 'ssh', sshChannelType: 'session' }),
      pkt({ number: 5, time: 0.02, proto: 'smb2', smb2Cmd: '0', smb2Response: true }),
    ]))
    expect(counts).toContainEqual({ app: 'http', kind: 'request', count: 1 })
    expect(counts).toContainEqual({ app: 'http', kind: 'response', count: 1 })
    expect(counts).toContainEqual({ app: 'dns', kind: 'query', count: 1 })
    expect(counts).toContainEqual({ app: 'ssh', kind: 'session', count: 1 })
    expect(counts).toContainEqual({ app: 'smb', kind: 'response', count: 1 })
  })
})

describe('M6 第二批 ApplicationAnalyzer — SSH/RDP/VNC/SMB 插件(加密协议只观察明文字段)', () => {
  it('SSH:版本横幅 → handshake(超 40 字符截断加 …);通道类型 → session;字段缺 → [](不臆造)', () => {
    const banner = 'SSH-2.0-' + 'a'.repeat(60)
    const evs = sshAnalyzer.analyze([
      pkt({ number: 1, time: 0, proto: 'ssh', sshProtocol: 'SSH-2.0-OpenSSH_9.6' }),
      pkt({ number: 2, time: 0.01, proto: 'ssh', sshProtocol: banner }),
      pkt({ number: 3, time: 0.02, proto: 'ssh', sshChannelType: 'session' }),
      pkt({ number: 4, time: 0.03, proto: 'ssh' }),
    ])
    expect(evs.map((e) => e.id)).toEqual(['ssh:handshake:1', 'ssh:handshake:2', 'ssh:session:3'])
    expect(evs[0]).toMatchObject({ app: 'ssh', kind: 'handshake', summary: 'SSH 版本横幅 SSH-2.0-OpenSSH_9.6' })
    // 横幅只保留前 40 字符 + 省略号(摘要层不承载全文)
    expect(evs[1].summary).toBe(`SSH 版本横幅 ${banner.slice(0, 40)}…`)
    expect(evs[2]).toMatchObject({ app: 'ssh', kind: 'session', summary: 'SSH 通道请求 session' })
    expect(sshAnalyzer.analyze([pkt({ number: 9, time: 0 })])).toEqual([])
  })

  it('RDP:协商掩码按位映射(0x3→SSL+CredSSP、0x4→RDSTLS、0x00000008→CredSSP扩展、纯十进制容错、解析失败回退原文)', () => {
    const evs = rdpAnalyzer.analyze([
      pkt({ number: 1, time: 0, proto: 'rdp', rdpNegProtocols: '0x00000003' }),
      pkt({ number: 2, time: 0.01, proto: 'rdp', rdpNegProtocols: '0x00000004' }),
      pkt({ number: 3, time: 0.02, proto: 'rdp', rdpNegProtocols: '0x00000008' }),
      pkt({ number: 4, time: 0.03, proto: 'rdp', rdpNegProtocols: '3' }),
      pkt({ number: 5, time: 0.04, proto: 'rdp', rdpNegProtocols: 'not-a-mask' }),
      pkt({ number: 6, time: 0.05, proto: 'rdp' }),
    ])
    expect(evs.map((e) => e.summary)).toEqual([
      'RDP 连接协商 请求协议=SSL+CredSSP',
      'RDP 连接协商 请求协议=RDSTLS',
      'RDP 连接协商 请求协议=CredSSP扩展',
      'RDP 连接协商 请求协议=SSL+CredSSP',
      'RDP 连接协商 请求协议=not-a-mask',
    ])
    expect(evs.every((e) => e.app === 'rdp' && e.kind === 'handshake')).toBe(true)
    expect(rdpAnalyzer.analyze([pkt({ number: 9, time: 0 })])).toEqual([])
  })

  it('RDP:客户端名 → session(超 40 截断加 …)', () => {
    const evs = rdpAnalyzer.analyze([
      pkt({ number: 1, time: 0, proto: 'rdp', rdpClientName: 'DESKTOP-ABC123' }),
      pkt({ number: 2, time: 0.01, proto: 'rdp', rdpClientName: 'M'.repeat(41) }),
    ])
    expect(evs[0]).toMatchObject({ app: 'rdp', kind: 'session', id: 'rdp:session:1', summary: 'RDP 客户端名 DESKTOP-ABC123' })
    expect(evs[1].summary).toBe(`RDP 客户端名 ${'M'.repeat(40)}…`)
  })

  it('VNC:RFB 版本横幅 → handshake;字段缺 → [](不臆造)', () => {
    const evs = vncAnalyzer.analyze([
      pkt({ number: 1, time: 0, proto: 'vnc', vncProtoVer: '003.008' }),
      pkt({ number: 2, time: 0.01, proto: 'vnc' }),
    ])
    expect(evs).toEqual([
      { id: 'vnc:handshake:1', app: 'vnc', kind: 'handshake', packetNumber: 1, time: 0, summary: 'VNC RFB 版本 003.008' },
    ])
  })

  it('SMB:命令号映射名称,方向按 smb2Response 区分;未知命令号回退;字段缺 → [](不臆造)', () => {
    const evs = smbAnalyzer.analyze([
      pkt({ number: 1, time: 0, proto: 'smb2', smb2Cmd: '0' }),
      pkt({ number: 2, time: 0.01, proto: 'smb2', smb2Cmd: '0', smb2Response: true }),
      pkt({ number: 3, time: 0.02, proto: 'smb2', smb2Cmd: '3', smb2Tree: '\\\\DEMO\\share' }),
      pkt({ number: 4, time: 0.03, proto: 'smb2', smb2Cmd: '99' }),
      pkt({ number: 5, time: 0.04, proto: 'smb2' }),
    ])
    expect(evs.map((e) => e.id)).toEqual(['smb:request:1', 'smb:response:2', 'smb:request:3', 'smb:request:4'])
    expect(evs.map((e) => e.kind)).toEqual(['request', 'response', 'request', 'request'])
    expect(evs.map((e) => e.summary)).toEqual(['SMB2 协商', 'SMB2 协商', 'SMB2 树连接 \\\\DEMO\\share', 'SMB2 命令 99'])
    expect(evs.every((e) => e.app === 'smb')).toBe(true)
    expect(smbAnalyzer.analyze([pkt({ number: 9, time: 0 })])).toEqual([])
  })

  it('SMB:tree 超 48 字符截断加 …;已知命令号全量映射', () => {
    const longTree = '\\\\srv\\' + 'd'.repeat(50)
    const [ev] = smbAnalyzer.analyze([pkt({ number: 1, time: 0, smb2Cmd: '3', smb2Tree: longTree })])
    expect(ev.summary).toBe(`SMB2 树连接 ${longTree.slice(0, 48)}…`)
    const names = smbAnalyzer.analyze(
      ['0', '1', '2', '3', '4', '5', '6', '7', '16', '18', '22'].map((cmd, i) =>
        pkt({ number: i + 1, time: i * 0.01, smb2Cmd: cmd })),
    ).map((e) => e.summary)
    expect(names).toEqual([
      'SMB2 协商', 'SMB2 会话建立', 'SMB2 会话注销', 'SMB2 树连接', 'SMB2 树断开', 'SMB2 创建',
      'SMB2 读取', 'SMB2 写入', 'SMB2 关闭', 'SMB2 枚举', 'SMB2 设置信息',
    ])
  })
})
