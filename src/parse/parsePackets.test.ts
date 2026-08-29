import { describe, expect, it } from 'vitest'
import { parsePackets } from './parsePackets'

const raw = JSON.stringify([
  {
    _source: {
      layers: {
        frame: {
          'frame.number': '1',
          'frame.time_relative': '0.000000',
          'frame.len': '74',
          'frame.protocols': 'eth:ethertype:ip:tcp:http',
        },
        eth: { 'eth.src': '00:11:22:33:44:55', 'eth.dst': '00:aa:bb:cc:dd:ee' },
        ip: { 'ip.src': '192.168.1.10', 'ip.dst': '93.184.216.34' },
        tcp: { 'tcp.srcport': '54321', 'tcp.dstport': '80', 'tcp.flags': '0x0002' },
        http: { 'http.request.method': 'GET', 'http.request.uri': '/', 'http.host': 'example.com' },
      },
    },
  },
])

describe('parsePackets', () => {
  it('maps tshark json layers to Packet fields', () => {
    const packets = parsePackets(raw)
    expect(packets).toHaveLength(1)
    const p = packets[0]
    expect(p.number).toBe(1)
    expect(p.time).toBeCloseTo(0.0)
    expect(p.len).toBe(74)
    expect(p.transport).toBe('tcp')
    expect(p.proto).toBe('http')
    expect(p.srcIp).toBe('192.168.1.10')
    expect(p.dstIp).toBe('93.184.216.34')
    expect(p.srcPort).toBe(54321)
    expect(p.dstPort).toBe(80)
    expect(p.tcpFlags).toBe('0x0002')
    expect(p.httpMethod).toBe('GET')
    expect(p.httpUri).toBe('/')
    expect(p.info).toContain('GET')
    expect(p.direction).toBe('other') // 方向在聚合阶段确定
  })

  it('超过解析上限的 JSON 文本直接拒绝(防 JSON.parse 对象图放大数 GB)', () => {
    const huge = '['.padEnd(128 * 1024 * 1024 + 1, ' ')
    expect(() => parsePackets(huge)).toThrow(/过大/)
    // 略小于上限的畸形文本仍走 JSON 语法错误(守卫只挡体积)
    expect(() => parsePackets('[')).toThrow()
  })

  it('解析 frame.interface_id 供接口数统计', () => {
    const raw = JSON.stringify([
      {
        _source: {
          layers: {
            frame: { 'frame.number': '1', 'frame.time_relative': '0.000000', 'frame.interface_id': '0', 'frame.len': '60', 'frame.protocols': 'eth:ethertype:ip:tcp' },
            ip: { 'ip.src': '1.1.1.1', 'ip.dst': '2.2.2.2' },
            tcp: { 'tcp.srcport': '12345', 'tcp.dstport': '80' },
          },
        },
      },
      {
        _source: {
          layers: {
            frame: { 'frame.number': '2', 'frame.time_relative': '0.001000', 'frame.interface_id': '1', 'frame.len': '60', 'frame.protocols': 'eth:ethertype:ip:tcp' },
            ip: { 'ip.src': '2.2.2.2', 'ip.dst': '1.1.1.1' },
            tcp: { 'tcp.srcport': '80', 'tcp.dstport': '12345' },
          },
        },
      },
    ])
    const [a, b] = parsePackets(raw)
    expect(a.interfaceId).toBe('0')
    expect(b.interfaceId).toBe('1')
  })

  it('解析 frame.time_epoch 供绝对时间戳展示', () => {
    const withEpoch = JSON.stringify([
      {
        _source: {
          layers: {
            frame: { 'frame.number': '1', 'frame.time_relative': '0.000000', 'frame.time_epoch': '1590969600.123456', 'frame.len': '60', 'frame.protocols': 'eth:ethertype:ip:tcp' },
            ip: { 'ip.src': '1.1.1.1', 'ip.dst': '2.2.2.2' },
            tcp: { 'tcp.srcport': '12345', 'tcp.dstport': '80' },
          },
        },
      },
    ])
    const [p] = parsePackets(withEpoch)
    expect(p.timeEpoch).toBeCloseTo(1590969600.123456, 5)
  })

  it('tcp.flags 嵌套对象形态仍解析为十六进制(jsonraw/旧版 tshark 兼容)', () => {
    const nested = JSON.stringify([
      {
        _source: {
          layers: {
            frame: { 'frame.number': '1', 'frame.time_relative': '0.000000', 'frame.len': '60', 'frame.protocols': 'eth:ethertype:ip:tcp' },
            ip: { 'ip.src': '1.1.1.1', 'ip.dst': '2.2.2.2' },
            tcp: { 'tcp.srcport': '12345', 'tcp.dstport': '80', 'tcp.flags': { 'tcp.flags': '0x0012', 'tcp.flags.str': '....S.' } },
          },
        },
      },
    ])
    const [p] = parsePackets(nested)
    expect(p.tcpFlags).toBe('0x0012')
    expect(p.info).toBe('TCP SYN-ACK')
  })

  it('仅有 flags.str 位串时也能推出十六进制', () => {
    const strOnly = JSON.stringify([
      {
        _source: {
          layers: {
            frame: { 'frame.number': '1', 'frame.time_relative': '0.000000', 'frame.len': '60', 'frame.protocols': 'eth:ethertype:ip:tcp' },
            ip: { 'ip.src': '1.1.1.1', 'ip.dst': '2.2.2.2' },
            tcp: { 'tcp.srcport': '12345', 'tcp.dstport': '80', 'tcp.flags': { 'tcp.flags.str': '..S...' } },
          },
        },
      },
    ])
    const [p] = parsePackets(strOnly)
    expect(p.tcpFlags).toBe('0x0002')
  })

  it('frame.protocols 缺失时 proto 为 unknown 而非空串', () => {
    const bare = JSON.stringify([
      {
        _source: {
          layers: {
            frame: { 'frame.number': '1', 'frame.time_relative': '0.000000', 'frame.len': '42' },
            eth: { 'eth.src': 'aa:bb:cc:dd:ee:01', 'eth.dst': 'aa:bb:cc:dd:ee:02' },
          },
        },
      },
    ])
    const [p] = parsePackets(bare)
    expect(p.proto).toBe('unknown')
  })

  it('extracts method/uri nested under the request-line key', () => {
    const lineRaw = JSON.stringify([
      {
        _source: {
          layers: {
            frame: { 'frame.number': '4', 'frame.time_relative': '0.045', 'frame.len': '100', 'frame.protocols': 'eth:ethertype:ip:tcp:http' },
            tcp: { 'tcp.srcport': '54321', 'tcp.dstport': '80' },
            http: { 'GET / HTTP/1.1\\r\\n': { 'http.request.method': 'GET', 'http.request.uri': '/' } },
          },
        },
      },
    ])
    const [p] = parsePackets(lineRaw)
    expect(p.httpMethod).toBe('GET')
    expect(p.httpUri).toBe('/')
    expect(p.info).toContain('GET')
  })

  it('extracts response code nested under the status-line key', () => {
    const lineRaw = JSON.stringify([
      {
        _source: {
          layers: {
            frame: { 'frame.number': '6', 'frame.time_relative': '0.180', 'frame.len': '150', 'frame.protocols': 'eth:ethertype:ip:tcp:http' },
            tcp: { 'tcp.srcport': '80', 'tcp.dstport': '54321' },
            http: { 'HTTP/1.1 200 OK\\r\\n': { 'http.response.code': '200' } },
          },
        },
      },
    ])
    const [p] = parsePackets(lineRaw)
    expect(p.httpCode).toBe('200')
    expect(p.info).toContain('200')
  })

  it('extracts dns query name from nested Queries section', () => {
    const lineRaw = JSON.stringify([
      {
        _source: {
          layers: {
            frame: { 'frame.number': '2', 'frame.time_relative': '0.02', 'frame.len': '70', 'frame.protocols': 'eth:ethertype:ip:udp:dns' },
            udp: { 'udp.srcport': '53', 'udp.dstport': '54322' },
            dns: { Queries: { 'example.com: type A, class IN': { 'dns.qry.name': 'example.com' } } },
          },
        },
      },
    ])
    const [p] = parsePackets(lineRaw)
    expect(p.dnsQuery).toBe('example.com')
    expect(p.info).toContain('example.com')
  })

  it('derives transport from the protocol stack', () => {
    const udpRaw = JSON.stringify([
      { _source: { layers: { frame: { 'frame.number': '1', 'frame.time_relative': '0', 'frame.len': '60', 'frame.protocols': 'eth:ethertype:ip:udp' }, udp: { 'udp.srcport': '54322', 'udp.dstport': '53' } } } },
    ])
    const [p] = parsePackets(udpRaw)
    expect(p.transport).toBe('udp')
    expect(p.srcPort).toBe(54322)
    expect(p.dstPort).toBe(53)
  })

  it('falls back to app protocol when no transport layer present', () => {
    const arpRaw = JSON.stringify([
      { _source: { layers: { frame: { 'frame.number': '1', 'frame.time_relative': '0', 'frame.len': '42', 'frame.protocols': 'eth:ethertype:arp' } } } },
    ])
    const [p] = parsePackets(arpRaw)
    expect(p.transport).toBe('arp')
    expect(p.proto).toBe('arp')
  })

  it('detects tcp analysis tags nested under tcp.analysis', () => {
    const raw = JSON.stringify([
      {
        _source: {
          layers: {
            frame: { 'frame.number': '5', 'frame.time_relative': '0.4', 'frame.len': '60', 'frame.protocols': 'eth:ethertype:ip:tcp:http' },
            tcp: { 'tcp.analysis': { 'tcp.analysis.flags': { _ws: { expert: { 'tcp.analysis.retransmission': '' } } } } },
          },
        },
      },
    ])
    const [p] = parsePackets(raw)
    expect(p.tcpAnalysis).toContain('retransmission')
  })

  it('extracts http.time response latency', () => {
    const raw = JSON.stringify([
      {
        _source: {
          layers: {
            frame: { 'frame.number': '6', 'frame.time_relative': '3.0', 'frame.len': '150', 'frame.protocols': 'eth:ethertype:ip:tcp:http' },
            tcp: { 'tcp.srcport': '80', 'tcp.dstport': '54321' },
            http: { 'http.response.line': 'HTTP/1.1 200 OK', 'http.time': '2.95' },
          },
        },
      },
    ])
    const [p] = parsePackets(raw)
    expect(p.httpTime).toBeCloseTo(2.95)
  })
})

describe('parsePackets -e 平铺形态(-T json -e 输出,大文件模式)', () => {
  // 真实 tshark 4.6 -e 输出形态:键直接平铺在 layers 上,值为数组;缺失字段整个不出现
  function flatFrame(layers: Record<string, string | string[]>): string {
    return JSON.stringify([{ _source: { layers } }])
  }

  it('平铺键直接映射到 Packet 字段', () => {
    const [p] = parsePackets(flatFrame({
      'frame.number': ['1'],
      'frame.time_relative': ['0.000000000'],
      'frame.time_epoch': ['0.000000000'],
      'frame.interface_id': ['0'],
      'frame.len': ['54'],
      'frame.protocols': ['eth:ethertype:ip:tcp'],
      'eth.src': ['00:11:22:33:44:55'],
      'eth.dst': ['00:aa:bb:cc:dd:ee'],
      'ip.src': ['192.168.1.10'],
      'ip.dst': ['93.184.216.34'],
      'tcp.srcport': ['54321'],
      'tcp.dstport': ['80'],
      'tcp.flags': ['0x0002'],
      'tcp.seq_raw': ['1000'],
      'tcp.ack_raw': ['0'],
    }))
    expect(p.number).toBe(1)
    expect(p.transport).toBe('tcp')
    expect(p.proto).toBe('tcp')
    expect(p.srcIp).toBe('192.168.1.10')
    expect(p.srcPort).toBe(54321)
    expect(p.tcpFlags).toBe('0x0002')
    expect(p.tcpSeq).toBe(1000)
    expect(p.srcMac).toBe('00:11:22:33:44:55')
    expect(p.info).toBe('TCP SYN')
  })

  it('-e 规范名(下划线)的 tcp.analysis 字段识别为标签', () => {
    const [p] = parsePackets(flatFrame({
      'frame.number': ['5'],
      'frame.time_relative': ['0.4'],
      'frame.len': ['113'],
      'frame.protocols': ['eth:ethertype:ip:tcp'],
      'ip.src': ['1.1.1.1'],
      'ip.dst': ['2.2.2.2'],
      'tcp.srcport': ['54321'],
      'tcp.dstport': ['80'],
      'tcp.analysis.retransmission': ['1'],
    }))
    expect(p.tcpAnalysis).toContain('retransmission')
  })

  it('dns.flags.response 的 -e 取值(True/False)正确判定方向信息', () => {
    const [q] = parsePackets(flatFrame({
      'frame.number': ['1'], 'frame.time_relative': ['0'], 'frame.len': ['70'],
      'frame.protocols': ['eth:ethertype:ip:udp:dns'],
      'ip.src': ['1.1.1.1'], 'ip.dst': ['8.8.8.8'],
      'udp.srcport': ['54322'], 'udp.dstport': ['53'],
      'dns.flags.response': ['False'], 'dns.qry.name': ['example.com'],
    }))
    expect(q.info).toContain('query')
    const [r] = parsePackets(flatFrame({
      'frame.number': ['2'], 'frame.time_relative': ['0.02'], 'frame.len': ['81'],
      'frame.protocols': ['eth:ethertype:ip:udp:dns'],
      'ip.src': ['8.8.8.8'], 'ip.dst': ['1.1.1.1'],
      'udp.srcport': ['53'], 'udp.dstport': ['54322'],
      'dns.flags.response': ['True'], 'dns.qry.name': ['example.com'],
    }))
    expect(r.info).toContain('response')
  })

  it('http 字段平铺时正常解析 method/uri/code/time', () => {
    const [get] = parsePackets(flatFrame({
      'frame.number': ['4'], 'frame.time_relative': ['0.045'], 'frame.len': ['113'],
      'frame.protocols': ['eth:ethertype:ip:tcp:http'],
      'ip.src': ['1.1.1.1'], 'ip.dst': ['2.2.2.2'],
      'tcp.srcport': ['54321'], 'tcp.dstport': ['80'],
      'http.request.method': ['GET'], 'http.request.uri': ['/'],
      'http.request.line': ['Host: example.com\r\n', 'User-Agent: pUI-test\r\n'],
    }))
    expect(get.httpMethod).toBe('GET')
    expect(get.httpUri).toBe('/')
    expect(get.info).toContain('GET')
    const [ok] = parsePackets(flatFrame({
      'frame.number': ['6'], 'frame.time_relative': ['0.18'], 'frame.len': ['150'],
      'frame.protocols': ['eth:ethertype:ip:tcp:http'],
      'ip.src': ['2.2.2.2'], 'ip.dst': ['1.1.1.1'],
      'tcp.srcport': ['80'], 'tcp.dstport': ['54321'],
      'http.response.code': ['200'], 'http.time': ['0.135'],
      'http.response.line': ['HTTP/1.1 200 OK'],
    }))
    expect(ok.httpCode).toBe('200')
    expect(ok.httpTime).toBeCloseTo(0.135)
    expect(ok.info).toContain('200')
  })

  it('ipv6 平铺字段回退正确', () => {
    const [p] = parsePackets(flatFrame({
      'frame.number': ['1'], 'frame.time_relative': ['0'], 'frame.len': ['74'],
      'frame.protocols': ['eth:ethertype:ipv6:tcp'],
      'ipv6.src': ['2001:db8::1'], 'ipv6.dst': ['2001:db8::2'],
      'tcp.srcport': ['54321'], 'tcp.dstport': ['443'],
    }))
    expect(p.srcIp).toBe('2001:db8::1')
    expect(p.dstIp).toBe('2001:db8::2')
  })

  it('tls.handshake.type 平铺字段解析', () => {
    const [p] = parsePackets(flatFrame({
      'frame.number': ['3'], 'frame.time_relative': ['0.05'], 'frame.len': ['317'],
      'frame.protocols': ['eth:ethertype:ip:tcp:tls'],
      'ip.src': ['1.1.1.1'], 'ip.dst': ['2.2.2.2'],
      'tcp.srcport': ['54321'], 'tcp.dstport': ['443'],
      'tls.handshake.type': ['1'],
    }))
    expect(p.tlsType).toBe('1')
    expect(p.proto).toBe('tls')
  })

  it('M6 第二批:SSH/RDP/VNC/SMB 平铺字段投影', () => {
    const [ssh] = parsePackets(flatFrame({
      'frame.number': ['1'], 'frame.time_relative': ['0'], 'frame.len': ['66'],
      'frame.protocols': ['eth:ethertype:ip:tcp:ssh'],
      'ssh.protocol': ['SSH-2.0-OpenSSH_9.6'], 'ssh.connection_type_name': ['session'],
    }))
    expect(ssh.sshProtocol).toBe('SSH-2.0-OpenSSH_9.6')
    expect(ssh.sshChannelType).toBe('session')
    const [rdp] = parsePackets(flatFrame({
      'frame.number': ['2'], 'frame.time_relative': ['0.01'], 'frame.len': ['100'],
      'frame.protocols': ['eth:ethertype:ip:tcp:rdp'],
      'rdp.negReq.requestedProtocols': ['0x00000003'], 'rdp.client.name': ['DEMO-PC'],
    }))
    expect(rdp.rdpNegProtocols).toBe('0x00000003')
    expect(rdp.rdpClientName).toBe('DEMO-PC')
    const [vnc] = parsePackets(flatFrame({
      'frame.number': ['3'], 'frame.time_relative': ['0.02'], 'frame.len': ['50'],
      'frame.protocols': ['eth:ethertype:ip:tcp:vnc'],
      'vnc.server_proto_ver': ['003.008'],
    }))
    expect(vnc.vncProtoVer).toBe('003.008')
    const [resp] = parsePackets(flatFrame({
      'frame.number': ['4'], 'frame.time_relative': ['0.03'], 'frame.len': ['130'],
      'frame.protocols': ['eth:ethertype:ip:tcp:smb2'],
      'smb2.cmd': ['3'], 'smb2.flags.response': ['True'], 'smb2.tree': ['\\\\DEMO\\share'],
    }))
    expect(resp.smb2Cmd).toBe('3')
    expect(resp.smb2Response).toBe(true)
    expect(resp.smb2Tree).toBe('\\\\DEMO\\share')
  })

  it('M6 第二批:smb2.flags.response 三态(True/1→true,False/0→false,缺失→undefined)', () => {
    // 字段存在但为请求 → false(与"字段缺失 undefined"是两种语义,分析器据此区分方向)
    const mk = (n: number, resp?: string) => parsePackets(flatFrame({
      'frame.number': [String(n)], 'frame.time_relative': ['0'], 'frame.len': ['120'],
      'frame.protocols': ['eth:ethertype:ip:tcp:smb2'],
      'smb2.cmd': ['0'],
      ...(resp == null ? {} : { 'smb2.flags.response': [resp] }),
    }))[0]
    expect(mk(1, 'True').smb2Response).toBe(true)
    expect(mk(2, '1').smb2Response).toBe(true)
    expect(mk(3, 'False').smb2Response).toBe(false)
    expect(mk(4, '0').smb2Response).toBe(false)
    expect(mk(5).smb2Response).toBeUndefined()
    // 完全无新字段的帧:全部 undefined(不臆造)
    const [none] = parsePackets(flatFrame({
      'frame.number': ['6'], 'frame.time_relative': ['0'], 'frame.len': ['60'],
      'frame.protocols': ['eth:ethertype:ip:tcp'],
    }))
    expect(none.sshProtocol).toBeUndefined()
    expect(none.sshChannelType).toBeUndefined()
    expect(none.rdpNegProtocols).toBeUndefined()
    expect(none.rdpClientName).toBeUndefined()
    expect(none.vncProtoVer).toBeUndefined()
    expect(none.smb2Cmd).toBeUndefined()
    expect(none.smb2Tree).toBeUndefined()
  })
})
