import { describe, expect, it } from 'vitest'
import type { Packet } from '../../model/types'
import {
  APPLICATION_ANALYZERS,
  countAppEvents,
  dnsAnalyzer,
  httpAnalyzer,
  runApplicationAnalyzers,
  tlsAnalyzer,
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
      pkt({ number: 4, time: 0.3, proto: 'http', httpCode: '200', httpTime: 0.28 }),
    ]
    const a = runApplicationAnalyzers(packets)
    expect(a.map((e) => e.app)).toEqual(['dns', 'tls', 'http', 'http'])
    expect(JSON.stringify(runApplicationAnalyzers(packets))).toBe(JSON.stringify(a))
  })

  it('插件注册表含第一批三协议;计数器按 app×kind 汇总', () => {
    expect(APPLICATION_ANALYZERS.map((a) => a.id)).toEqual(['http', 'dns', 'tls'])
    const counts = countAppEvents(runApplicationAnalyzers([
      pkt({ number: 1, time: 0, proto: 'http', httpMethod: 'GET', httpUri: '/' }),
      pkt({ number: 2, time: 0.3, proto: 'http', httpCode: '200' }),
      pkt({ number: 3, time: 0, proto: 'dns', dnsQuery: 'x.com', info: 'query' }),
    ]))
    expect(counts).toContainEqual({ app: 'http', kind: 'request', count: 1 })
    expect(counts).toContainEqual({ app: 'http', kind: 'response', count: 1 })
    expect(counts).toContainEqual({ app: 'dns', kind: 'query', count: 1 })
  })
})
