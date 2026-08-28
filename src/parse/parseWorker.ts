import { parsePackets } from './parsePackets'

/**
 * 报文解析 Worker(M5 性能项):tshark JSON 的 JSON.parse + 字段投影是纯 CPU 工作,
 * 10 万包在主线程会秒级卡死 UI。全部计算搬到这里,主线程只等一条消息。
 *
 * 协议:进 { jsonText },出 { packets } 或 { error }。有界(单请求)。
 * Worker 内同样受 MAX_PARSE_JSON 守卫(parsePackets 自带),超大输入在两侧都会抛错。
 */

export interface ParseRequest {
  kind: 'parse'
  jsonText: string
}

export interface ParseOk {
  kind: 'ok'
  packets: import('../model/types').Packet[]
}

export interface ParseErr {
  kind: 'err'
  error: string
}

export type ParseResponse = ParseOk | ParseErr

self.onmessage = (ev: MessageEvent<ParseRequest>): void => {
  const msg = ev.data
  if (msg?.kind !== 'parse') return
  try {
    const packets = parsePackets(msg.jsonText)
    const resp: ParseResponse = { kind: 'ok', packets }
    ;(self as unknown as Worker).postMessage(resp)
  } catch (e) {
    const resp: ParseResponse = { kind: 'err', error: e instanceof Error ? e.message : String(e) }
    ;(self as unknown as Worker).postMessage(resp)
  }
}
