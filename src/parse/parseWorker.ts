import { parsePackets } from './parsePackets'
import type { Packet } from '../model/types'

/**
 * 报文解析 Worker(M5 性能项):tshark JSON 的 JSON.parse + 字段投影是纯 CPU 工作,
 * 10 万包在主线程会秒级卡死 UI。全部计算搬到这里,主线程只等一条消息。
 *
 * 协议:进 { kind:'parse', jsonText, requestId },出 { kind:'ok'|'err', requestId, ... }。
 * requestId 必须原样回传 —— 主线程(parseAsync)靠它关联并发请求,缺失会让
 * 该 Worker 上的首个并发请求永久挂起(曾因未回传导致 pending 关联失败)。
 * Worker 内同样受 MAX_PARSE_JSON 守卫(parsePackets 自带),超大输入在两侧都会抛错。
 */

export interface ParseRequest {
  kind: 'parse'
  jsonText: string
  requestId: number
}

export interface ParseOk {
  kind: 'ok'
  requestId: number
  packets: Packet[]
}

export interface ParseErr {
  kind: 'err'
  requestId: number
  error: string
}

export type ParseResponse = ParseOk | ParseErr

/** 处理一条解析请求,把结果经 post 回传(requestId 原样带回)。
 *  纯函数:Worker 顶层注册与本单测共用同一入口,回传协议不再依赖假 Worker 自证。 */
export function handleParseMessage(msg: unknown, post: (resp: ParseResponse) => void): void {
  if (!msg || typeof msg !== 'object' || (msg as { kind?: unknown }).kind !== 'parse') return
  const req = msg as ParseRequest
  try {
    const packets = parsePackets(req.jsonText)
    post({ kind: 'ok', requestId: req.requestId, packets })
  } catch (e) {
    post({ kind: 'err', requestId: req.requestId, error: e instanceof Error ? e.message : String(e) })
  }
}

// 仅 Worker 上下文注册消息入口(node 测试环境无 self,直接 import 也不炸)
if (typeof self !== 'undefined') {
  self.onmessage = (ev: MessageEvent<ParseRequest>): void => {
    handleParseMessage(ev.data, (resp) => {
      ;(self as unknown as Worker).postMessage(resp)
    })
  }
}
