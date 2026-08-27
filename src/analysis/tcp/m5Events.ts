import type { Packet } from '../../model/types'

/**
 * M5 事件扩展(plan M5 第一块):零窗口 / 窗口耗尽 / RST / SYN 重传。
 *
 * 与 M3 事件引擎刻意解耦:
 * - 独立文件、独立函数,可逐项开关(计划要求"每项可独立关闭");
 * - 只消费 Packet 平面字段(tcpFlags/tcpWindow),不依赖 M2 序列空间 ——
 *   中途抓包、无法排序的输入同样可用(检测语义本身不依赖排序);
 * - 观察与推断分离红线与 M3 一致:陈述单观察点事实,不断言对端状态。
 *
 * 需要 tcp.window_size 字段(M5 新增契约字段);字段缺失时直接返回空 ——
 * 缺字段不做推测,与"byteCount 缺失显示 unknown 不显示 0"同一原则。
 */

/** M5 事件类型:与 M3 三类事件平行,不共用 kind 空间 */
export type M5EventKind = 'zero-window' | 'full-window' | 'rst' | 'syn-retransmission'

export type M5Severity = 'low' | 'medium' | 'high'

/** 与 M3 TcpEvent 同构的观察/推断/限制三层结构(UI 可复用现有渲染) */
export interface M5Event {
  kind: M5EventKind
  direction: 'c2s' | 's2c'
  startTime: number
  endTime: number
  severity: M5Severity
  /** 事件首个报文(零窗口=通告包;RST=RST 包;SYN 重传=首个 SYN) */
  startPacket: number
  /** 事件收束报文(零窗口重开/ SYN-ACK 到达);未收束为 undefined */
  endPacket?: number
  /** 零窗口重开/确认到达的报文 */
  reopenPacket?: number
  synAckPacket?: number
  retransPackets?: number[]
  advertisedWindow?: number
  unackedBytes?: number
  durationSeconds?: number
  observations: Array<{ statement: string; packetNumber: number }>
  inference: { statement: string; confidence: 'low' | 'medium' | 'high' }
  limitations: string[]
}

const SINGLE_POINT = '单观察点抓包:仅能确认本地观察到的通告/到达情况,无法确认对端进程或系统状态'

const F_SYN = 0x02
const F_ACK = 0x10
const F_RST = 0x04

function flagsOf(p: Packet): number {
  const n = Number.parseInt(p.tcpFlags ?? '', 16)
  return Number.isNaN(n) ? 0 : n
}

/** 按时间稳定的排序键(检测输出确定性) */
function timeOrder(a: Packet, b: Packet): number {
  return a.time - b.time || a.number - b.number
}

/** 方向:无流上下文时的近似 —— 知名端口(<1024)侧为服务端;相等/缺失时低端口侧为服务端。
 *  (客户端临时端口通常 >1024,该近似在无 M2 facts 时足够稳定) */
function directionOf(p: Packet): 'c2s' | 's2c' {
  if (p.srcPort != null && p.dstPort != null) return p.dstPort < p.srcPort ? 'c2s' : 's2c'
  return 'c2s'
}

// ---------------------------------------------------------------------------
// 零窗口:接收方通告 window=0(缓冲区满),直到窗口重开
// ---------------------------------------------------------------------------

/**
 * 零窗口事件:纯 ACK 报文上 tcp.window_size === 0 视为一次零窗口通告。
 * 连续的 0 通告合并为一个事件,窗口重开(>0)或抓包结束收束。
 */
export function detectZeroWindowEvents(packets: Packet[]): M5Event[] {
  const ordered = [...packets].sort(timeOrder)
  const events: M5Event[] = []
  let open: { start: Packet; count: number } | null = null

  const close = (reopen: Packet | undefined): void => {
    if (!open) return
    const end = reopen ?? ordered[ordered.length - 1] ?? open.start
    const duration = Math.max(0, end.time - open.start.time)
    events.push({
      kind: 'zero-window',
      direction: directionOf(open.start),
      startTime: open.start.time,
      endTime: end.time,
      severity: reopen ? 'medium' : 'high', // 未重开持续到抓包结束 → 更高严重度
      startPacket: open.start.number,
      endPacket: end.number,
      reopenPacket: reopen?.number,
      durationSeconds: duration,
      observations: [
        {
          statement: `该纯 ACK 报文通告接收窗口为 0(接收缓冲区已满),此前/期间共观察到 ${open.count} 个零窗口通告`,
          packetNumber: open.start.number,
        },
      ],
      inference: {
        statement:
          '接收方在此时间段内通告零窗口:发送方无法继续发送数据。这是流量控制机制的正常行为,零窗口本身不指示故障;但长时间未重开值得关注',
        confidence: 'high',
      },
      limitations: [SINGLE_POINT, '窗口重开依赖后续 ACK:抓包在重开前结束则无法判断零窗口持续了多久'],
    })
    open = null
  }

  for (const p of ordered) {
    const f = flagsOf(p)
    // 只看纯 ACK(无载荷、无 SYN/FIN/RST):数据报文的窗口字段同样反映通告,
    // 但零窗口的「持续期」语义以 ACK 流为准,避免与 M3 数据事件重叠
    const isPureAck = (f & (F_SYN | F_RST)) === 0 && (p.tcpLen ?? 0) === 0
    if (!isPureAck) continue
    if (p.tcpWindow === undefined) continue // 字段缺失 ≠ 0
    if (p.tcpWindow === 0) {
      if (open) open.count++
      else open = { start: p, count: 1 }
    } else if (open) {
      close(p)
    }
  }
  close(undefined)

  // 事件仍按时间升序(与 M3 的未恢复优先不同:这里同 kind 无需跨事件排序)
  return events.sort((a, b) => a.startTime - b.startTime)
}

// ---------------------------------------------------------------------------
// 窗口耗尽:发送在途未确认字节逼近对端通告窗口(发送停滞的窗口侧解释)
// ---------------------------------------------------------------------------

/** 在途未确认字节的近似上限(单观察点):最高已发送 seq+len - 累计 ACK */
export function detectFullWindowEvents(packets: Packet[]): M5Event[] {
  const ordered = [...packets].sort(timeOrder)
  const events: M5Event[] = []
  // 逐方向跟踪:发送方累计 ACK 与最高已发送字节沿;通告方取反向报文的 window
  const st = {
    c2s: { ack: null as number | null, high: -1, win: Infinity, winPkt: null as Packet | null },
    s2c: { ack: null as number | null, high: -1, win: Infinity, winPkt: null as Packet | null },
  }

  for (const p of ordered) {
    const f = flagsOf(p)
    const dir = directionOf(p)
    const opp = dir === 'c2s' ? 's2c' : 'c2s'
    // 本方向报文推进"已发送字节沿"
    if (p.tcpLen != null && p.tcpLen > 0 && p.tcpSeq != null && (f & F_RST) === 0) {
      const end = (p.tcpSeq + p.tcpLen) >>> 0
      if (end > st[dir].high) st[dir].high = end
    }
    // 反方向报文携带对本方向的确认与窗口通告
    if (p.tcpAck != null) st[opp].ack = p.tcpAck
    if (p.tcpWindow != null && (f & F_RST) === 0) {
      st[opp].win = p.tcpWindow
      st[opp].winPkt = p
      // 在途未确认字节超出通告窗口右沿 → 窗口耗尽(首次通告即检查,不要求收缩)
      const ack = st[opp].ack
      if (ack != null && st[opp].high > ack + p.tcpWindow && st[opp].high - ack >= 100) {
        const unacked = st[opp].high - ack
        events.push({
          kind: 'full-window',
          direction: opp,
          startTime: p.time,
          endTime: p.time,
          severity: 'medium',
          startPacket: p.number,
          advertisedWindow: p.tcpWindow,
          unackedBytes: unacked,
          observations: [
            {
              statement: `该报文把接收窗口收缩到 ${p.tcpWindow} 字节,而发送方仍有约 ${unacked} 字节未被确认(超出窗口右沿)`,
              packetNumber: p.number,
            },
          ],
          inference: {
            statement:
              '发送方的在途未确认字节已达到/超过对端通告的接收窗口:后续发送将被窗口机制暂停,直到窗口前进。这是发送停滞的窗口侧解释',
            confidence: 'medium',
          },
          limitations: [SINGLE_POINT, '在途字节按"最高已发送 - 累计 ACK"近似,含重传字节,实际有效在途量可能更小'],
        })
      }
    }
  }
  return events
}

// ---------------------------------------------------------------------------
// RST:连接被重置
// ---------------------------------------------------------------------------

const RST_LIMITATIONS = (midstream: boolean): string[] => [
  SINGLE_POINT,
  'RST 的来源无法从单观察点区分:对端主动关闭/进程崩溃、中间设备注入、防火墙拒绝都会表现为 RST' +
    (midstream ? ';本抓包未见完整握手(中途抓包),连接建立过程的前提信息缺失' : ''),
]

export function detectRstEvents(packets: Packet[]): M5Event[] {
  const ordered = [...packets].sort(timeOrder)
  const events: M5Event[] = []
  let sawSyn = false
  for (const p of ordered) {
    const f = flagsOf(p)
    if (f & F_SYN) sawSyn = true
    if ((f & F_RST) === 0) continue
    const midstream = !sawSyn
    events.push({
      kind: 'rst',
      direction: directionOf(p),
      startTime: p.time,
      endTime: p.time,
      severity: 'medium',
      startPacket: p.number,
      observations: [
        {
          statement: `该报文置位 RST${f & F_ACK ? '(带 ACK)' : ''},连接被重置;此后同流报文不再属于正常数据交换`,
          packetNumber: p.number,
        },
      ],
      inference: {
        statement: '观察到连接被 RST 终止。RST 表明某一端(或中间设备)立即放弃该连接;具体由哪一侧发起、为何发起无法从单观察点确认',
        confidence: 'medium',
      },
      limitations: RST_LIMITATIONS(midstream),
    })
  }
  return events
}

// ---------------------------------------------------------------------------
// SYN 重传:连接建立困难(无响应/丢包/静默丢弃)
// ---------------------------------------------------------------------------

export function detectSynRetransmissionEvents(packets: Packet[]): M5Event[] {
  const ordered = [...packets].sort(timeOrder)
  const events: M5Event[] = []
  interface Attempt {
    key: string
    seq: number
    first: Packet
    retx: number[]
    synAck?: Packet
  }
  // 同一端点对可能有多次连接尝试(不同 seq / 已建立后的新尝试),按数组保留
  const attemptsByFlow = new Map<string, Attempt[]>()

  const pending = (key: string, seq: number): Attempt | undefined => {
    const arr = attemptsByFlow.get(key)
    if (!arr) return undefined
    // 最近一次未收 SYN-ACK 且同 seq 的尝试(同 seq 才算重传;新 seq 是新尝试)
    for (let i = arr.length - 1; i >= 0; i--) {
      const a = arr[i]
      if (a.seq === seq && !a.synAck) return a
      if (a.seq !== seq) return undefined
    }
    return undefined
  }

  /** seq 缺失时的退化匹配:同流最近一次未收 SYN-ACK 的尝试 */
  const lastPending = (key: string): Attempt | undefined => {
    const arr = attemptsByFlow.get(key)
    if (!arr || arr.length === 0) return undefined
    const a = arr[arr.length - 1]
    return a.synAck ? undefined : a
  }

  for (const p of ordered) {
    const f = flagsOf(p)
    const isSynOnly = (f & F_SYN) !== 0 && (f & F_ACK) === 0 && (p.tcpLen ?? 0) === 0
    const isSynAck = (f & F_SYN) !== 0 && (f & F_ACK) !== 0
    const key = `${p.srcIp}:${p.srcPort}>${p.dstIp}:${p.dstPort}`

    if (isSynOnly) {
      // seq 可用:严格按 seq 分组(新 seq = 新尝试);seq 缺失(残缺解析/极旧抓包):
      // 退化为"同流最近未决尝试"——同端点对重复 SYN 本身就是重传或再次尝试
      const cur = p.tcpSeq != null ? pending(key, p.tcpSeq) : lastPending(key)
      if (cur) {
        cur.retx.push(p.number)
      } else {
        attemptsByFlow.set(key, [...(attemptsByFlow.get(key) ?? []), { key, seq: p.tcpSeq ?? 0, first: p, retx: [] }])
      }
    } else if (isSynAck) {
      // 反方向的 SYN-ACK 收编该端点对最近的未决尝试
      const revKey = `${p.dstIp}:${p.dstPort}>${p.srcIp}:${p.srcPort}`
      const arr = attemptsByFlow.get(revKey) ?? []
      for (let i = arr.length - 1; i >= 0; i--) {
        if (!arr[i].synAck) {
          arr[i].synAck = p
          break
        }
      }
    }
  }

  for (const arr of attemptsByFlow.values()) {
    for (const a of arr) {
      if (a.retx.length === 0) continue // 单次 SYN 无重传:连接尝试正常发起,不构成事件
      const last = ordered.find((q) => q.number === a.retx[a.retx.length - 1])
      events.push({
        kind: 'syn-retransmission',
        direction: directionOf(a.first),
        startTime: a.first.time,
        endTime: (last ?? a.first).time,
        severity: a.synAck ? 'low' : 'medium',
        startPacket: a.first.number,
        endPacket: last?.number,
        synAckPacket: a.synAck?.number,
        retransPackets: a.retx,
        observations: [
          {
            statement: `同一连接尝试的 SYN 重发了 ${a.retx.length} 次(#${a.retx.join(', #')})${a.synAck ? `,最终收到 SYN-ACK(#${a.synAck.number})` : ',抓包范围内未收到 SYN-ACK'}`,
            packetNumber: a.first.number,
          },
        ],
        inference: {
          statement: a.synAck
            ? 'SYN 重传后连接最终建立:首次 SYN 或其 ACK 疑似未按时到达,但最终恢复正常'
            : '连接建立阶段反复重传 SYN 且未见响应:服务无响应、网络丢包或中间设备静默丢弃都可能,单观察点无法区分',
          confidence: a.synAck ? 'medium' : 'low',
        },
        limitations: [
          SINGLE_POINT,
          a.synAck
            ? '已恢复的连接建立延迟通常无需处置'
            : '未收到 SYN-ACK 不能断定服务不可用:响应可能发生在抓包窗口之外,或被防火墙静默丢弃',
        ],
      })
    }
  }
  return events.sort((x, y) => x.startTime - y.startTime)
}
