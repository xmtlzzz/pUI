import type { Packet } from '../../model/types'
import { seqDiff } from './seq'
import type { StreamAnalysisFacts, StreamDirection } from './streamAnalysis'

/**
 * 三类 MVP 事件(plan M3)。窗口、连接建立、RST 等属 M5,不在此实现。
 *
 * 分类依据一律是 M2 还原出的序列空间事实,**不是** tshark 的 analysis 标签 ——
 * 实测乱序补齐会被 tshark 打上 retransmission,若照标签归类就会把"乱序"误判成"丢包"。
 * 标签只作为 Observation 如实记录。
 */
export type TcpEventKind =
  /** 出现序列空间缺口,伴随 ACK 停滞/Dup ACK/SACK,并由重传补齐 */
  | 'possible-loss-or-delay'
  /** 数据到达顺序与序列号不同,缺口由迟到的原始段补齐,未观察到重发 */
  | 'reordering'
  /** 重发了已被确认的数据,序列空间无有意义缺口(通常是 ACK 未被发送端看到) */
  | 'possible-ack-loss-or-spurious'

export type Severity = 'low' | 'medium' | 'high'
export type Confidence = 'low' | 'medium' | 'high'

/** 可直接由报文字段验证的事实 */
export interface Observation {
  id: string
  statement: string
  packetNumber: number
  /** 支撑该陈述的字段名与取值,便于 UI 展示"证据在哪" */
  field?: string
  value?: string | number
}

/** 规则推断。必须引用至少一条 Observation —— 无证据的结论不允许存在 */
export interface Inference {
  statement: string
  confidence: Confidence
  evidenceRefs: Array<{ observationId: string; packetNumber: number }>
}

export interface TcpEvent {
  /** 稳定 id:仅由流/方向/类型/序列号导出,与输入顺序、数组下标无关 */
  id: string
  kind: TcpEventKind
  direction: StreamDirection
  startTime: number
  endTime: number
  severity: Severity
  /** 缺口是否已被补齐(伪重传类无缺口,视为已恢复) */
  recovered: boolean
  /** 证据完整度评分,用于排序;越高说明证据链越完整 */
  evidenceScore: number
  gap?: { start: number; end: number; byteCount: number }
  /** 越过缺口到达、从而暴露缺口的那个段 */
  originalSegmentPacket?: number
  /** 真正重发已发送数据的报文(乱序补齐不算) */
  retransmissionPacket?: number
  /** ACK 前进、缺口恢复的那个报文 */
  recoveryAckPacket?: number
  duplicateAckCount: number
  duplicateAckPackets: number[]
  sackPresent: boolean
  observations: Observation[]
  inference: Inference
  limitations: string[]
}

const SINGLE_POINT_LIMITATION =
  '单观察点抓包:可确认本地观察到的到达情况,但无法定位丢包发生在哪个网络节点,也无法确认对端是否已发出'
const MID_STREAM_LIMITATION = '抓包从连接中途开始(未见完整握手):流起始处的缺失不构成丢包证据,结论置信度下调'
const CAPTURE_DROP_LIMITATION = '无法排除抓包点自身漏包(网卡/ring buffer/镜像口),缺口不等于网络丢包'

/** 事件 id:同一条缺口在任何输入顺序下都得到同一 id */
function eventId(kind: TcpEventKind, dir: StreamDirection, streamId: number | undefined, anchor: number): string {
  return `${streamId ?? 'x'}:${dir}:${kind}:${anchor}`
}

/**
 * 把序列空间事实组织成可点击、可解释的事件(plan M3)。
 *
 * 每个事件串联:原始段 → ACK 停滞 → Dup ACK / SACK → 重传 → 恢复 ACK,
 * 并把每一环都落到具体 packet number,供 UI 下钻(指南第 10、11 节)。
 */
export function detectTcpEvents(facts: StreamAnalysisFacts, packets: Packet[]): TcpEvent[] {
  const byNumber = new Map<number, Packet>()
  for (const p of packets) byNumber.set(p.number, p)
  const ordered = [...packets].sort((a, b) => a.time - b.time || a.number - b.number)

  const baseLimitations = (): string[] => {
    const l = [SINGLE_POINT_LIMITATION, CAPTURE_DROP_LIMITATION]
    if (facts.midStream) l.unshift(MID_STREAM_LIMITATION)
    return l
  }

  const events: TcpEvent[] = []

  // ---- 1) 每个序列空间缺口生成一个事件:丢包/延迟 或 乱序 ----
  for (const gap of facts.gaps) {
    const obs: Observation[] = []
    const mk = (statement: string, packetNumber: number, field?: string, value?: string | number): void => {
      obs.push({ id: `${gap.direction}:${gap.start}:o${obs.length + 1}`, statement, packetNumber, field, value })
    }

    // 缺口本身是第一条观察:mk 已把它记入 obs,无需保留返回值
    mk(
      `序列空间存在缺口 ${gap.start}–${gap.end}(${gap.byteCount} 字节),由该报文越过缺口到达而暴露`,
      gap.firstObservedPacket,
      'tcp.seq_raw',
      gap.start,
    )

    // ACK 停滞与 Dup ACK:统计缺口开放期间、反向发出且累计 ACK 停在缺口起点的报文
    const ackDir: StreamDirection = gap.direction === 'c2s' ? 's2c' : 'c2s'
    const dupAckPackets: number[] = []
    let sackPresent = gap.sackCovered
    for (const p of ordered) {
      if (p.time < gap.firstObservedTime) continue
      if (gap.filledTime != null && p.time > gap.filledTime) break
      const seg = facts.segments.find((s) => s.packetNumber === p.number)
      if (seg?.direction !== ackDir) continue
      // 累计 ACK 停在缺口起点 = 接收端还没等到缺失字节。
      // 逐报文遍历,天然按报文计数一次 —— 不能改成统计 tcp.analysis.duplicate_ack 的取值个数:
      // 平铺模式下单个 dup ACK 报文该字段值是 ["1","1"](实测),按条目数会把计数翻倍。
      if (p.tcpAck != null && seqDiff(p.tcpAck, gap.start) === 0) {
        dupAckPackets.push(p.number)
      }
      if (p.tcpSackBlocks?.length) sackPresent = true
    }
    for (const n of dupAckPackets) {
      const p = byNumber.get(n)
      mk(`累计 ACK 停在 ${gap.start} 未前进(重复确认)`, n, 'tcp.ack_raw', p?.tcpAck ?? gap.start)
    }
    if (sackPresent) {
      const sackPkt = ordered.find(
        (p) => p.tcpSackBlocks?.length && p.time >= gap.firstObservedTime && (gap.filledTime == null || p.time <= gap.filledTime),
      )
      if (sackPkt) {
        mk(
          `SACK 报告缺口之后的数据已到达接收端:${sackPkt.tcpSackBlocks!.map(([l, r]) => `${l}–${r}`).join(', ')}`,
          sackPkt.number,
          'tcp.options.sack_le/re',
          sackPkt.tcpSackBlocks!.map(([l, r]) => `${l}-${r}`).join(','),
        )
      }
    }

    // 填补者是"重发已发送过的数据",还是"迟到的原始段"?这决定丢包 vs 乱序
    const filler = gap.filledByPacket != null ? facts.segments.find((s) => s.packetNumber === gap.filledByPacket) : undefined
    const fillerPkt = gap.filledByPacket != null ? byNumber.get(gap.filledByPacket) : undefined
    // 迟到的原始段带来的全是新字节;真正的重传会与已见数据重叠,或距首次暴露有明显时延
    const isLateArrival =
      filler != null && filler.newBytes === filler.seqLen && (gap.durationSeconds ?? 0) < 0.1 && dupAckPackets.length < 3

    if (fillerPkt?.tcpAnalysis?.length) {
      // 如实记录 tshark 标签(仅作为观察,不参与分类)
      mk(`tshark 对该报文的标注:${fillerPkt.tcpAnalysis.join(', ')}`, fillerPkt.number, 'tcp.analysis.*', fillerPkt.tcpAnalysis.join(','))
    }

    const kind: TcpEventKind = isLateArrival ? 'reordering' : 'possible-loss-or-delay'

    if (gap.filled && !isLateArrival && filler) {
      mk(`缺失数据被重新发送`, gap.filledByPacket!, 'tcp.seq_raw', gap.start)
    }

    // 恢复 ACK:填补之后第一个 ACK 越过缺口终点
    let recoveryAck: number | undefined
    if (gap.filledTime != null) {
      const rec = ordered.find((p) => {
        if (p.time < gap.filledTime!) return false
        const seg = facts.segments.find((s) => s.packetNumber === p.number)
        if (seg?.direction !== ackDir) return false
        return p.tcpAck != null && seqDiff(p.tcpAck, gap.end) >= 0
      })
      if (rec) {
        recoveryAck = rec.number
        mk(`ACK 前进到 ${rec.tcpAck},缺口已恢复`, rec.number, 'tcp.ack_raw', rec.tcpAck!)
      }
    }

    const confidence: Confidence = facts.midStream ? 'low' : sackPresent && dupAckPackets.length > 0 ? 'high' : 'medium'
    const statement =
      kind === 'reordering'
        ? '数据到达顺序与序列号顺序不同,缺口随后由迟到的原始段补齐,未观察到重发 —— 乱序不等于丢包'
        : gap.filled
          ? '观察到数据未按连续序列到达,随后由重传补齐;证据支持"数据未及时到达",但不能据此断定丢包位置'
          : '观察到数据未按连续序列到达,且在抓包范围内始终未被补齐'

    const evidenceScore =
      obs.length + (sackPresent ? 2 : 0) + dupAckPackets.length + (recoveryAck != null ? 1 : 0) + (gap.filled ? 1 : 0)

    events.push({
      id: eventId(kind, gap.direction, facts.streamId, gap.start),
      kind,
      direction: gap.direction,
      startTime: gap.firstObservedTime,
      endTime: gap.filledTime ?? (ordered.length ? ordered[ordered.length - 1].time : gap.firstObservedTime),
      severity: !gap.filled ? 'high' : kind === 'reordering' ? 'low' : 'medium',
      recovered: gap.filled,
      evidenceScore,
      gap: { start: gap.start, end: gap.end, byteCount: gap.byteCount },
      originalSegmentPacket: gap.firstObservedPacket,
      retransmissionPacket: kind === 'reordering' ? undefined : gap.filledByPacket,
      recoveryAckPacket: recoveryAck,
      duplicateAckCount: dupAckPackets.length,
      duplicateAckPackets: dupAckPackets,
      sackPresent,
      observations: obs,
      inference: {
        statement,
        confidence,
        evidenceRefs: obs.map((o) => ({ observationId: o.id, packetNumber: o.packetNumber })),
      },
      limitations: baseLimitations(),
    })
  }

  // ---- 2) 无缺口的重复/重叠段:伪重传 / 可能 ACK 丢失 ----
  // 这类段说明数据其实已经到过,只是发送端没看到确认 —— 绝不能算数据丢失
  const gapCovered = (seq: number): boolean =>
    facts.gaps.some((g) => seqDiff(seq, g.start) >= 0 && seqDiff(seq, g.end) < 0)

  for (const seg of facts.segments) {
    if (seg.classification !== 'pure-duplicate' && seg.classification !== 'overlapping-retransmit') continue
    if (gapCovered(seg.seq)) continue // 已由上面的缺口事件覆盖
    const p = byNumber.get(seg.packetNumber)
    const obs: Observation[] = []
    const oid = `${seg.direction}:${seg.seq}:o`
    obs.push({
      id: `${oid}1`,
      statement: `该报文重发的字节此前已在序列空间中观察到(新增字节 ${seg.newBytes} / ${seg.seqLen})`,
      packetNumber: seg.packetNumber,
      field: 'tcp.seq_raw',
      value: seg.seq,
    })
    obs.push({
      id: `${oid}2`,
      statement: '该重发对应的序列区间没有有意义的缺口',
      packetNumber: seg.packetNumber,
      field: 'tcp.len',
      value: seg.payloadLen,
    })
    if (p?.tcpAnalysis?.length) {
      obs.push({
        id: `${oid}3`,
        statement: `tshark 对该报文的标注:${p.tcpAnalysis.join(', ')}`,
        packetNumber: seg.packetNumber,
        field: 'tcp.analysis.*',
        value: p.tcpAnalysis.join(','),
      })
    }
    // 恢复 ACK:重发之后对端的确认(通常仍停在原处,说明数据早已收到)
    const ackDir: StreamDirection = seg.direction === 'c2s' ? 's2c' : 'c2s'
    const rec = ordered.find((q) => {
      if (q.time < seg.time) return false
      const s = facts.segments.find((x) => x.packetNumber === q.number)
      return s?.direction === ackDir && q.tcpAck != null
    })

    events.push({
      id: eventId('possible-ack-loss-or-spurious', seg.direction, facts.streamId, seg.seq),
      kind: 'possible-ack-loss-or-spurious',
      direction: seg.direction,
      startTime: seg.time,
      endTime: rec?.time ?? seg.time,
      severity: 'low',
      recovered: true, // 数据本就已到达,无需恢复
      evidenceScore: obs.length,
      gap: undefined,
      originalSegmentPacket: undefined,
      retransmissionPacket: seg.packetNumber,
      recoveryAckPacket: rec?.number,
      duplicateAckCount: 0,
      duplicateAckPackets: [],
      sackPresent: false,
      observations: obs,
      inference: {
        statement:
          '发送端重发了接收端已经收到的数据,序列空间中没有对应缺口。更可能是确认未被发送端及时看到(ACK 丢失/延迟),而非数据丢失',
        confidence: facts.midStream ? 'low' : 'medium',
        evidenceRefs: obs.map((o) => ({ observationId: o.id, packetNumber: o.packetNumber })),
      },
      limitations: baseLimitations(),
    })
  }

  // 排序(plan M3):未恢复优先 → 证据完整度 → 持续时长;末位用 id 兜底保证完全确定
  return events.sort((a, b) => {
    if (a.recovered !== b.recovered) return a.recovered ? 1 : -1
    if (a.evidenceScore !== b.evidenceScore) return b.evidenceScore - a.evidenceScore
    const da = a.endTime - a.startTime
    const db = b.endTime - b.startTime
    if (da !== db) return db - da
    return a.id.localeCompare(b.id)
  })
}
