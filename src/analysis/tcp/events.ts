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

/**
 * 缺口被填补时的启发信号。分类器只依据这三个信号做判断,
 * 且原样记录到事件上 —— Why 面板(指南第 10 节)必须能把"为什么这么分类"
 * 还原成用户可见的数字,而不是藏在代码里的魔法数字。
 */
export interface FillSignals {
  /** 填补段带来的全部是新字节(迟到的原始段),还是与已见数据重叠(真正的重发) */
  fillerCarriesOnlyNewBytes: boolean
  /** 缺口从暴露到被填补的时长(秒) */
  durationSeconds: number
  /** 缺口开放期间累计 ACK 停在缺口起点的报文数(重复确认次数) */
  duplicateAckCount: number
}

/** 分类结果:事件类型 + 置信度 + 一句话理由(理由必须可被 Why 面板直接展示) */
export interface FillClassification {
  kind: TcpEventKind
  confidence: Confidence
  rationale: string
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
  /** 缺口类事件:分类所依据的原始信号(供 Why 面板渲染;伪重传类无此字段) */
  classificationSignals?: FillSignals
  /** 分类理由:一句话说明依据了哪些信号、为何得出该 kind(不断言确定性丢包) */
  rationale?: string
}

const SINGLE_POINT_LIMITATION =
  '单观察点抓包:可确认本地观察到的到达情况,但无法定位丢包发生在哪个网络节点,也无法确认对端是否已发出'
const MID_STREAM_LIMITATION = '抓包从连接中途开始(未见完整握手):流起始处的缺失不构成丢包证据,结论置信度下调'
const CAPTURE_DROP_LIMITATION = '无法排除抓包点自身漏包(网卡/ring buffer/镜像口),缺口不等于网络丢包'

/**
 * 模糊区限制:乱序与丢包在单观察点下可能表现完全相同 ——
 * 只有"填补段全为新字节 + 短时长 + 少量/无重复确认"三者同时成立时,
 * 才允许把事件归为乱序;信号不全时置信度必须降级并附加本说明。
 */
const AMBIGUOUS_CLASSIFICATION_LIMITATION =
  '该分类基于启发信号(时长/重复 ACK 数/填补字节新旧),单观察点下乱序与丢包可能表现相同'

/**
 * 填补分类器:把「丢包还是乱序」的判断从隐式布尔合取提升为显式规则表。
 *
 * 判据是 TCP 的机制,不是经验阈值:
 * - 迟到的原始段带来的全是新字节,且接收端无需触发快重传(0–2 个重复 ACK)
 *   就能等它到达 —— 这是纯乱序的形态;
 * - 3 个重复 ACK 正是 RFC 快重传的触发条件,出现 ≥3 说明接收端确实在催缺失数据;
 * - RTO(通常 ≥200ms)量级的静默期后重传,说明发送端已超时放弃等待,
 *   是真丢失后超时重传的典型形态;
 * - 填补段与已见字节重叠 = 同一段字节被发了两次,本身就是重发证据。
 *
 * 单观察点永远无法 100% 区分两者,因此除高置信情形外一律保守降级。
 */
export function classifyFill(s: FillSignals): FillClassification {
  // 重叠填补:同一段字节被发送了两次,这是最直接的丢失证据 → 高置信
  if (!s.fillerCarriesOnlyNewBytes) {
    return {
      kind: 'possible-loss-or-delay',
      confidence: 'high',
      rationale: `填补段与此前已见数据重叠(${s.duplicateAckCount} 个重复 ACK、${s.durationSeconds}s):同一段字节被发送了两次,支持"原始段未按时到达后重发"`,
    }
  }
  // 全新字节的填补段 + ≥3 个重复 ACK:3 个重复 ACK 正是快重传触发条件,
  // 接收端明确在催缺失数据 → 走快重传路径,疑似真丢失
  if (s.duplicateAckCount >= 3) {
    return {
      kind: 'possible-loss-or-delay',
      confidence: 'medium',
      rationale: `填补段全为新字节,但缺口开放期间出现 ${s.duplicateAckCount} 个重复 ACK(快重传触发条件),接收端曾持续等待缺失字节`,
    }
  }
  // 全新字节 + RTO 量级时长(≥200ms)且重复 ACK 不足:发送端大概率已超时重传,
  // 静默期说明数据确实长时间未到 → 疑似真丢失
  if (s.durationSeconds >= 0.2) {
    return {
      kind: 'possible-loss-or-delay',
      confidence: 'medium',
      rationale: `填补段全为新字节且间隔 ${s.durationSeconds}s(RTO 量级)、仅 ${s.duplicateAckCount} 个重复 ACK:疑似原始段丢失后由超时重传补齐`,
    }
  }
  // 全新字节 + 短时长(<100ms)+ 重复 ACK <3:迟到的原始段,接收端无需催促即等到 → 纯乱序
  if (s.durationSeconds < 0.1) {
    return {
      kind: 'reordering',
      confidence: 'high',
      rationale: `填补段全为新字节,间隔 ${s.durationSeconds}s(<100ms)且仅 ${s.duplicateAckCount} 个重复 ACK:符合迟到原始段形态,未观察到重发`,
    }
  }
  // 其余(100ms ≤ 时长 <200ms 且重复 ACK <3):模糊区。单观察点无法排除丢包,
  // 归为乱序但置信度压到最低,并强制附带不确定性说明。
  return {
    kind: 'reordering',
    confidence: 'low',
    rationale: `填补段全为新字节,间隔 ${s.durationSeconds}s 处于模糊区且仅 ${s.duplicateAckCount} 个重复 ACK:更可能是迟到原始段,但无法排除该段确曾丢失`,
  }
}

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

  // 性能护栏(VDI 抓包实测冻死主线程的根因):每 gap 的 ACK 停滞扫描若对全量报文
  // 线性遍历、且内嵌 segments.find() 线性查找,复杂度为 O(gaps × n²) —— 重传风暴下
  // 几千 gap × 几万段是百亿级操作。预建两个索引把每 gap 成本压到窗口大小:
  //   segByPacket:packetNumber -> segment(替代内层 find)
  //   timeWindow :ordered 数组上按时间的二分边界(只扫 [firstObservedTime, filledTime] 窗口)
  const segByPacket = new Map<number, StreamAnalysisFacts['segments'][number]>()
  for (const s of facts.segments) segByPacket.set(s.packetNumber, s)
  const times = ordered.map((p) => p.time)
  const lowerBound = (t: number): number => {
    let lo = 0
    let hi = times.length
    while (lo < hi) {
      const mid = (lo + hi) >> 1
      if (times[mid] < t) lo = mid + 1
      else hi = mid
    }
    return lo
  }

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
    // 只扫缺口开放窗口(二分定界);未填补时窗口为 [firstObservedTime, 抓包结束]
    const winStart = lowerBound(gap.firstObservedTime)
    const winEnd = gap.filledTime != null ? lowerBound(gap.filledTime + 1e-9) : ordered.length
    for (let wi = winStart; wi < winEnd; wi++) {
      const p = ordered[wi]
      const seg = segByPacket.get(p.number)
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
      // 同样只扫缺口开放窗口(二分定界)
      let sackPkt: Packet | undefined
      for (let wi = winStart; wi < winEnd; wi++) {
        const p = ordered[wi]
        if (p.tcpSackBlocks?.length) {
          sackPkt = p
          break
        }
      }
      if (sackPkt) {
        mk(
          `SACK 报告缺口之后的数据已到达接收端:${sackPkt.tcpSackBlocks!.map(([l, r]) => `${l}–${r}`).join(', ')}`,
          sackPkt.number,
          'tcp.options.sack_le/re',
          sackPkt.tcpSackBlocks!.map(([l, r]) => `${l}-${r}`).join(','),
        )
      }
    }

    // 填补者是"重发已发送过的数据",还是"迟到的原始段"?这决定丢包 vs 乱序。
    // 判断交给显式分类器(见 classifyFill):信号原样记录在事件上,规则可解释、可复核。
    const filler = gap.filledByPacket != null ? segByPacket.get(gap.filledByPacket) : undefined
    const fillerPkt = gap.filledByPacket != null ? byNumber.get(gap.filledByPacket) : undefined
    const fillClassification = filler
      ? classifyFill({
          fillerCarriesOnlyNewBytes: filler.newBytes === filler.seqLen,
          durationSeconds: gap.durationSeconds ?? 0,
          duplicateAckCount: dupAckPackets.length,
        })
      : undefined
    const isLateArrival = fillClassification?.kind === 'reordering'

    if (fillerPkt?.tcpAnalysis?.length) {
      // 如实记录 tshark 标签(仅作为观察,不参与分类)
      mk(`tshark 对该报文的标注:${fillerPkt.tcpAnalysis.join(', ')}`, fillerPkt.number, 'tcp.analysis.*', fillerPkt.tcpAnalysis.join(','))
    }

    const kind: TcpEventKind = isLateArrival ? 'reordering' : 'possible-loss-or-delay'

    if (gap.filled && !isLateArrival && filler) {
      mk(`缺失数据被重新发送`, gap.filledByPacket!, 'tcp.seq_raw', gap.start)
    }

    // 恢复 ACK:填补之后第一个 ACK 越过缺口终点(从填补时刻的二分位置向后找)
    let recoveryAck: number | undefined
    if (gap.filledTime != null) {
      const recStart = lowerBound(gap.filledTime)
      for (let wi = recStart; wi < ordered.length; wi++) {
        const p = ordered[wi]
        const seg = segByPacket.get(p.number)
        if (seg?.direction !== ackDir) continue
        if (p.tcpAck != null && seqDiff(p.tcpAck, gap.end) >= 0) {
          recoveryAck = p.number
          mk(`ACK 前进到 ${p.tcpAck},缺口已恢复`, p.number, 'tcp.ack_raw', p.tcpAck)
          break
        }
      }
    }

    // 置信度:中途抓包一律封顶 low(流起点不完整,任何分类都缺前提);
    // 否则采用分类器给出的置信度 —— 它已经按"多少个启发信号相互印证"分了级
    const confidence: Confidence = facts.midStream ? 'low' : fillClassification?.confidence ?? 'medium'
    let statement: string
    if (kind === 'reordering') {
      statement =
        confidence === 'low'
          ? '缺口由全新字节的段在模糊区间内补齐:更可能是迟到的原始段(乱序),但单观察点无法排除该段确曾丢失后重传'
          : '数据到达顺序与序列号顺序不同,缺口随后由迟到的原始段补齐,未观察到重发 —— 乱序不等于丢包'
    } else if (gap.filled) {
      statement = '观察到数据未按连续序列到达,随后由重传补齐;证据支持"数据未及时到达",但不能据此断定丢包位置'
    } else {
      statement = '观察到数据未按连续序列到达,且在抓包范围内始终未被补齐'
    }

    const evidenceScore =
      obs.length + (sackPresent ? 2 : 0) + dupAckPackets.length + (recoveryAck != null ? 1 : 0) + (gap.filled ? 1 : 0)

    const limitations = baseLimitations()
    // 低置信度的分类必须把不确定性说透:置信度被压到 low(模糊区,或中途抓包封顶)时,
    // 单观察点下乱序与丢包不可区分,必须显式告知用户。
    if (confidence === 'low') limitations.push(AMBIGUOUS_CLASSIFICATION_LIMITATION)

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
      limitations,
      classificationSignals: filler
        ? {
            fillerCarriesOnlyNewBytes: filler.newBytes === filler.seqLen,
            durationSeconds: gap.durationSeconds ?? 0,
            duplicateAckCount: dupAckPackets.length,
          }
        : undefined,
      rationale: fillClassification?.rationale,
    })
  }

  // ---- 2) 无缺口的重复/重叠段:伪重传 / 可能 ACK 丢失 ----
  // 这类段说明数据其实已经到过,只是发送端没看到确认 —— 绝不能算数据丢失。
  //
  // 守卫(VDI 风暴实测暴露):已被第 1 步缺口事件覆盖的报文(作为缺口的填补者/
  // 重传者)不得再进本分支,否则同一段重发被报成两个事件 —— 实测 100 个缺口
  // 事件外又多出 99 个 spurious 事件。用"已覆盖报文号集合"一次排除,
  // 比事后逐个 seq 落点判断既准确又 O(1)。
  const coveredByGapEvent = new Set<number>()
  for (const g of facts.gaps) {
    if (g.filledByPacket != null) coveredByGapEvent.add(g.filledByPacket)
    coveredByGapEvent.add(g.firstObservedPacket)
  }

  for (const seg of facts.segments) {
    if (seg.classification !== 'pure-duplicate' && seg.classification !== 'overlapping-retransmit') continue
    if (coveredByGapEvent.has(seg.packetNumber)) continue // 已由缺口事件覆盖
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
    // 恢复 ACK:重发之后对端的确认(通常仍停在原处,说明数据早已收到)。
    // 二分定位重发时刻,只向后扫到第一个反向 ACK 为止。
    const ackDir: StreamDirection = seg.direction === 'c2s' ? 's2c' : 'c2s'
    let rec: Packet | undefined
    for (let wi = lowerBound(seg.time); wi < ordered.length; wi++) {
      const q = ordered[wi]
      const s = segByPacket.get(q.number)
      if (s?.direction === ackDir && q.tcpAck != null) {
        rec = q
        break
      }
    }

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
      // 伪重传分支不走 classifyFill(无缺口可填补),但 Why 面板同样需要一句分类理由
      rationale: '重发段的字节此前已全部观察到且序列空间无对应缺口:支持"数据早已到达、确认未及时送达",不支持数据丢失',
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
