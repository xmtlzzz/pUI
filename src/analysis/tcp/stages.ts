import type { Packet } from '../../model/types'
import type { StreamAnalysisFacts } from './streamAnalysis'
import type { TcpEvent } from './events'
import { seqDiff } from './seq'

/**
 * 故障阶段(EventStage)推导 —— M4 审批强化要求的视图模型基座。
 *
 * 审批要求(2026-08-26,记录于 docs/specs/m4-cases/* 审批记录):
 * 报文交互过程必须有明显的阶段标注,每阶段的起止报文、时长、信息要点在图形上直接可见;
 * 阶段边界必须从引擎输出确定性推导,**不得在组件里手写阶段数组**。
 *
 * 设计:阶段不是第四种独立分析,而是把单个 TcpEvent 的证据链(observations 的时间顺序 +
 * gap 生命周期 + 分类信号)重新投影为「叙事段落」。因此:
 * - 同一输入永远得到同一阶段序列(纯函数);
 * - 每个阶段必须携带 summary(信息要点)与 observationRefs(证据指针)——
 *   只有名字没有内容的阶段不允许存在;
 * - 阶段覆盖事件的时间范围且单调递增,可直接作 GSAP 播放轨道。
 */

/** 一个故障阶段:时间线上的命名段落 */
export interface EventStage {
  /** 阶段名(短,直接渲染在阶段带上),如「缺口显露」「重传回补」 */
  label: string
  /** 信息要点:该阶段发生了什么。必须具体到可读(含关键数值/报文号) */
  summary: string
  /** 该阶段覆盖的报文号(闭区间;单报文阶段 from==to) */
  fromPacket: number
  toPacket: number
  startTime: number
  endTime: number
  /** 该阶段依赖的观察 id 子集(供阶段信息面板引用真实证据) */
  observationRefs: string[]
}

const byNumber = (packets: Packet[]): Map<number, Packet> => {
  const m = new Map<number, Packet>()
  for (const p of packets) m.set(p.number, p)
  return m
}

/**
 * 从单个事件的证据链推导故障阶段。
 * event 为 undefined(无可对照事件)时返回空数组。
 */
export function deriveStages(
  event: TcpEvent | undefined,
  facts: StreamAnalysisFacts,
  packets: Packet[],
): EventStage[] {
  if (!event || !event.gap && !event.retransmissionPacket && event.observations.length === 0) {
    return []
  }
  const nums = byNumber(packets)

  // ---- 伪重传/疑似 ACK 丢失类:无缺口,按「正常发确 → 静默窗 → 冗余重传 → 确认无变化」划分 ----
  if (event.kind === 'possible-ack-loss-or-spurious') {
    return spuriousStages(event, packets, nums)
  }

  // ---- 缺口类(loss/delay 与 reordering):按证据链节点划分 ----
  return gapStages(event, facts, nums)
}

/** 缺口类事件阶段:正常传输 → 缺口显露 → (重复确认与 SACK 增长)→ 重传回补/迟到补齐 → 恢复 */
function gapStages(event: TcpEvent, facts: StreamAnalysisFacts, nums: Map<number, Packet>): EventStage[] {
  const obs = event.observations
  const findObs = (re: RegExp): { packetNumber: number; time: number; id: string; text: string } | undefined => {
    for (const o of obs) {
      if (re.test(o.statement)) {
        const p = nums.get(o.packetNumber)
        if (p) return { packetNumber: o.packetNumber, time: p.time, id: o.id, text: o.statement }
      }
    }
    return undefined
  }

  // 事件开始前的正常传输段:事件起点之前的同方向数据段及其确认
  // (从 observations 里"越过缺口到达"的那条拿事件锚点)
  const exposeObs =
    findObs(/越过缺口|暴露/) ??
    (event.originalSegmentPacket != null
      ? (() => {
          const p = nums.get(event.originalSegmentPacket)
          return p ? { packetNumber: p.number, time: p.time, id: 'orig', text: '' } : undefined
        })()
      : undefined)
  if (!exposeObs) return []

  const dirKey = (n: number): 'c2s' | 's2c' | '?' => {
    const p = nums.get(n)
    if (!p) return '?'
    const seg = facts.segments.find((sg) => sg.packetNumber === n)
    return seg?.direction ?? '?'
  }

  const stages: EventStage[] = []

  // ① 正常传输:事件前最近的同向数据段 + 其 ACK(最多回看一对;找不到就省略该阶段)
  const firstDataBefore = [...nums.values()]
    .filter((p) => p.time < exposeObs.time && (p.tcpLen ?? 0) > 0 && dirKey(p.number) === dirKey(exposeObs.packetNumber))
    .sort((a, b) => a.time - b.time)
    .pop()
  if (firstDataBefore) {
    const ackAfter = [...nums.values()]
      .find(
        (p) =>
          p.time > firstDataBefore.time &&
          p.time < exposeObs.time &&
          dirKey(p.number) !== dirKey(firstDataBefore.number),
      )
    stages.push({
      label: '正常传输',
      summary: `段 #${firstDataBefore.number}(seq=${firstDataBefore.tcpSeq},${firstDataBefore.tcpLen}B)被正常确认${
        ackAfter ? `(#${ackAfter.number} ack=${ackAfter.tcpAck})` : ''
      },此时序列空间无缺口`,
      fromPacket: firstDataBefore.number,
      toPacket: ackAfter?.number ?? firstDataBefore.number,
      startTime: firstDataBefore.time,
      endTime: ackAfter?.time ?? firstDataBefore.time,
      observationRefs: [],
    })
  }

  // ② 缺口显露:越过缺口到达的段
  stages.push({
    label: '缺口显露',
    summary: `#${exposeObs.packetNumber} 越过缺口到达(seq=${nums.get(exposeObs.packetNumber)?.tcpSeq}),序列空间出现缺口 ${event.gap?.start}–${event.gap?.end}(${event.gap?.byteCount}B)`,
    fromPacket: exposeObs.packetNumber,
    toPacket: exposeObs.packetNumber,
    startTime: exposeObs.time,
    endTime: exposeObs.time,
    observationRefs: [exposeObs.id],
  })

  // ③ 重复确认与 SACK 增长:存在 dup ACK 时才有(乱序直补场景没有)
  const dupObs = obs.filter((o) => /重复确认|ACK 停在/.test(o.statement))
  if (dupObs.length > 0) {
    const dupNums = dupObs.map((o) => o.packetNumber)
    const t0 = Math.min(...dupNums.map((n) => nums.get(n)?.time ?? Infinity))
    const t1 = Math.max(...dupNums.map((n) => nums.get(n)?.time ?? -Infinity))
    const sackText = obs.find((o) => /SACK/.test(o.statement))?.statement ?? ''
    stages.push({
      label: '重复确认与 SACK 增长',
      summary: `累计 ACK 停在 ${event.gap?.start} 未前进(${dupNums.length} 次${sackText ? ';SACK 报告缺口后数据已到达' : ''})`,
      fromPacket: Math.min(...dupNums),
      toPacket: Math.max(...dupNums),
      startTime: t0,
      endTime: t1,
      observationRefs: dupObs.map((o) => o.id),
    })
  }

  // ④ 补齐:重传回补(loss 类)或 迟到补齐(reordering 类)。
  //    注意 reordering 事件的 retransmissionPacket 刻意留空(迟到原始段不是重发),
  //    填补者要从 gap 生命周期的 filledByPacket 拿,两条路径都要能定位到填补报文。
  const fillerPacket = event.retransmissionPacket ?? facts.gaps.find((g) => g.filledByPacket != null)?.filledByPacket
  const fillTime = fillerPacket != null ? nums.get(fillerPacket)?.time : undefined
  if (fillerPacket != null && fillTime != null) {
    if (event.kind === 'reordering') {
      const filler = nums.get(fillerPacket)
      const tagObs = obs.find((o) => /tshark/.test(o.statement))
      stages.push({
        label: '迟到补齐',
        summary: `#${fillerPacket} 迟到到达填补缺口(seq=${filler?.tcpSeq});tshark 标注为 retransmission,但该段携带的全部是新字节——标签是现象,序列空间证明只是乱序`,
        fromPacket: fillerPacket,
        toPacket: fillerPacket,
        startTime: fillTime,
        endTime: fillTime,
        observationRefs: tagObs ? [tagObs.id] : [],
      })
    } else {
      const tagObs = obs.find((o) => /tshark 标注/.test(o.statement))
      const resendObs = obs.find((o) => /重新发送/.test(o.statement))
      stages.push({
        label: '重传回补',
        summary: `#${fillerPacket} 重发缺失数据(seq=${event.gap?.start}),几何上精确回补缺口`,
        fromPacket: fillerPacket,
        toPacket: fillerPacket,
        startTime: fillTime,
        endTime: fillTime,
        observationRefs: [tagObs?.id, resendObs?.id].filter((x): x is string => x != null),
      })
    }
  }

  // ⑤ 恢复:ACK 越过缺口终点
  const recPkt = event.recoveryAckPacket != null ? nums.get(event.recoveryAckPacket) : undefined
  if (recPkt) {
    stages.push({
      label: '恢复',
      summary: `#${recPkt.number} 的 ACK 前进到 ${recPkt.tcpAck},越过缺口终点 ${event.gap?.end},缺口闭合`,
      fromPacket: recPkt.number,
      toPacket: recPkt.number,
      startTime: recPkt.time,
      endTime: recPkt.time,
      observationRefs: obs.filter((o) => o.packetNumber === recPkt.number).map((o) => o.id),
    })
  }

  return stages
}

/** 伪重传类阶段:正常发确 → 静默窗 → 冗余重传 → 确认无变化·已恢复 */
function spuriousStages(event: TcpEvent, packets: Packet[], nums: Map<number, Packet>): EventStage[] {
  const retx = event.retransmissionPacket != null ? nums.get(event.retransmissionPacket) : undefined
  if (!retx) return []
  const obs = event.observations

  // 重传之前的原始段:与其 seq 相同、时间更早的数据段
  const original = [...packets]
    .filter((p) => p.time < retx.time && (p.tcpLen ?? 0) > 0 && p.tcpSeq === retx.tcpSeq)
    .sort((a, b) => b.time - a.time)[0]

  const stages: EventStage[] = []

  // ① 正常发确:原始段及其确认(以及更早的一对,若有)
  if (original) {
    const ackDirPackets = packets
      .filter((p) => p.time <= retx.time && p.tcpAck != null && p.number !== retx.number)
      .sort((a, b) => a.time - b.time)
    const lastAckBeforeRetx = ackDirPackets[ackDirPackets.length - 1]
    stages.push({
      label: '正常发确',
      summary: `数据被正常确认:#${original.number}(seq=${original.tcpSeq},${original.tcpLen}B)${
        lastAckBeforeRetx ? ` → #${lastAckBeforeRetx.number} ack=${lastAckBeforeRetx.tcpAck}` : ''
      },接收端已完整收到`,
      fromPacket: original.number,
      toPacket: lastAckBeforeRetx?.number ?? original.number,
      startTime: original.time,
      endTime: lastAckBeforeRetx?.time ?? original.time,
      observationRefs: [],
    })

    // ② 静默窗:最后确认之后到重传之间无任何新数据 —— 静默本身是证据
    //    (发送端长时间未看到确认才触发重传;此处展示实际静默时长)
    const silenceMs = ((retx.time - (lastAckBeforeRetx?.time ?? original.time)) * 1000).toFixed(0)
    stages.push({
      label: '静默窗',
      summary: `${silenceMs}ms 内无新数据传输;随后发生重传,提示发送端可能未看到此前的确认`,
      fromPacket: lastAckBeforeRetx?.number ?? original.number,
      toPacket: retx.number - 1 >= (lastAckBeforeRetx?.number ?? original.number) ? retx.number - 1 : retx.number,
      startTime: lastAckBeforeRetx?.time ?? original.time,
      endTime: retx.time,
      observationRefs: [],
    })
  }

  // ③ 冗余重传
  stages.push({
    label: '冗余重传',
    summary: `#${retx.number} 重发 seq=${retx.tcpSeq}(新增字节 ${obs[0]?.value != null ? '' : ''}0/${retx.tcpLen});序列空间零缺口——数据早已到达`,
    fromPacket: retx.number,
    toPacket: retx.number,
    startTime: retx.time,
    endTime: retx.time,
    observationRefs: obs.filter((o) => o.packetNumber === retx.number).map((o) => o.id),
  })

  // ④ 确认无变化:重传后的响应 ACK 与重传前相同
  const ackAfter = packets
    .filter((p) => p.time > retx.time && p.tcpAck != null)
    .sort((a, b) => a.time - b.time)[0]
  if (ackAfter) {
    const ackBefore = packets
      .filter((p) => p.time < retx.time && p.tcpAck != null)
      .sort((a, b) => b.time - a.time)[0]
    const unchanged = ackBefore != null && seqDiff(ackAfter.tcpAck!, ackBefore.tcpAck!) === 0
    stages.push({
      label: unchanged ? '确认无变化·已恢复' : '确认状态不变',
      summary: `#${ackAfter.number} 回应 ack=${ackAfter.tcpAck}${unchanged ? ',与重传前相同——无需恢复任何数据' : ''}`,
      fromPacket: ackAfter.number,
      toPacket: ackAfter.number,
      startTime: ackAfter.time,
      endTime: ackAfter.time,
      observationRefs: obs.filter((o) => o.packetNumber === ackAfter.number).map((o) => o.id),
    })
  }

  return stages
}
