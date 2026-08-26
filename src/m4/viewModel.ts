import type { Packet } from '../model/types'
import type { StreamAnalysisFacts } from '../analysis/tcp/streamAnalysis'
import type { TcpEvent } from '../analysis/tcp/events'
import type { EventStage } from '../analysis/tcp/stages'

/**
 * M4 故障/正常对照页的视图模型层:把引擎输出投影为组件可直接渲染的纯数据。
 *
 * 设计约束(来自案例审批记录,docs/specs/m4-cases/*):
 * - 阶段带必须由 deriveStages 的输出驱动,本层只做坐标归一化与报文-阶段关联,
 *   绝不在组件里手写阶段数组;
 * - 右栏「正常参考」是解释性示意,本层生成的 referenceSteps 不含任何真实包号
 *   (数据保真红线,有测试钉住);
 * - 纯函数、确定性输出,同一输入两次构建结果逐字节一致。
 */

/** 对照页左栏消息(真实抓包报文 + 事件角色标注) */
export interface CompareMessage {
  packetNumber: number
  time: number
  dir: 'c2s' | 's2c'
  /** 展示标签,如 "PSH·ACK seq=201 len=100" */
  label: string
  flags?: string
  seq?: number
  ack?: number
  len?: number
  sackBlocks?: Array<[number, number]>
  /** tshark 标签(仅作观察展示,不参与渲染判定) */
  tags?: string[]
  /** 所属阶段索引(-1 = 不属于任何阶段);播放高亮联动用 */
  stageIndex: number
  /** 事件角色标注(缺口显露/重复确认/重传回补/恢复 等),直接渲染在报文旁 */
  roleBadge?: string
}

/** 右栏示意基线的一个步骤(绝不含真实包号) */
export interface ReferenceStep {
  index: number
  label: string
  kind: 'data' | 'ack'
  detail: string
}

/** 阶段带轨道条目:EventStage + 归一化时间坐标 */
export interface StageBandEntry extends EventStage {
  /** 相对事件时间线的归一化起点/终点 [0,1],供阶段带布局 */
  t0: number
  t1: number
}

export interface CompareViewModel {
  leftMessages: CompareMessage[]
  stages: StageBandEntry[]
  referenceSteps: ReferenceStep[]
  degraded: {
    unorderableInput: boolean
    midStream: boolean
    lengthUnavailable: boolean
    noEvents: boolean
  }
  headline: string
}

const KIND_LABEL: Record<TcpEvent['kind'], string> = {
  'possible-loss-or-delay': '疑似丢包 / 延迟到达',
  reordering: '乱序到达',
  'possible-ack-loss-or-spurious': '疑似 ACK 丢失 / 冗余重传',
}

function flagsLabel(flagsHex: string | undefined): string {
  if (!flagsHex) return ''
  const n = Number.parseInt(flagsHex, 16)
  if (Number.isNaN(n)) return ''
  const parts: string[] = []
  if (n & 0x01) parts.push('FIN')
  if (n & 0x02) parts.push('SYN')
  if (n & 0x04) parts.push('RST')
  if (n & 0x08) parts.push('PSH')
  if (n & 0x10) parts.push('ACK')
  return parts.join('·')
}

/** 报文的展示方向:以流内首个数据报文源端点为 c2s(与分析层 dirOf 一致的近似) */
function directionOf(p: Packet, c2sKey: string | null): 'c2s' | 's2c' {
  if (!c2sKey) return p.srcPort != null && p.dstPort != null && p.srcPort < p.dstPort ? 'c2s' : 's2c'
  return `${p.srcIp ?? '?'}:${p.srcPort ?? 0}` === c2sKey ? 'c2s' : 's2c'
}

/**
 * 从事件的证据结构推断报文的事件角色(渲染在报文旁的醒目标注)。
 * 依据是 detectTcpEvents 输出的确定性字段(packet 相等性),不是对文本的猜测。
 */
function roleBadgeOf(packetNumber: number, event: TcpEvent): string | undefined {
  if (event.originalSegmentPacket === packetNumber && event.gap) return '缺口显露'
  if (event.retransmissionPacket === packetNumber) {
    return event.kind === 'reordering' ? '迟到补齐' : event.gap ? '重传回补' : '冗余重传'
  }
  if (event.recoveryAckPacket === packetNumber) {
    return event.kind === 'possible-ack-loss-or-spurious' ? '确认无变化' : '恢复'
  }
  if (event.duplicateAckPackets.includes(packetNumber)) return `重复确认 ×${event.duplicateAckCount}`
  return undefined
}

/** 右栏示意基线:固定 5 段连续发送 + 每段被立即确认(形状取自 reference-normal,不含包号) */
function buildReferenceSteps(): ReferenceStep[] {
  const steps: ReferenceStep[] = []
  for (let i = 1; i <= 5; i++) {
    steps.push({
      index: i,
      label: `数据段 ${i} · 100B`,
      kind: 'data',
      detail: '按序列顺序连续发送',
    })
    steps.push({
      index: i,
      label: `ACK 前进到 ${i * 100 + 1}`,
      kind: 'ack',
      detail: '每个数据段都被立即确认,累计 ACK 单调前进,无停滞',
    })
  }
  return steps
}

/**
 * 构建对照页视图模型。无可对照事件时返回 null(调用方渲染空态)。
 */
export function buildCompareViewModel(
  packets: Packet[],
  facts: StreamAnalysisFacts,
  event: TcpEvent | undefined,
  stages: EventStage[],
): CompareViewModel | null {
  if (!event || stages.length === 0) return null

  // c2s 锚点:首个数据段源端点(facts.segments 已带 direction,直接取第一个非零载荷段的)
  const firstSeg = facts.segments.find((s) => s.seqLen > 0)
  const firstPkt = firstSeg ? packets.find((p) => p.number === firstSeg.packetNumber) : undefined
  const c2sKey = firstPkt ? `${firstPkt.srcIp ?? '?'}:${firstPkt.srcPort ?? 0}` : null

  // 时间线归一化基准:事件起点到最后一个阶段终点(阶段带只覆盖事件过程,不含握手前)
  const timelineStart = Math.min(...stages.map((s) => s.startTime))
  const timelineEnd = Math.max(...stages.map((s) => s.endTime))
  const span = timelineEnd - timelineStart

  const bandStages: StageBandEntry[] = stages.map((s) => ({
    ...s,
    t0: span > 0 ? (s.startTime - timelineStart) / span : 0,
    t1: span > 0 ? (s.endTime - timelineStart) / span : 1,
  }))

  // 事件相关报文号集合:阶段区间内的所有报文都进入左栏(事件上下文),
  // 其余(握手等)不进 —— 左栏聚焦故障过程本身
  const inBand = (t: number): boolean => t >= timelineStart && t <= timelineEnd
  const relevant = packets
    .filter((p) => inBand(p.time))
    .sort((a, b) => a.time - b.time || a.number - b.number)

  const leftMessages: CompareMessage[] = relevant.map((p) => {
    const stageIdx = stages.findIndex((s) => p.time >= s.startTime && p.time <= s.endTime)
    const fl = flagsLabel(p.tcpFlags)
    const labelParts = [fl, p.tcpSeq != null ? `seq=${p.tcpSeq}` : null, p.tcpLen ? `len=${p.tcpLen}` : null].filter(Boolean)
    return {
      packetNumber: p.number,
      time: p.time,
      dir: directionOf(p, c2sKey),
      label: labelParts.join(' ') || 'TCP',
      flags: p.tcpFlags,
      seq: p.tcpSeq,
      ack: p.tcpAck,
      len: p.tcpLen,
      sackBlocks: p.tcpSackBlocks,
      tags: p.tcpAnalysis,
      stageIndex: stageIdx,
      roleBadge: roleBadgeOf(p.number, event),
    }
  })

  return {
    leftMessages,
    stages: bandStages,
    referenceSteps: buildReferenceSteps(),
    degraded: {
      unorderableInput: facts.unorderableInput,
      midStream: facts.midStream,
      lengthUnavailable: facts.lengthUnavailable,
      noEvents: false,
    },
    headline: `${KIND_LABEL[event.kind]} · 缺口 ${event.gap ? `${event.gap.start}–${event.gap.end}(${event.gap.byteCount}B)` : '无'} · ${event.severity}`,
  }
}

/**
 * 播放时刻 -> 当前阶段索引。
 * 边界语义:首阶段开始前为 -1;落在某阶段 [t0,t1] 内返回该索引;
 * 最后阶段结束后停在最后一个索引(终态驻留,与案例分镜 S8 一致)。
 */
export function stageAtTime(vm: CompareViewModel, t: number): number {
  const { stages } = vm
  if (stages.length === 0) return -1
  for (let i = stages.length - 1; i >= 0; i--) {
    if (t >= stages[i].t0) return i
  }
  return -1
}
