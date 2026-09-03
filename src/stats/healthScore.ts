import type { Packet } from '../model/types'

/**
 * M5 Health Score(plan M5):透明的会话健康分,仅用于筛选/排序。
 *
 * 红线(plan 原文):
 * - 绝不进入证据、观察或导出(UI 需注明"仅筛选用");
 * - 公式版本化;每项扣分带规则 key、分值与一句话理由,明细逐项可见;
 * - 覆盖不足(非 TCP)显式 unavailable,绝不编造数字。
 *
 * v1 规则(满分 100,扣分合计封顶 100):
 * - unrecovered-gap:-20/个,封顶 40(数据越过确认沿后再无确认 —— 最强异常信号)
 * - rst:-15(RST 终止;来源无法区分,中等扣分)
 * - zero-window-unrecovered:-10(零窗口通告至抓包结束未重开)
 * - truncated-capture:-5(存在截断帧;采集侧问题,轻微)
 * - retransmissions:-1/次,封顶 10(tshark 标签仅现象,重传≠丢包,权重最轻)
 *
 * 未恢复缺口判定(纯平面字段,不引入 M2 全量分析):
 * 按 (tcp.stream, 方向) 跟踪"已确认沿";某数据段起点越过已确认沿 ≥100B 且
 * 直到抓包结束确认沿仍未推进越过它 → 计一个未恢复缺口。
 */

export const HEALTH_FORMULA_VERSION = 'health-v1'

export interface HealthDeduction {
  key: string
  points: number
  reason: string
}

export interface HealthScore {
  /** 非 TCP 会话公式不适用 → false */
  available: boolean
  /** [0,100];available=false 时 undefined */
  score?: number
  deductions: HealthDeduction[]
  formula: string
}

const F_RST = 0x04

/** 缺口判定阈值:数据段起点越过确认沿的字节数 ≥ 此值记为缺口(含等号;
 *  与头部注释「≥100B」一致 —— 起点正好越过 100B 也算缺口) */
const GAP_OVERSHOOT_BYTES = 100

export function computeHealthScore(packets: Packet[]): HealthScore {
  if (packets.length === 0 || !packets.some((p) => p.transport === 'tcp')) {
    return { available: false, deductions: [], formula: HEALTH_FORMULA_VERSION }
  }
  const tcp = packets.filter((p) => p.transport === 'tcp')
  const flagsOf = (p: Packet): number => {
    const n = Number.parseInt(p.tcpFlags ?? '', 16)
    return Number.isNaN(n) ? 0 : n
  }
  const dirOf = (p: Packet): 'c2s' | 's2c' => {
    if (p.srcPort != null && p.dstPort != null) return p.dstPort < p.srcPort ? 'c2s' : 's2c'
    return 'c2s'
  }
  const deductions: HealthDeduction[] = []

  // ---- 未恢复缺口:按 (stream, 方向) 跟踪确认沿 ----
  interface DirState {
    ackedTo: number
    hole: boolean
  }
  const states = new Map<string, DirState>()
  const stateOf = (stream: number | undefined, dir: 'c2s' | 's2c'): DirState => {
    const key = `${stream ?? 'x'}:${dir}`
    let st = states.get(key)
    if (!st) {
      st = { ackedTo: -1, hole: false }
      states.set(key, st)
    }
    return st
  }
  const ordered = [...tcp].sort((a, b) => a.time - b.time || a.number - b.number)
  for (const p of ordered) {
    const f = flagsOf(p)
    if (f & F_RST) continue // RST 后确认不再可靠
    const dir = dirOf(p)
    // 本方向数据段:起点越过本方向确认沿 ≥ GAP_OVERSHOOT_BYTES → 缺口期开始
    // (ackedTo 仅在收到对向 ACK 时推进 —— 对向缺 tcpAck 字段则确认沿恒为 -1,
    // 判定不触发:无 ACK 信息时保守不扣分,而不是把一切数据段都判为缺口)
    if (p.tcpLen != null && p.tcpLen > 0 && p.tcpSeq != null) {
      const st = stateOf(p.tcpStream, dir)
      if (st.ackedTo >= 0 && p.tcpSeq - st.ackedTo >= GAP_OVERSHOOT_BYTES) st.hole = true
    }
    // 对向报文携带本方向的确认:推进**对向**的确认沿,闭合其对向未决缺口
    if (p.tcpAck != null) {
      const opp: 'c2s' | 's2c' = dir === 'c2s' ? 's2c' : 'c2s'
      const ost = stateOf(p.tcpStream, opp)
      if (p.tcpAck > ost.ackedTo) {
        ost.ackedTo = p.tcpAck
        ost.hole = false // 确认追平:缺口闭合(足够近似:v1 不精确配对缺口边界)
      }
    }
  }
  const unrecovered = [...states.values()].filter((s) => s.hole).length
  if (unrecovered > 0) {
    deductions.push({
      key: 'unrecovered-gap',
      points: Math.min(40, unrecovered * 20),
      reason: `${unrecovered} 处数据缺口在抓包范围内未见确认越过(未恢复)`,
    })
  }

  // ---- RST ----
  const rst = tcp.find((p) => (flagsOf(p) & F_RST) !== 0)
  if (rst) {
    deductions.push({ key: 'rst', points: 15, reason: `连接被 RST 终止(#${rst.number})` })
  }

  // ---- 零窗口未重开(简化:抓包结束时最后窗口通告为 0) ----
  const withWin = ordered.filter((p) => p.tcpWindow !== undefined)
  const lastWin = withWin.length > 0 ? withWin[withWin.length - 1].tcpWindow : undefined
  if (lastWin === 0) {
    deductions.push({ key: 'zero-window-unrecovered', points: 10, reason: '最后一次窗口通告为 0:对端接收缓冲至抓包结束未重开' })
  }

  // ---- 截断帧(采集侧,轻微) ----
  const truncated = tcp.filter((p) => p.capLen != null && p.capLen < p.len)
  if (truncated.length > 0) {
    deductions.push({
      key: 'truncated-capture',
      points: 5,
      reason: `${truncated.length} 帧被截断(snaplen/采集口):载荷分析受限;采集侧信号,不指示网络丢包`,
    })
  }

  // ---- 重传(tshark 标签,仅现象;权重最轻) ----
  const retx = tcp.filter((p) => p.tcpAnalysis?.includes('retransmission') || p.tcpAnalysis?.includes('fast-retransmission'))
  if (retx.length > 0) {
    deductions.push({ key: 'retransmissions', points: Math.min(10, retx.length), reason: `${retx.length} 次重传(重传≠丢包,权重最轻)` })
  }

  const total = deductions.reduce((a, d) => a + d.points, 0)
  return {
    available: true,
    score: Math.max(0, 100 - total),
    deductions,
    formula: HEALTH_FORMULA_VERSION,
  }
}
