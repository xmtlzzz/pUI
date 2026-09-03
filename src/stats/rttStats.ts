import type { Packet } from '../model/types'

/**
 * M5 RTT 统计(plan M5 分析增强):单观察点的往返时间近似。
 *
 * 度量定义:每个"累计 ACK 前进"事件的时间 - 对应被确认字节首次发出的时间。
 * - 以确认事件为样本(不是逐报文配对):重传段不重复计入;
 * - 被确认字节沿用"首次发出时刻"(Karn 算法的单观察点近似:重传后收到的 ACK
 *   归属首次发送,否则 RTT 会被重传时距抬高);
 * - 样本 < MIN_RTT_SAMPLES 时 available=false,绝不输出编造的数字。
 *
 * 限制(必须随展示说明):单观察点只能测到「发送→看到确认」的本地间隔,
 * 含对端处理时延,不等于纯网络往返。
 */

export const MIN_RTT_SAMPLES = 5

export interface RttStats {
  /** 样本是否足以给出分位数 */
  available: boolean
  /** 确认事件样本数 */
  samples: number
  /** 毫秒;available=false 时为 undefined */
  p50Ms?: number
  p90Ms?: number
  maxMs?: number
}

interface DirState {
  /** 已确认到的累计字节沿 */
  ackedTo: number
  /** 字节沿 -> 首次发出时刻(秒) */
  sentAt: Map<number, number>
}

const emptyDir = (): DirState => ({ ackedTo: -1, sentAt: new Map() })

/** 最近邻向上取整的分位数(升序数组,非空) */
function percentile(sorted: number[], q: number): number {
  const idx = Math.min(sorted.length - 1, Math.ceil(q * sorted.length) - 1)
  return sorted[Math.max(0, idx)]
}

export function computeRttStats(packets: Packet[]): RttStats {
  const ordered = [...packets].sort((a, b) => a.time - b.time || a.number - b.number)
  const dirs: Record<'c2s' | 's2c', DirState> = { c2s: emptyDir(), s2c: emptyDir() }

  // 方向:知名端口侧为服务端(与 m5Events 同一近似)
  const dirOf = (p: Packet): 'c2s' | 's2c' => {
    if (p.srcPort != null && p.dstPort != null) return p.dstPort < p.srcPort ? 'c2s' : 's2c'
    return 'c2s'
  }
  const flags = (p: Packet): number => {
    const n = Number.parseInt(p.tcpFlags ?? '', 16)
    return Number.isNaN(n) ? 0 : n
  }

  const samples: number[] = []
  for (const p of ordered) {
    const dir = dirOf(p)
    const f = flags(p)
    if (f & 0x04) continue // RST:之后不再有可靠确认
    // 数据段:登记字节沿首次发出时刻(Karn 单观察点近似 —— 只保留首次发送时刻,
    // 重传段不得覆盖:否则 ACK 落在重传后会把 RTT 算成「重传→ACK」的低估)
    if (p.tcpLen != null && p.tcpLen > 0 && p.tcpSeq != null) {
      const end = (p.tcpSeq + p.tcpLen) >>> 0
      if (end > dirs[dir].ackedTo && !dirs[dir].sentAt.has(end)) dirs[dir].sentAt.set(end, p.time)
    }
    // 反向 ACK:确认沿前进 → 产生一个 RTT 样本(Karn 近似:归属首次发送)
    if (p.tcpAck != null) {
      const opp = dir === 'c2s' ? 's2c' : 'c2s'
      const st = dirs[opp]
      if (p.tcpAck > st.ackedTo) {
        const sentTime = st.sentAt.get(p.tcpAck)
        if (sentTime != null && p.time >= sentTime) {
          // 毫秒粒度足够:浮点秒差直接乘会带 1e-13 级噪声,先取整
          samples.push(Math.round((p.time - sentTime) * 1000))
        }
        st.ackedTo = p.tcpAck
      }
    }
  }

  if (samples.length < MIN_RTT_SAMPLES) {
    return { available: false, samples: samples.length }
  }
  const sorted = [...samples].sort((a, b) => a - b)
  return {
    available: true,
    samples: samples.length,
    p50Ms: percentile(sorted, 0.5),
    p90Ms: percentile(sorted, 0.9),
    maxMs: sorted[sorted.length - 1],
  }
}
