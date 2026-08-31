import type { ConversationDiff } from './diff'

/**
 * 结论辅助(对照分析第三层):从差异模型推导红线条目。
 *
 * **红线**:全部措辞限定在观察层 —— 只描述「两点各自观察到的现象差异」,
 * 对路径位置只用「提示」并显式声明「不构成断言」,与项目不过度归因红线一致
 * (单观察点的 limitation 措辞风格见 events.ts,这里是双点版)。
 */

export interface VerdictEntry {
  statement: string
  severity: 'info' | 'warn'
}

/** 包数差异显著阈值:较大侧/较小侧 > 1.5 且绝对差 > 20 包。
 *  双阈值原因:少量会话上 1 包之差在比例上可很夸张(2 vs 1),只看比例会噪声泛滥;
 *  只看绝对差则大流量会话(5000 vs 5100)被误报 —— 两者同时满足才算「显著」。 */
const RATIO_THRESHOLD = 1.5
const ABS_THRESHOLD = 20

/** 丢包类事件 kind(缺口/重传类):与 M3 引擎 kind 空间对应。
 *  reordering(乱序)不算丢包类 —— 单侧乱序是路径时序抖动的正常形态,
 *  双点对照中把它当丢失信号会制造假红。 */
const LOSS_KINDS = new Set(['possible-loss-or-delay', 'syn-retransmission'])

export function buildVerdicts(diff: ConversationDiff): VerdictEntry[] {
  const entries: VerdictEntry[] = []

  // ---- 红线 1:仅单侧见到的丢包类事件 → warn(路径位置提示,非断言) ----
  for (const e of diff.eventDiffs) {
    if (!LOSS_KINDS.has(e.kind)) continue
    if (e.onlyIn === 'A') {
      entries.push({
        severity: 'warn',
        statement:
          'A 侧观察到缺口/重传,B 侧同流未见:缺失发生在 A→B 传输路径上的可能性较高(提示位置,不构成断言;B 侧抓包漏包亦可产生同样现象)',
      })
    } else if (e.onlyIn === 'B') {
      entries.push({
        severity: 'warn',
        statement:
          'B 侧观察到缺口/重传,A 侧同流未见:缺失发生在 B→A 传输路径上的可能性较高(提示位置,不构成断言;A 侧抓包漏包亦可产生同样现象)',
      })
    }
  }

  // ---- 红线 2:两侧同事件 → info(现象横跨两点) ----
  for (const e of diff.eventDiffs) {
    if (e.onlyIn !== 'both') continue
    entries.push({
      severity: 'info',
      statement: `两侧均观察到 ${e.kind}:该现象横跨两点,非单点链路可解释`,
    })
  }

  // ---- 红线 3:包数差异显著 → info(采集位置/过滤差异提示) ----
  const { countA, countB } = diff.stats
  const max = Math.max(countA, countB)
  const min = Math.min(countA, countB)
  if (min > 0 && max / min > RATIO_THRESHOLD && max - min > ABS_THRESHOLD) {
    entries.push({
      severity: 'info',
      statement: `两侧报文计数差异显著(${countA} vs ${countB}):可能与各侧采集位置/过滤差异有关`,
    })
  }

  // ---- 红线 4:无任何差异 → info(两侧观察一致)。
  //      判定基于差异模型本身而非「上面是否产出过条目」:包数未达「显著」阈值
  //      但两侧计数仍不同时,不属于「无任何差异」,不得输出「两侧观察一致」
  //      (把 60 vs 50 说成一致会违反观察层的精确性) ----
  if (
    entries.length === 0 &&
    diff.stats.countA === diff.stats.countB &&
    diff.stats.bytesA === diff.stats.bytesB
  ) {
    entries.push({ severity: 'info', statement: '两侧观察一致' })
  }

  return entries
}
