import type { ConversationDiff } from './diff'

/**
 * 结论辅助(对照分析第三层):从差异模型推导红线条目。
 *
 * **红线**:全部措辞限定在观察层 —— 只描述「两点各自观察到的现象差异」,
 * 对路径位置只用「提示」并显式声明「不构成断言」,与项目不过度归因红线一致
 * (单观察点的 limitation 措辞风格见 events.ts,这里是双点版)。
 *
 * 路径方向推断(2026-08-31 修正):缺口事件的 direction(c2s/s2c)= 数据流向,
 * 观察到缺口的侧就是「该数据的接收侧」。仅 X 侧观察到 c2s 缺口 = 客户端发出的
 * 数据在到达 X 前丢失 → 候选路径段是「发送端 → X 侧观测点」。
 * 方向未知(字段缺失)时退化为不指明端点的旧措辞。
 */

export interface VerdictEntry {
  statement: string
  severity: 'info' | 'warn'
}

/** 对照端点身份(供 verdict 把 c2s/s2c 翻译成「客户端→服务端」等路径措辞) */
export interface VerdictEndpoints {
  client: string
  server: string
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

/** 单侧丢包事件的路径提示:观察侧=该方向数据的接收侧(或贴近接收端的观测点),
 *  缺失发生在「发送端 → 观察侧」之间。端点身份可用时给出显式路径,否则退化为方向中性的旧措辞。 */
function lossPathStatement(observedIn: 'A' | 'B', direction: 'c2s' | 's2c' | undefined, ep: VerdictEndpoints | null): string {
  const sideCn = observedIn === 'A' ? 'A 侧' : 'B 侧'
  const otherCn = observedIn === 'A' ? 'B 侧' : 'A 侧'
  // direction = 数据流方向;观察侧见缺口 = 观察侧(贴近)接收端。
  // 发送端 = c2s 时的客户端 / s2c 时的服务端。
  if (ep) {
    const sender = direction === 's2c' ? ep.server : ep.client
    return `${sideCn}观察到缺口/重传,${otherCn}同流未见:${sender} 发往${direction === 's2c' ? ep.client : ep.server}的数据在到达 ${sideCn} 观测点之前缺失的可能性较高(提示位置,不构成断言;${otherCn}抓包漏包亦可产生同样现象)`
  }
  const dirCn = direction === 'c2s' ? '客户端→服务端' : direction === 's2c' ? '服务端→客户端' : '方向未知'
  return `${sideCn}观察到缺口/重传(${dirCn}数据),${otherCn}同流未见:缺失发生在该方向传输路径上的可能性较高(提示位置,不构成断言;${otherCn}抓包漏包亦可产生同样现象)`
}

export function buildVerdicts(diff: ConversationDiff, endpoints?: VerdictEndpoints): VerdictEntry[] {
  const entries: VerdictEntry[] = []
  const ep = endpoints ?? null

  // ---- 红线 1:仅单侧见到的丢包类事件 → warn(路径位置提示,非断言) ----
  // 方向语义:缺口事件的 direction = 数据流向;观察侧 = 该数据「应当到达而未到达」
  // 的接收侧(或其贴近点)。因此仅 X 侧观察到 direction=D 的缺口 ⇒ 候选路径段 =
  // D 的发送端 → X 观测点。字段缺失时退化为不含端点名的通用措辞。
  for (const e of diff.eventDiffs) {
    if (!LOSS_KINDS.has(e.kind)) continue
    if (e.onlyIn === 'A' || e.onlyIn === 'B') {
      entries.push({ severity: 'warn', statement: lossPathStatement(e.onlyIn, e.direction, ep) })
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
