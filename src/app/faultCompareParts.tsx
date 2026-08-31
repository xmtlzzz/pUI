import type { EventCard as EventCardModel, StageBandEntry } from '../m4/viewModel'

/**
 * FaultCompare 子组件(从 FaultCompare.tsx 拆出,行为零变化):
 * 单文件曾增长到 ~1000 行,阶段带与事件卡是两块自包含的渲染区,
 * 拆出后主文件聚焦编排逻辑;样式类名与 data-testid 保持逐字不变
 * (测试断言依赖它们,拆分不得改变任何可见结构)。
 */

/** 阶段段配色(与事件轨图钉共用,迁自 FaultCompare.tsx) */
export const STAGE_COLORS = ['#3b82f6', '#ef4444', '#f59e0b', '#8b5cf6', '#10b981', '#ec4899', '#14b8a6', '#f97316']

/**
 * 阶段带:上为 DSH duration 式总览条(彩色阶段段),下为阶段卡片
 * (审批要求:每阶段的名称/起止包号/时刻/信息要点常驻可见,不藏在 hover 里)。
 * 纯受控组件:选中态与点选回调归父层(CompareContent)。
 */
export function StageBand({
  stages,
  activeIdx,
  onSelect,
}: {
  stages: StageBandEntry[]
  activeIdx: number
  onSelect: (i: number) => void
}) {
  return (
    <div className="fc-timeband" data-testid="fc-stageband" role="list" aria-label="故障阶段时间带">
      <div className="fc-timeband-track">
        {stages.map((s, i) => {
          const w = s.t1 - s.t0
          // 带内标注(常驻,不藏 hover):宽段显示「序号. 阶段名」,窄段退化为序号;
          // 完整信息(起止包号/时刻/要点)仍在下方阶段卡常驻
          const tag = w >= 0.12 ? `${i + 1}. ${s.label}` : w >= 0.03 ? `${i + 1}` : null
          return (
            <div
              key={`${s.label}-${s.fromPacket}`}
              role="listitem"
              tabIndex={0}
              title={`阶段 ${i + 1}:${s.label}(#${s.fromPacket}–#${s.toPacket})`}
              onClick={() => onSelect(i)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') onSelect(i)
              }}
              className={`fc-timeband-seg ${i === activeIdx ? 'active' : ''}`}
              style={{
                left: `${s.t0 * 100}%`,
                width: `${Math.max(w * 100, 1.5)}%`,
                background: STAGE_COLORS[i % STAGE_COLORS.length],
              }}
            >
              {tag && <span className="fc-seg-tag">{tag}</span>}
            </div>
          )
        })}
      </div>
      <div className="fc-stage-cards" data-testid="fc-stage-cards">
        {stages.map((s, i) => (
          <button
            key={`card-${s.label}-${i}`}
            type="button"
            className={`fc-stage-card ${i === activeIdx ? 'active' : ''}`}
            onClick={() => onSelect(i)}
          >
            <span className="fc-stage-idx" style={{ background: STAGE_COLORS[i % STAGE_COLORS.length] }}>
              {i + 1}
            </span>
            <span className="fc-stage-name">{s.label}</span>
            <span className="fc-stage-pkt">
              #{s.fromPacket}–#{s.toPacket} · {s.startTime.toFixed(3)}–{s.endTime.toFixed(3)}s
            </span>
            <p className="fc-stage-summary">{s.summary}</p>
          </button>
        ))}
      </div>
    </div>
  )
}

/**
 * 事件卡:观察/推断/限制三层(证据链口径的 UI 呈现)。
 * 观察项的跳包按钮携带父层上下文(jumpCtx 由父层闭包提供)。
 */
export function EventCard({
  card,
  onSelectPacket,
}: {
  card: EventCardModel
  onSelectPacket: (n: number) => void
}) {
  return (
    <div className="fc-card">
      <div className="fc-card-sec">
        <h4>观察 Observed</h4>
        <ul>
          {card.observations.map((o, i) => (
            <li key={i}>
              <button type="button" className="fc-pkt-chip" onClick={() => onSelectPacket(o.packetNumber)} title="查看报文详情">
                #{o.packetNumber}
              </button>
              {o.statement}
            </li>
          ))}
        </ul>
      </div>
      <div className="fc-card-sec">
        <h4>推断 Inference · 置信度 {card.inference.confidence}</h4>
        <p>{card.inference.statement}</p>
      </div>
      <div className="fc-card-sec fc-limitations">
        <h4>限制 Limitation</h4>
        <ul>
          {card.limitations.map((l, i) => (
            <li key={i}>{l}</li>
          ))}
        </ul>
      </div>
    </div>
  )
}
