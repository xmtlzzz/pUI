import { useMemo, useState } from 'react'
import type { CompareViewModel } from '../m4/viewModel'
import { usePlayback, type PlaybackPhase } from '../m4/usePlayback'
import './faultCompare.css'

/**
 * M4 故障/正常对照页(整页板块)。
 *
 * 布局(用户审批反馈 2026-08-26 第二轮):
 * - 整页切换:进入故障分析时工具的整个工作区切换到本板块,可返回;
 * - 左栏核心是**序列空间图形化**(已见字节条 + Gap hatch + SACK 绿块 + 重传回补箭头 +
 *   ACK 游标),不是逐报文列表 —— VDI 抓包数千报文的列表不可用;
 * - 阶段带为时间进度条形态(DSH duration 式):彩色阶段段 + 当前位置游标 + 刻度,
 *   当前阶段信息面板固定展示;
 * - 关键报文链只含证据链报文(点击跳回原报文)。
 */

interface FaultCompareProps {
  vm: CompareViewModel | null
  onSelectPacket: (n: number) => void
  onBack: () => void
}

function phaseLabel(p: PlaybackPhase): string {
  switch (p) {
    case 'playing':
      return '播放中'
    case 'paused':
      return '已暂停'
    case 'done':
      return '终态'
    case 'static':
      return '静态模式'
    default:
      return '待播放'
  }
}

const STAGE_COLORS = ['#3b82f6', '#ef4444', '#f59e0b', '#8b5cf6', '#10b981', '#ec4899', '#14b8a6', '#f97316']

/** 序列空间图形:SVG 渲染已见字节条/Gap/SACK/ACK 游标 */
function SeqSpaceGraphic({ vm, playhead }: { vm: CompareViewModel; playhead: number }) {
  const { seqSpace: sq } = vm
  const W = 720
  const H = 150
  const x = (v: number): number => ((v - sq.axisMin) / (sq.axisMax - sq.axisMin)) * (W - 16) + 8
  // ACK 游标位置:播放时刻之前最后一个 ACK 轨迹点
  const ackPos = useMemo(() => {
    if (sq.ackTrack.length === 0) return null
    // 播放时刻映射回真实时间:用阶段带的时间轴(首阶段起点 + playhead * 总时长)
    const st = vm.stages
    if (st.length === 0) return null
    const t0 = st[0].startTime
    const t1 = st[st.length - 1].endTime
    const t = t0 + playhead * (t1 - t0)
    let last = sq.ackTrack[0]
    for (const pt of sq.ackTrack) {
      if (pt.time <= t) last = pt
      else break
    }
    return last.ack
  }, [playhead, sq.ackTrack, vm.stages])

  return (
    <svg className="fc-seqsvg" viewBox={`0 0 ${W} ${H}`} role="img" aria-label="序列空间图形化" data-testid="fc-seqspace">
      {/* 刻度轴 */}
      <line x1={8} y1={H - 22} x2={W - 8} y2={H - 22} stroke="#cbd5e1" />
      {sq.ticks.map((t) => (
        <g key={t}>
          <line x1={x(t)} y1={H - 22} x2={x(t)} y2={H - 18} stroke="#cbd5e1" />
          <text x={x(t)} y={H - 6} textAnchor="middle" fontSize={10} fill="#64748b">
            {t}
          </text>
        </g>
      ))}
      {/* 已见字节条 */}
      {sq.seenRuns.map(([s, e], i) => (
        <rect key={`seen${i}`} x={x(s)} y={30} width={Math.max(x(e) - x(s), 1)} height={14} fill="#10b981" rx={2}>
          <title>{`已见字节 ${Math.round(s)}–${Math.round(e)}`}</title>
        </rect>
      ))}
      {/* Gap hatch */}
      {sq.gaps.map(([s, e], i) => (
        <rect key={`gap${i}`} x={x(s)} y={30} width={Math.max(x(e) - x(s), 2)} height={14} fill="url(#fc-hatch)" stroke="#ef4444" strokeDasharray="3 2">
          <title>{`缺口 ${Math.round(s)}–${Math.round(e)}`}</title>
        </rect>
      ))}
      {/* SACK 块(绿色叠加) */}
      {sq.sackBlocks.map(([s, e], i) => (
        <rect key={`sack${i}`} x={x(s)} y={48} width={Math.max(x(e) - x(s), 2)} height={10} fill="#22c55e" opacity={0.75} rx={2}>
          <title>{`SACK ${Math.round(s)}–${Math.round(e)}`}</title>
        </rect>
      ))}
      {/* 重传回补箭头 */}
      {sq.retxArrow && (
        <g>
          <line x1={x(sq.retxArrow.seq)} y1={70} x2={x(sq.retxArrow.seq)} y2={46} stroke="#ef4444" strokeWidth={2} markerEnd="url(#fc-arr)" />
          <text x={x(sq.retxArrow.seq) + 4} y={70} fontSize={10} fill="#ef4444">
            重传回补
          </text>
        </g>
      )}
      {/* ACK 游标 */}
      {ackPos != null && (
        <g>
          <line x1={x(ackPos)} y1={92} x2={x(ackPos)} y2={H - 22} stroke="#1d4ed8" strokeWidth={1.5} strokeDasharray="4 3" />
          <circle cx={x(ackPos)} cy={92} r={5} fill="#1d4ed8" />
          <text x={x(ackPos)} y={88} textAnchor="middle" fontSize={10} fill="#1d4ed8">
            ACK {ackPos}
          </text>
        </g>
      )}
      <defs>
        <pattern id="fc-hatch" width="6" height="6" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
          <rect width="6" height="6" fill="#fee2e2" />
          <line x1="0" y1="0" x2="0" y2="6" stroke="#ef4444" strokeWidth="2" />
        </pattern>
        <marker id="fc-arr" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
          <path d="M0,0 L6,3 L0,6 z" fill="#ef4444" />
        </marker>
      </defs>
    </svg>
  )
}

export function FaultCompare({ vm, onSelectPacket, onBack }: FaultCompareProps) {
  const stageAt = useMemo(
    () => (t: number): number => {
      if (!vm || vm.stages.length === 0) return -1
      for (let i = vm.stages.length - 1; i >= 0; i--) {
        if (t >= vm.stages[i].t0) return i
      }
      return -1
    },
    [vm],
  )
  const pb = usePlayback(vm?.stages ?? [], stageAt)
  const [selectedStage, setSelectedStage] = useState<number | null>(null)

  if (!vm) {
    return (
      <div className="fc-page" data-testid="fault-compare-empty">
        <div className="fc-toolbar">
          <button type="button" onClick={onBack} data-testid="fc-back">
            ← 返回时序视图
          </button>
        </div>
        <div className="fc-empty">
          <p>该会话未检出可解释的 TCP 事件,没有可对照的故障过程。</p>
        </div>
      </div>
    )
  }

  const activeIdx = selectedStage ?? pb.activeStageIndex
  const active = activeIdx >= 0 ? vm.stages[activeIdx] : null

  const onKeyDown = (e: React.KeyboardEvent) => {
    switch (e.key) {
      case ' ':
        e.preventDefault()
        if (pb.phase === 'playing') pb.pause()
        else if (pb.phase === 'static') pb.overrideOnce()
        else pb.play()
        break
      case 'ArrowRight':
        e.preventDefault()
        pb.stepForward()
        break
      case 'ArrowLeft':
        e.preventDefault()
        pb.stepBack()
        break
      case 'Escape':
        e.preventDefault()
        pb.stop()
        break
      default:
        break
    }
  }

  return (
    <div className="fc-page" data-testid="fault-compare" tabIndex={0} onKeyDown={onKeyDown}>
      <div className="fc-toolbar">
        <button type="button" onClick={onBack} data-testid="fc-back">
          ← 返回时序视图
        </button>
        <span className="fc-headline">{vm.headline}</span>
        <span className="fc-phase">
          {phaseLabel(pb.phase)} {pb.phase === 'playing' || pb.phase === 'paused' ? `(${Math.round(pb.time * 100)}%)` : ''}
        </span>
        {pb.phase !== 'static' && (
          <span className="fc-controls">
            <button type="button" onClick={pb.phase === 'playing' ? pb.pause : pb.play} data-testid="fc-playpause">
              {pb.phase === 'playing' ? '⏸ 暂停' : '▶ 播放'}
            </button>
            <button type="button" onClick={pb.stepBack} aria-label="上一阶段">
              |◀
            </button>
            <button type="button" onClick={pb.stepForward} aria-label="下一阶段">
              ▶|
            </button>
          </span>
        )}
        {pb.phase === 'static' && (
          <span className="fc-static-note" role="status">
            系统已开启「减少动效」,动画停用;可点选阶段或用单步遍历。
            <button type="button" data-testid="fc-enable-animation" onClick={pb.overrideOnce}>
              仍要播放一次
            </button>
          </span>
        )}
      </div>

      {(vm.degraded.midStream || vm.degraded.unorderableInput || vm.degraded.lengthUnavailable) && (
        <div className="fc-degraded" role="status">
          {vm.degraded.midStream && <p>⚠ 抓包从连接中途开始:流起始处的缺失不构成丢包证据。</p>}
          {vm.degraded.lengthUnavailable && <p>⚠ 载荷长度不可用:字节数以 unknown 显示(不会显示为 0)。</p>}
          {vm.degraded.unorderableInput && <p>⚠ 序列空间存在无法定位的输入:图形仅供参考。</p>}
        </div>
      )}

      <div className="fc-body">
        {/* 左栏:实际故障 */}
        <section className="fc-left" aria-label="实际故障">
          <h3>
            实际故障 <span className="fc-real-badge">真实抓包</span>
          </h3>

          {/* 序列空间图形化:核心可视化 */}
          <SeqSpaceGraphic vm={vm} playhead={pb.time} />

          {/* 阶段信息面板(固定,不依赖 hover) */}
          <div className="fc-stage-panel" data-testid="fc-stage-panel" role="region" aria-label="当前阶段信息">
            {active ? (
              <>
                <strong style={{ color: STAGE_COLORS[activeIdx % STAGE_COLORS.length] }}>
                  阶段 {activeIdx + 1}/{vm.stages.length}:{active.label}
                </strong>
                <span>
                  报文 #{active.fromPacket}–#{active.toPacket} · {active.startTime.toFixed(3)}–{active.endTime.toFixed(3)}s
                </span>
                <p>{active.summary}</p>
              </>
            ) : (
              <p>按「播放」或单步查看各故障阶段;阶段条上每个阶段始终可见。</p>
            )}
          </div>

          {/* 阶段带:上为 DSH duration 式总览条(彩色段+播放游标),下为阶段卡片
              (审批要求:每阶段的名称/起止包号/时刻/信息要点常驻可见,不藏在 hover 里) */}
          <div className="fc-timeband" data-testid="fc-stageband" role="list" aria-label="故障阶段时间带">
            <div className="fc-timeband-track">
              {vm.stages.map((s, i) => (
                <div
                  key={`${s.label}-${s.fromPacket}`}
                  role="listitem"
                  tabIndex={0}
                  title={`阶段 ${i + 1}:${s.label}(#${s.fromPacket}–#${s.toPacket})`}
                  onClick={() => setSelectedStage(i)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') setSelectedStage(i)
                  }}
                  className={`fc-timeband-seg ${i === activeIdx ? 'active' : ''}`}
                  style={{
                    left: `${s.t0 * 100}%`,
                    width: `${Math.max((s.t1 - s.t0) * 100, 1.5)}%`,
                    background: STAGE_COLORS[i % STAGE_COLORS.length],
                  }}
                />
              ))}
              {(pb.phase === 'playing' || pb.phase === 'paused' || pb.phase === 'done') && (
                <div className="fc-timeband-cursor" style={{ left: `${pb.time * 100}%` }} />
              )}
            </div>
            <div className="fc-stage-cards" data-testid="fc-stage-cards">
              {vm.stages.map((s, i) => (
                <button
                  key={`card-${s.label}-${i}`}
                  type="button"
                  className={`fc-stage-card ${i === activeIdx ? 'active' : ''}`}
                  onClick={() => setSelectedStage(i)}
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

          {/* 事件卡:观察/推断/限制三层 */}
          <div className="fc-card">
            <div className="fc-card-sec">
              <h4>观察 Observed</h4>
              <ul>
                {vm.card.observations.map((o, i) => (
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
              <h4>推断 Inference · 置信度 {vm.card.inference.confidence}</h4>
              <p>{vm.card.inference.statement}</p>
            </div>
            <div className="fc-card-sec fc-limitations">
              <h4>限制 Limitation</h4>
              <ul>
                {vm.card.limitations.map((l, i) => (
                  <li key={i}>{l}</li>
                ))}
              </ul>
            </div>
          </div>

          {/* 关键报文链(仅证据链报文) */}
          <div className="fc-keypkts" data-testid="fc-messages">
            <h4>关键报文链</h4>
            <div className="fc-keypkt-row">
              {vm.keyPackets.map((m) => (
                <button key={m.packetNumber} type="button" className="fc-keypkt" onClick={() => onSelectPacket(m.packetNumber)} title={m.label}>
                  {m.roleBadge && <span className="fc-keypkt-role">{m.roleBadge}</span>}#{m.packetNumber}
                </button>
              ))}
            </div>
          </div>
        </section>

        {/* 右栏:正常参考(示意) */}
        <section className="fc-right" aria-label="正常参考示意">
          <h3>
            正常参考 <span className="fc-ref-badge">示意 · 非本抓包数据</span>
          </h3>
          <ol className="fc-ref-steps" data-testid="fc-ref-steps">
            {vm.referenceSteps.map((r, i) => (
              <li key={i} className={`fc-ref-${r.kind}`}>
                <span className="fc-ref-stepno">{r.index}</span>
                <span>{r.label}</span>
                <small>{r.detail}</small>
              </li>
            ))}
          </ol>
          <p className="fc-ref-note">
            本栏为解释性基线:同类交互正常情况下应为连续发送、ACK 逐段前进。它不是本抓包中的真实报文,
            不进入任何观察、证据或导出报告。
          </p>
        </section>
      </div>
    </div>
  )
}
