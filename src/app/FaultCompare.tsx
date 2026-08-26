import { useMemo, useState } from 'react'
import type { CompareViewModel } from '../m4/viewModel'
import { usePlayback, type PlaybackPhase } from '../m4/usePlayback'
import './faultCompare.css'

/**
 * M4 故障/正常对照页(案例审批通过后的实现)。
 *
 * 审批强化要求(核心):报文交互过程必须有明显的阶段标注 ——
 * - 阶段带常驻可见:每个阶段显示 名称 + 起止报文 + 信息要点;
 * - 播放时当前阶段高亮,阶段信息面板固定展示(不依赖 hover);
 * - 无动画/静态模式下全部阶段信息同样完整可读。
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
      return '静态模式(reduced-motion)'
    default:
      return '待播放'
  }
}

export function FaultCompare({ vm, onSelectPacket, onBack }: FaultCompareProps) {
  // 键盘控制:Space 播放/暂停、←/→ 单步、Esc 中断至终态。
  // 挂在容器 div 上(有 tabindex),不抢全局焦点。
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
  // 点击选中阶段:覆盖播放时刻的自动跟随(审批要求:阶段信息不依赖 hover,点选即看)。
  // hooks 必须在提前 return 之前调用(与 SequenceDiagram 的处理一致)。
  const [selectedStage, setSelectedStage] = useState<number | null>(null)

  if (!vm) {
    return (
      <div className="fc-wrap" data-testid="fault-compare-empty">
        <div className="fc-empty">
          <p>该会话未检出可解释的 TCP 事件,没有可对照的故障过程。</p>
          <button type="button" onClick={onBack}>
            返回会话视图
          </button>
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
    <div className="fc-wrap" data-testid="fault-compare" tabIndex={0} onKeyDown={onKeyDown}>
      <div className="fc-toolbar">
        <button type="button" onClick={onBack} data-testid="fc-back">
          ← 返回会话
        </button>
        <span className="fc-headline">{vm.headline}</span>
        <span className="fc-phase">{phaseLabel(pb.phase)}</span>
        {pb.phase !== 'static' && (
          <span className="fc-controls">
            <button type="button" onClick={pb.phase === 'playing' ? pb.pause : pb.play} data-testid="fc-playpause">
              {pb.phase === 'playing' ? '⏸ 暂停' : '▶ 播放'}
            </button>
            <button type="button" onClick={pb.stepBack} aria-label="上一阶段">
              |◀ 单步
            </button>
            <button type="button" onClick={pb.stepForward} aria-label="下一阶段">
              单步 ▶|
            </button>
          </span>
        )}
        {pb.phase === 'static' && (
          <span className="fc-static-note" role="status">
            已按系统偏好停用动画:全部阶段信息以静态方式完整呈现
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

      {/* 阶段信息面板:固定展示当前(或选中)阶段的完整要点 —— 审批要求不藏在 hover 里 */}
      <div className="fc-stage-panel" data-testid="fc-stage-panel" role="region" aria-label="当前阶段信息">
        {active ? (
          <>
            <strong>
              阶段 {pb.activeStageIndex + 1}/{vm.stages.length}:{active.label}
            </strong>
            <span>
              报文 #{active.fromPacket}–#{active.toPacket} · {active.startTime.toFixed(3)}–{active.endTime.toFixed(3)}s
            </span>
            <p>{active.summary}</p>
          </>
        ) : (
          <p>按「播放」或「单步」查看各故障阶段;每个阶段的名称与要点始终在下方阶段带可见。</p>
        )}
      </div>

      <div className="fc-body">
        {/* 左栏:实际故障 */}
        <section className="fc-left" aria-label="实际故障">
          <h3>实际故障(真实抓包)</h3>

          {/* 报文交互过程:每条报文一行,角色标注醒目,点击跳回原报文 */}
          <ol className="fc-messages" data-testid="fc-messages">
            {vm.leftMessages.map((m) => (
              <li key={m.packetNumber} className={`fc-msg ${m.stageIndex === pb.activeStageIndex ? 'in-stage' : ''}`}>
                <button type="button" onClick={() => onSelectPacket(m.packetNumber)} title="点击查看该报文详情">
                  #{m.packetNumber}
                </button>
                <span className="fc-msg-dir">{m.dir}</span>
                <span className="fc-msg-label">{m.label}</span>
                {m.sackBlocks && m.sackBlocks.length > 0 && (
                  <span className="fc-msg-sack">SACK {m.sackBlocks.map(([a, b]) => `${a}-${b}`).join(', ')}</span>
                )}
                {m.roleBadge && <span className={`fc-badge fc-role-${m.stageIndex >= 0 ? 'stage' : 'plain'}`}>{m.roleBadge}</span>}
              </li>
            ))}
          </ol>

          {/* 阶段带:审批强化要求的主体 —— 常驻、命名、含起止包号与要点 */}
          <div className="fc-stageband" data-testid="fc-stageband" role="list" aria-label="故障阶段带">
            {vm.stages.map((s, i) => (
              <div
                key={`${s.label}-${s.fromPacket}`}
                role="listitem"
                tabIndex={0}
                onClick={() => setSelectedStage(i)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') setSelectedStage(i)
                }}
                className={`fc-stage ${i === activeIdx ? 'active' : ''}`}
                style={{ flexGrow: Math.max(s.t1 - s.t0, 0.04) }}
              >
                <div className="fc-stage-head">
                  <span className="fc-stage-idx">{i + 1}</span>
                  <span className="fc-stage-name">{s.label}</span>
                  <span className="fc-stage-pkt">
                    #{s.fromPacket}–#{s.toPacket}
                  </span>
                </div>
                <p className="fc-stage-summary">{s.summary}</p>
              </div>
            ))}
          </div>

          <div className="fc-limitations">
            <h4>限制</h4>
            <ul>
              <li>单观察点抓包:可确认本地观察到的到达情况,但无法定位丢包发生在哪个网络节点,也无法确认对端是否已发出</li>
              <li>无法排除抓包点自身漏包(网卡/ring buffer/镜像口),缺口不等于网络丢包</li>
            </ul>
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
