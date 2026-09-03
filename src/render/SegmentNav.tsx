import type { Segment } from '../aggregate/segmentConversation'

/**
 * 四形态共享的分段导航按钮组(「全部 / 1段 / 2段 …」)。
 * A/B/C/D 复用同一阅读上下文(store.seqSegIdx):切形态不丢段位置。
 * 段内渲染不截断 —— 由各组件按 segIdx 取 segment.packets 喂布局函数。
 */
export function SegmentNav({
  segments,
  segIdx,
  onSelect,
}: {
  segments: Segment[]
  segIdx: number | null
  onSelect: (idx: number | null) => void
}) {
  if (segments.length <= 1) return null
  return (
    <span className="seg-nav">
      <button type="button" className={segIdx == null ? 'on' : ''} onClick={() => onSelect(null)}>
        全部
      </button>
      {segments.map((sg) => (
        <button
          key={sg.index}
          type="button"
          className={segIdx === sg.index ? 'on' : ''}
          title={`${sg.start.toFixed(2)}~${sg.end.toFixed(2)}s · ${sg.packetCount} 包`}
          onClick={() => onSelect(sg.index)}
        >
          {sg.index + 1}段
        </button>
      ))}
    </span>
  )
}
