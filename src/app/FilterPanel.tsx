import { useApp } from '../state/appStore'
import { FilterSelect } from './FilterSelect'
import type { FilterCondition } from '../model/types'

type FieldKey = 'protocol' | 'srcIp' | 'dstIp' | 'srcPort' | 'dstPort'

const ISSUE_TYPES: Array<{ type: string; label: string }> = [
  { type: 'retransmission', label: '重传' },
  { type: 'out-of-order', label: '乱序' },
  { type: 'dup-ack', label: '重复ACK' },
  { type: 'lost-segment', label: '丢段' },
  { type: 'slow-response', label: '慢响应' },
  { type: 'no-close', label: '未关闭' },
  { type: 'rst', label: '被重置' },
  { type: 'unanswered', label: '请求无响应' },
  { type: 'syn-no-reply', label: '连接未建立' },
  { type: 'one-way', label: '单向' },
]

export function FilterPanel() {
  const options = useApp((s) => s.options)
  const filter = useApp((s) => s.filter)
  const setFilter = useApp((s) => s.setFilter)
  const clearFilter = useApp((s) => s.clearFilter)
  const filteredCount = useApp((s) => s.filtered.length)
  const total = useApp((s) => s.conversations.length)
  const issueCount = useApp((s) => s.conversations.filter((c) => c.issues.length > 0).length)
  const portsEnabled = options.ports.length > 0
  const slowThreshold = useApp((s) => s.slowThreshold)
  const setSlowThreshold = useApp((s) => s.setSlowThreshold)
  const issueTypes = filter.issueTypes ?? []

  const patch = (key: FieldKey, list: string[]) => {
    const p: Partial<FilterCondition> = { ...filter }
    ;(p as Record<string, unknown>)[key] = key === 'srcPort' || key === 'dstPort' ? list.map(Number) : list
    setFilter(p)
  }

  const toggle = (arr: string[], v: string) => (arr.includes(v) ? arr.filter((x) => x !== v) : [...arr, v])

  return (
    <>
      <div className="pane-title">筛选</div>
      <FilterSelect title="协议" colorize options={options.protocols} current={filter.protocol} onToggle={(v) => patch('protocol', toggle(filter.protocol, v))} />
      <FilterSelect title="源地址" options={options.srcIps} current={filter.srcIp} onToggle={(v) => patch('srcIp', toggle(filter.srcIp, v))} />
      <FilterSelect title="目的地址" options={options.dstIps} current={filter.dstIp} onToggle={(v) => patch('dstIp', toggle(filter.dstIp, v))} />
      <FilterSelect
        title="源端口"
        options={options.ports.map(String)}
        current={filter.srcPort.map(String)}
        disabled={!portsEnabled}
        hint="当前文件不含带端口报文(ARP 等)"
        onToggle={(v) => patch('srcPort', toggle(filter.srcPort.map(String), v))}
      />
      <FilterSelect
        title="目的端口"
        options={options.ports.map(String)}
        current={filter.dstPort.map(String)}
        disabled={!portsEnabled}
        hint="当前文件不含带端口报文(ARP 等)"
        onToggle={(v) => patch('dstPort', toggle(filter.dstPort.map(String), v))}
      />
      <label className="field" title="对全部已选条件整体取反:只看不满足任一条件的会话(条件之间的 AND 整体取非)">
        <input type="checkbox" checked={filter.negate} onChange={(e) => setFilter({ negate: e.target.checked })} /> 取反
      </label>
      <label className="field" title="只显示带异常标记的会话;与上方异常类型勾选叠加时按类型细化">
        <input type="checkbox" checked={filter.issueOnly} onChange={(e) => setFilter({ issueOnly: e.target.checked })} /> 仅看异常会话
      </label>
      {ISSUE_TYPES.map((it) => (
        <label key={it.type} className="field issue-type">
          <input
            type="checkbox"
            checked={issueTypes.includes(it.type)}
            onChange={(e) => setFilter({ issueTypes: e.target.checked ? [...issueTypes, it.type] : issueTypes.filter((x) => x !== it.type) })}
          />{' '}
          {it.label}
        </label>
      ))}
      <label className="field" title="http.time 超过该阈值判定为慢响应">
        慢响应阈值 {' '}
        <input
          type="number"
          className="threshold-input"
          min={0.05}
          max={60}
          step={0.05}
          value={slowThreshold}
          onChange={(e) => setSlowThreshold(Number(e.target.value))}
        />{' '}
        s
      </label>
      <div style={{ display: 'flex', gap: 8 }}>
        <button className="btn" onClick={clearFilter}>
          重置筛选
        </button>
      </div>
      <div style={{ marginTop: 10, fontSize: 12, color: '#64748b' }}>
        命中 <b style={{ color: '#2563eb' }}>{filteredCount}</b> / {total} 会话
        {issueCount > 0 && (
          <span style={{ marginLeft: 8, color: '#d97706' }}>
            ⚠ {issueCount} 个异常
          </span>
        )}
      </div>
    </>
  )
}
