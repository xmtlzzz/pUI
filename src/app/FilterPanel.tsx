import { useApp } from '../state/appStore'
import { FilterSelect } from './FilterSelect'
import type { FilterCondition } from '../model/types'

type FieldKey = 'protocol' | 'srcIp' | 'dstIp' | 'srcPort' | 'dstPort'

export function FilterPanel() {
  const options = useApp((s) => s.options)
  const filter = useApp((s) => s.filter)
  const setFilter = useApp((s) => s.setFilter)
  const clearFilter = useApp((s) => s.clearFilter)
  const filteredCount = useApp((s) => s.filtered.length)
  const total = useApp((s) => s.conversations.length)
  const issueCount = useApp((s) => s.conversations.filter((c) => c.issues.length > 0).length)
  const portsEnabled = options.ports.length > 0

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
      <label className="field">
        <input type="checkbox" checked={filter.negate} onChange={(e) => setFilter({ negate: e.target.checked })} /> 取反
      </label>
      <label className="field">
        <input type="checkbox" checked={filter.issueOnly} onChange={(e) => setFilter({ issueOnly: e.target.checked })} /> 仅看异常会话
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
