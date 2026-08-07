import { useApp, selectFiltered } from '../state/appStore'
import type { FilterCondition } from '../model/types'

type FieldKey = 'protocol' | 'srcIp' | 'dstIp' | 'srcPort' | 'dstPort'

export function FilterPanel() {
  const options = useApp((s) => s.options)
  const filter = useApp((s) => s.filter)
  const setFilter = useApp((s) => s.setFilter)
  const clearFilter = useApp((s) => s.clearFilter)
  const filteredCount = useApp((s) => selectFiltered(s).length)
  const total = useApp((s) => s.conversations.length)
  const portsEnabled = options.ports.length > 0

  const patch = (key: FieldKey, list: string[]) => {
    const p: Partial<FilterCondition> = { ...filter }
    ;(p as Record<string, unknown>)[key] = key === 'srcPort' || key === 'dstPort' ? list.map(Number) : list
    setFilter(p)
  }

  const render = (title: string, key: FieldKey, values: string[], current: string[], disabled = false) => (
    <label className={`field${disabled ? ' disabled' : ''}`} title={disabled ? '当前文件不含带端口报文(ARP 等)' : ''}>
      {title}
      <select
        className="select"
        disabled={disabled}
        value=""
        onChange={(e) => {
          const v = e.target.value
          if (v) patch(key, current.includes(v) ? current.filter((x) => x !== v) : [...current, v])
        }}
      >
        <option value="">+ 添加</option>
        {values.map((v) => (
          <option key={v} value={v}>
            {v}
          </option>
        ))}
      </select>
      <div>
        {current.map((v) => (
          <span
            key={v}
            className="badge"
            style={{ background: '#eff6ff', color: '#1d4ed8', margin: 2, cursor: 'pointer' }}
            onClick={() => patch(key, current.filter((x) => x !== v))}
          >
            {v} ✕
          </span>
        ))}
      </div>
    </label>
  )

  return (
    <>
      <div className="pane-title">筛选</div>
      {render('协议', 'protocol', options.protocols, filter.protocol)}
      {render('源地址', 'srcIp', options.srcIps, filter.srcIp)}
      {render('目的地址', 'dstIp', options.dstIps, filter.dstIp)}
      {render('源端口', 'srcPort', options.ports.map(String), filter.srcPort.map(String), !portsEnabled)}
      {render('目的端口', 'dstPort', options.ports.map(String), filter.dstPort.map(String), !portsEnabled)}
      <label className="field">
        <input type="checkbox" checked={filter.negate} onChange={(e) => setFilter({ negate: e.target.checked })} /> 取反
      </label>
      <div style={{ display: 'flex', gap: 8 }}>
        <button className="btn" onClick={clearFilter}>
          重置筛选
        </button>
      </div>
      <div style={{ marginTop: 10, fontSize: 12, color: '#64748b' }}>
        命中 <b style={{ color: '#2563eb' }}>{filteredCount}</b> / {total} 会话
      </div>
    </>
  )
}
