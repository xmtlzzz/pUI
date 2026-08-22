import { useState } from 'react'
import { ConversationList } from './ConversationList'
import { HostPanel } from './HostPanel'
import { SummaryPanel } from './SummaryPanel'
import { TopologyPanel } from './TopologyPanel'

export type ListTab = 'conv' | 'host' | 'summary' | 'topo'

/** 左侧栏:会话 / 主机 / 摘要 / 拓扑 四个视角切换 */
export function ListPane() {
  const [tab, setTab] = useState<ListTab>('conv')
  return (
    <>
      <div className="pane-tabs">
        <button className={tab === 'conv' ? 'on' : ''} onClick={() => setTab('conv')}>
          会话
        </button>
        <button className={tab === 'host' ? 'on' : ''} onClick={() => setTab('host')}>
          主机
        </button>
        <button className={tab === 'summary' ? 'on' : ''} onClick={() => setTab('summary')}>
          摘要
        </button>
        <button className={tab === 'topo' ? 'on' : ''} onClick={() => setTab('topo')}>
          拓扑
        </button>
      </div>
      {tab === 'conv' ? <ConversationList /> : tab === 'host' ? <HostPanel /> : tab === 'summary' ? <SummaryPanel /> : <TopologyPanel />}
    </>
  )
}
