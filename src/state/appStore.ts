import { create } from 'zustand'
import { aggregateConversations } from '../aggregate/aggregateConversations'
import { filterConversations, collectFilterOptions } from '../filter/filterConversations'
import { openCapture, openSample, fetchHex } from '../bridge/tauri'
import { emptyFilter } from '../model/types'
import type { CaptureMeta, Conversation, FilterCondition, FilterOptions, Packet } from '../model/types'

interface AppState {
  meta: CaptureMeta | null
  packets: Packet[]
  conversations: Conversation[]
  options: FilterOptions
  filter: FilterCondition
  selectedId: string | null
  selectedPacket: number | null
  currentPath: string
  diagramStyle: 'A' | 'B'
  loading: boolean
  error: string | null
  hexCache: Record<number, string>
  openFile: (path: string) => Promise<void>
  openExample: (name: string) => Promise<void>
  setFilter: (patch: Partial<FilterCondition>) => void
  clearFilter: () => void
  select: (id: string) => void
  selectPacket: (n: number) => void
  setDiagramStyle: (s: 'A' | 'B') => void
  fetchHexFor: (n: number) => Promise<string>
  getHex: (n: number) => string | null
}

export const useApp = create<AppState>((set, get) => ({
  meta: null,
  packets: [],
  conversations: [],
  options: { protocols: [], srcIps: [], dstIps: [], ports: [] },
  filter: emptyFilter(),
  selectedId: null,
  selectedPacket: null,
  currentPath: '',
  diagramStyle: 'A',
  loading: false,
  error: null,
  hexCache: {},

  async openFile(path) {
    set({ loading: true, error: null })
    try {
      const { meta, packets, path: realPath } = await openCapture(path)
      const conversations = aggregateConversations(packets)
      set({ meta, packets, conversations, options: collectFilterOptions(packets), selectedId: null, selectedPacket: null, currentPath: realPath, loading: false })
    } catch (e) {
      set({ loading: false, error: String(e) })
    }
  },

  async openExample(name) {
    set({ loading: true, error: null })
    try {
      const { meta, packets, path } = await openSample(name)
      const conversations = aggregateConversations(packets)
      set({ meta, packets, conversations, options: collectFilterOptions(packets), selectedId: null, selectedPacket: null, currentPath: path, loading: false })
    } catch (e) {
      set({ loading: false, error: String(e) })
    }
  },

  setFilter(patch) {
    set({ filter: { ...get().filter, ...patch } })
  },
  clearFilter() {
    set({ filter: emptyFilter() })
  },
  select(id) {
    set({ selectedId: id, selectedPacket: null })
  },
  selectPacket(n) {
    set({ selectedPacket: n })
  },
  setDiagramStyle(s) {
    set({ diagramStyle: s })
  },
  async fetchHexFor(n) {
    const cached = get().hexCache[n]
    if (cached) return cached
    if (!get().currentPath) return ''
    const hex = await fetchHex(get().currentPath, n)
    set({ hexCache: { ...get().hexCache, [n]: hex } })
    return hex
  },
  getHex(n) {
    return get().hexCache[n] ?? null
  },
}))

// 派生选择器
export const selectFiltered = (s: AppState): Conversation[] => filterConversations(s.conversations, s.filter)
export const selectSelected = (s: AppState): Conversation | null => s.conversations.find((c) => c.id === s.selectedId) ?? null
export const selectSelectedPacket = (s: AppState): Packet | null => {
  const conv = selectSelected(s)
  if (!conv) return null
  return conv.packets.find((p) => p.number === s.selectedPacket) ?? null
}
