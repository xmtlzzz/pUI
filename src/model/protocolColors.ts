export interface ProtocolStyle {
  fg: string // 前景/箭头/圆点色
  bg: string // 徽章浅底
}

const STYLES: Record<string, ProtocolStyle> = {
  // 传输层
  tcp: { fg: '#0369a1', bg: '#e0f2fe' },
  udp: { fg: '#0f766e', bg: '#ccfbf1' },
  icmp: { fg: '#c2410c', bg: '#ffedd5' },
  icmpv6: { fg: '#c2410c', bg: '#ffedd5' },
  // 应用层(常见)
  http: { fg: '#15803d', bg: '#dcfce7' },
  https: { fg: '#7c3aed', bg: '#f3e8ff' },
  ssl: { fg: '#7c3aed', bg: '#f3e8ff' },
  tls: { fg: '#7c3aed', bg: '#f3e8ff' },
  quic: { fg: '#0e7490', bg: '#cffafe' },
  http2: { fg: '#15803d', bg: '#dcfce7' },
  http3: { fg: '#0e7490', bg: '#cffafe' },
  websocket: { fg: '#16a34a', bg: '#dcfce7' },
  grpc: { fg: '#0f766e', bg: '#ccfbf1' },
  dns: { fg: '#1d4ed8', bg: '#dbeafe' },
  mdns: { fg: '#1d4ed8', bg: '#dbeafe' },
  nbdgm: { fg: '#1d4ed8', bg: '#dbeafe' },
  nbss: { fg: '#1d4ed8', bg: '#dbeafe' },
  llmnr: { fg: '#1d4ed8', bg: '#dbeafe' },
  dhcp: { fg: '#b45309', bg: '#fef3c7' },
  bootp: { fg: '#b45309', bg: '#fef3c7' },
  ntp: { fg: '#a16207', bg: '#fefce8' },
  syslog: { fg: '#a16207', bg: '#fefce8' },
  ssh: { fg: '#166534', bg: '#dcfce7' },
  ftp: { fg: '#b91c1c', bg: '#fee2e2' },
  'ftp-data': { fg: '#b91c1c', bg: '#fee2e2' },
  tftp: { fg: '#1d4ed8', bg: '#dbeafe' },
  smtp: { fg: '#be185d', bg: '#fce7f3' },
  imap: { fg: '#db2777', bg: '#fce7f3' },
  pop: { fg: '#db2777', bg: '#fce7f3' },
  smb: { fg: '#1e40af', bg: '#dbeafe' },
  nbns: { fg: '#1d4ed8', bg: '#dbeafe' },
  rdp: { fg: '#334155', bg: '#e2e8f0' },
  telnet: { fg: '#64748b', bg: '#f1f5f9' },
  sip: { fg: '#dc2626', bg: '#fee2e2' },
  rtp: { fg: '#db2777', bg: '#fce7f3' },
  rtsp: { fg: '#db2777', bg: '#fce7f3' },
  // 路由/发现/安全
  arp: { fg: '#475569', bg: '#f1f5f9' },
  igmp: { fg: '#c2410c', bg: '#ffedd5' },
  ndp: { fg: '#4338ca', bg: '#e0e7ff' },
  ospf: { fg: '#1e40af', bg: '#dbeafe' },
  bgp: { fg: '#6d28d9', bg: '#ede9fe' },
  lldp: { fg: '#475569', bg: '#f1f5f9' },
  stp: { fg: '#1e40af', bg: '#dbeafe' },
  mpls: { fg: '#7c3aed', bg: '#f3e8ff' },
  vlan: { fg: '#475569', bg: '#f1f5f9' },
  ocsp: { fg: '#7c3aed', bg: '#f3e8ff' },
  ike: { fg: '#0f766e', bg: '#ccfbf1' },
  esp: { fg: '#0e7490', bg: '#cffafe' },
  gre: { fg: '#475569', bg: '#f1f5f9' },
  eapol: { fg: '#db2777', bg: '#fce7f3' },
}

/** 未知协议也给出稳定且彼此不同的颜色,避免一片灰 */
const PALETTE = [
  '#0ea5e9', '#8b5cf6', '#f59e0b', '#ec4899', '#10b981', '#f43f5e', '#14b8a6',
  '#6366f1', '#d946ef', '#84cc16', '#06b6d4', '#a855f7', '#eab308', '#fb7185',
  '#22d3ee', '#34d399', '#f97316', '#c084fc', '#facc15', '#2dd4bf',
]

function hash(name: string): number {
  let h = 0
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0
  return h
}

function lighten(hex: string, mix = 0.88): string {
  const n = parseInt(hex.slice(1), 16)
  const r = (n >> 16) & 0xff
  const g = (n >> 8) & 0xff
  const b = n & 0xff
  const lr = Math.round(r + (255 - r) * mix)
  const lg = Math.round(g + (255 - g) * mix)
  const lb = Math.round(b + (255 - b) * mix)
  return `rgb(${lr}, ${lg}, ${lb})`
}

export function protocolStyle(proto: string): ProtocolStyle {
  const p = proto.toLowerCase()
  const known = STYLES[p]
  if (known) return known
  const fg = PALETTE[hash(p) % PALETTE.length]
  return { fg, bg: lighten(fg) }
}

export function protocolColor(proto: string): string {
  return protocolStyle(proto).fg
}
