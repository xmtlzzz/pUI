export interface ProtocolStyle {
  fg: string // 前景/箭头色
  bg: string // 徽章浅底
}

const STYLES: Record<string, ProtocolStyle> = {
  // 传输层
  tcp: { fg: '#0369a1', bg: '#e0f2fe' },
  udp: { fg: '#0f766e', bg: '#ccfbf1' },
  icmp: { fg: '#c2410c', bg: '#ffedd5' },
  // 应用层(常见)
  http: { fg: '#15803d', bg: '#dcfce7' },
  https: { fg: '#7c3aed', bg: '#f3e8ff' },
  tls: { fg: '#7c3aed', bg: '#f3e8ff' },
  quic: { fg: '#0e7490', bg: '#cffafe' },
  'http2': { fg: '#15803d', bg: '#dcfce7' },
  websocket: { fg: '#16a34a', bg: '#dcfce7' },
  grpc: { fg: '#0f766e', bg: '#ccfbf1' },
  dns: { fg: '#1d4ed8', bg: '#dbeafe' },
  mdns: { fg: '#1d4ed8', bg: '#dbeafe' },
  dhcp: { fg: '#b45309', bg: '#fef3c7' },
  ntp: { fg: '#a16207', bg: '#fefce8' },
  ssh: { fg: '#166534', bg: '#dcfce7' },
  ftp: { fg: '#b91c1c', bg: '#fee2e2' },
  'ftp-data': { fg: '#b91c1c', bg: '#fee2e2' },
  smtp: { fg: '#be185d', bg: '#fce7f3' },
  imap: { fg: '#db2777', bg: '#fce7f3' },
  pop: { fg: '#db2777', bg: '#fce7f3' },
  smb: { fg: '#1e40af', bg: '#dbeafe' },
  rdp: { fg: '#334155', bg: '#e2e8f0' },
  telnet: { fg: '#64748b', bg: '#f1f5f9' },
  sip: { fg: '#dc2626', bg: '#fee2e2' },
  rtp: { fg: '#db2777', bg: '#fce7f3' },
  arp: { fg: '#475569', bg: '#f1f5f9' },
}

const DEFAULT_STYLE: ProtocolStyle = { fg: '#64748b', bg: '#f8fafc' }

export function protocolStyle(proto: string): ProtocolStyle {
  return STYLES[proto.toLowerCase()] ?? DEFAULT_STYLE
}

export function protocolColor(proto: string): string {
  return protocolStyle(proto).fg
}
