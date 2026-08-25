/** tshark `-e` 精选字段清单:前后端契约的唯一前端源。
 *  与 src-tauri/src/tshark.rs 的 CAPTURE_FIELDS 保持逐字一致(Rust 侧为权威实现,
 *  scripts/gen-parsed.mjs 与本清单同步);新增字段时三处一起改。
 *  字段名为 tshark -G fields 规范名(下划线);前端解析器同时兼容树形态的连字符键。 */
export const CAPTURE_FIELDS: string[] = [
  'frame.number',
  'frame.time_relative',
  'frame.time_epoch',
  'frame.interface_id',
  'frame.len',
  // 捕获长度:< frame.len 即该帧被 snaplen 截断(采集完整性信号,不足以断言网络丢包)
  'frame.cap_len',
  'frame.protocols',
  'eth.src',
  'eth.dst',
  'ip.src',
  'ip.dst',
  'ipv6.src',
  'ipv6.dst',
  'tcp.srcport',
  'tcp.dstport',
  'tcp.flags',
  'tcp.seq_raw',
  'tcp.ack_raw',
  // 流身份:同一端点对复用端口/并发连接时,端点 key 会把多条连接错并成一条(实测 tshark 给出
  // stream=0/1 而 pUI 只看到一个会话),TCP 状态机必须按 tcp.stream 分流
  'tcp.stream',
  // TCP 载荷长度:序列号推进只能用它算,frame.len 是帧长(含各层头部)不能用于序列空间
  'tcp.len',
  // 握手完整性位掩码(SYN=1 SYN-ACK=2 ACK=4 DATA=8 FIN=16 RST=32):
  // (值 & 0x03) === 0 即中途抓包,此时"流起始丢段/未正常关闭"结论不可信
  'tcp.completeness',
  // SACK 左/右边界:平铺 -e 模式下为并行数组(sack_le[i] 配 sack_re[i]),取值必须逐对 zip;
  // 只取首元素会静默丢掉第 2..n 块,进而漏掉多个 Gap
  'tcp.options.sack_le',
  'tcp.options.sack_re',
  'tcp.analysis.retransmission',
  'tcp.analysis.fast_retransmission',
  'tcp.analysis.out_of_order',
  'tcp.analysis.duplicate_ack',
  // 第几个重复 ACK:平铺模式下 duplicate_ack 对单包会给出两个数组条目,
  // 计数需按报文而非数组长度;本字段提供 tshark 自己的序号供交叉校验
  'tcp.analysis.duplicate_ack_num',
  'tcp.analysis.lost_segment',
  // 伪重传:支撑"重传 ≠ 数据丢失"的判定(数据已到达、只是 ACK 未被看到)
  'tcp.analysis.spurious_retransmission',
  'udp.srcport',
  'udp.dstport',
  'http.request.method',
  'http.request.uri',
  'http.response.code',
  'http.time',
  'http.request.line',
  'http.response.line',
  'dns.qry.name',
  'dns.flags.response',
  'tls.handshake.type',
]
