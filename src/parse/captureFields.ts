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
  // 接收窗口通告(M5 窗口事件:零窗口/窗口耗尽)。字段缺失不做推测,0 有独立语义
  'tcp.window_size',
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
  // —— M6 第二批:SSH/RDP/VNC/SMB 应用层分析。这四类协议多为加密协议,只取明文握手/命令字段,
  // 不重组流、不解密;字段缺失 = 能力缺失,分析器不臆造事件。
  // 注意:本段注释刻意不用 ASCII 单引号 —— gen-parsed.mjs 会把文件里所有单引号包裹的
  // 小写 token 当作字段名抓走(契约测试据此对齐三处)。
  // SSH 版本横幅(如 SSH-2.0-OpenSSH_9.6):密钥交换后全程加密,横幅是唯一明文能力信号
  'ssh.protocol',
  // SSH 通道类型名(session/exec 等):通道打开请求为明文,可观察用途意图(通道内数据不可见)
  'ssh.connection_type_name',
  // RDP 连接协商请求协议位掩码(0x1=SSL 0x2=CredSSP 0x8=RDSTLS);tshark 输出形如 0x00000003。
  // 该字段是 Wireshark 官方注册名、含大写字母,gen-parsed.mjs 的 [a-z0-9_.] 正则抓不到
  // (示例抓包 http/dns/mixed/lossy 均不含 RDP,fixture 再生成不受影响;契约测试中显式豁免)
  'rdp.negReq.requestedProtocols',
  // RDP 客户端机器名:仅明文 X.224 cookie 场景落值,缺失即不产出事件
  'rdp.client.name',
  // RFB 版本横幅(如 003.008):实机验证只在服务端横幅帧落值。
  // vnc.security_type 在常见 RFB 3.8 握手下实测不落值,纳入只会放大 JSON 体积,故不纳入契约
  'vnc.server_proto_ver',
  // SMB2 命令号(tshark 十进制输出:0=协商 3=树连接 5=创建 6=读 7=写 16=关闭)
  'smb2.cmd',
  // SMB2 响应标志:区分请求/响应方向(取值 1 或 true,大小写不敏感,视为响应)
  'smb2.flags.response',
  // 树连接路径:smb2.filename 为省字段数不纳入(会话建立后文件名多在加密载荷内),摘要只到 tree 粒度
  'smb2.tree',
]
