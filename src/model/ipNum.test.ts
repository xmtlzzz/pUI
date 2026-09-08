import { describe, it, expect } from 'vitest'
import { ip4ToNum, numToIp4, isIp4, compareHosts, withIp4Sort } from './ipNum'

describe('ip4ToNum / numToIp4', () => {
  it('往返:任意合法 IPv4 ↔ 32 位无符号整数', () => {
    for (const [ip, n] of [
      ['0.0.0.0', 0],
      ['192.168.1.10', 0xc0a8010a],
      ['10.0.0.1', 0x0a000001],
      ['255.255.255.255', 0xffffffff],
      ['1.2.3.4', 0x01020304],
    ] as const) {
      expect(ip4ToNum(ip)).toBe(n)
      expect(numToIp4(n)).toBe(ip)
    }
  })

  it('数值序 = 网络序:同网段内的主机按最后一字节正确比较,不受词法影响', () => {
    // 词法 '10.0.0.10' < '10.0.0.2' 是错误的网络顺序;ip4ToNum 对合法 IPv4 不返回 null
    expect(ip4ToNum('10.0.0.2')!).toBeLessThan(ip4ToNum('10.0.0.10')!)
    // 跨段: 10.x 永远小于 192.x(词法 '192...' < '10...' 反而错误)
    expect(ip4ToNum('10.255.255.255')!).toBeLessThan(ip4ToNum('192.0.0.1')!)
  })

  it('边界段:0 和 255 是合法八位组', () => {
    expect(ip4ToNum('0.1.0.255')).toBe(0x0001_00ff)
    expect(ip4ToNum('1.0.255.0')).toBe(0x0100_ff00)
  })
})

describe('isIp4', () => {
  it('接受标准点分四段', () => {
    expect(isIp4('192.168.1.10')).toBe(true)
    expect(isIp4('0.0.0.0')).toBe(true)
    expect(isIp4('255.255.255.255')).toBe(true)
  })

  it('拒绝越界八位组与非 IPv4 形态(MAC/IPv6/带端口/域名)', () => {
    expect(isIp4('256.1.1.1')).toBe(false)
    expect(isIp4('1.2.3')).toBe(false)
    expect(isIp4('1.2.3.4.5')).toBe(false)
    expect(isIp4('a.b.c.d')).toBe(false)
    expect(isIp4('192.168.1.1:443')).toBe(false)
    expect(isIp4('aa:bb:cc:dd:ee:ff')).toBe(false)
    expect(isIp4('2001:db8::1')).toBe(false)
    expect(isIp4('example.com')).toBe(false)
    expect(isIp4('')).toBe(false)
  })

  it('前导零:与 tshark 输出口径一致地拒绝(八位组按十进制解析,02 非法)', () => {
    // tshark ip.src 输出规范为无前导零;宽松接受会与筛选候选集合(来自同一解析层)不一致
    expect(isIp4('192.168.01.10')).toBe(false)
  })
})

describe('compareHosts:IPv4 数值序,其余回落 localeCompare numeric', () => {
  it('双侧均为 IPv4:按 32 位整数比较', () => {
    expect(compareHosts('10.0.0.10', '10.0.0.2')).toBeGreaterThan(0)
    expect(compareHosts('10.0.0.1', '192.168.1.1')).toBeLessThan(0)
    expect(compareHosts('1.2.3.4', '1.2.3.4')).toBe(0)
  })

  it('IPv4 与非 IPv4(MAC/IPv6/主机名):IPv4 排在前(确定性分桶,先数值桶后其他桶)', () => {
    // 分桶本身是一种排序约定;两侧各自仍是确定的、可解释的(数值地址优先于符号地址)
    const mac = 'aa:bb:cc:dd:ee:ff'
    expect(compareHosts('10.0.0.1', mac)).toBeLessThan(0)
    expect(compareHosts(mac, '10.0.0.1')).toBeGreaterThan(0)
  })

  it('非 IPv4 之间:localeCompare numeric(维持既有词法+数字行为)', () => {
    expect(compareHosts('aa:bb:cc:dd:ee:01', 'aa:bb:cc:dd:ee:ff')).toBeLessThan(0)
    expect(compareHosts('aa:bb:cc:dd:ee:ff', 'aa:bb:cc:dd:ee:01')).toBeGreaterThan(0)
    expect(compareHosts('2001:db8::1', '2001:db8::2')).toBeLessThan(0)
  })
})

describe('withIp4Sort:IP 数组排序(筛选候选列表展示顺序)', () => {
  it('IPv4 按网络序升序,与字符串序明显不同时保持正确', () => {
    const out = withIp4Sort(['192.168.1.3', '10.0.0.2', '192.168.1.10', '10.0.0.21', '10.0.0.9'])
    expect(out).toEqual(['10.0.0.2', '10.0.0.9', '10.0.0.21', '192.168.1.3', '192.168.1.10'])
  })

  it('混合形态:IPv4 在前(数值序),非 IPv4(MAC/IPv6)在后保持 locale 序', () => {
    const out = withIp4Sort(['ff:ee:dd:cc:bb:aa', '192.168.1.2', '10.0.0.1', '2001:db8::1'])
    expect(out).toEqual(['10.0.0.1', '192.168.1.2', '2001:db8::1', 'ff:ee:dd:cc:bb:aa'])
  })

  it('全非 IPv4 时退化为 locale 排序(原行为)', () => {
    const out = withIp4Sort(['bb:00:00:00:00:02', 'aa:00:00:00:00:10', 'aa:00:00:00:00:2'])
    expect(out).toEqual(['aa:00:00:00:00:2', 'aa:00:00:00:00:10', 'bb:00:00:00:00:02'])
  })

  it('不修改入参(纯函数)', () => {
    const input = ['192.168.1.3', '10.0.0.2']
    withIp4Sort(input)
    expect(input).toEqual(['192.168.1.3', '10.0.0.2'])
  })
})
