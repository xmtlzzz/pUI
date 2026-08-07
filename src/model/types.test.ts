import { describe, expect, it } from 'vitest'
import { hostPort, hostOf } from './types'

describe('hostPort / hostOf', () => {
  it('splits IPv4:port', () => {
    expect(hostPort('192.168.1.10:80')).toEqual({ host: '192.168.1.10', port: '80' })
    expect(hostOf('192.168.1.10:80')).toBe('192.168.1.10')
  })

  it('splits IPv6:port by the last colon', () => {
    expect(hostPort('2001:db8::1:443')).toEqual({ host: '2001:db8::1', port: '443' })
    expect(hostOf('2001:db8::1:443')).toBe('2001:db8::1')
    expect(hostPort('2001:db8:0:1::1:5353')).toEqual({ host: '2001:db8:0:1::1', port: '5353' })
  })

  it('keeps bare MAC as the whole host', () => {
    expect(hostPort('aa:bb:cc:dd:ee:ff')).toEqual({ host: 'aa:bb:cc:dd:ee:ff', port: undefined })
    expect(hostOf('aa:bb:cc:dd:ee:ff')).toBe('aa:bb:cc:dd:ee:ff')
    // 数值结尾的 MAC 也不拆
    expect(hostOf('00:11:22:33:44:55')).toBe('00:11:22:33:44:55')
  })

  it('keeps bare IP as the whole host', () => {
    expect(hostOf('8.8.8.8')).toBe('8.8.8.8')
    expect(hostOf('fe80::1')).toBe('fe80::1')
  })
})
