import { describe, expect, it } from 'vitest'
import { defaultPngName } from './exportPng'

describe('defaultPngName', () => {
  it('builds a readable filename', () => {
    expect(defaultPngName('192.168.1.10:54321', '93.184.216.34:80', 'http')).toBe('192.168.1.10-93.184.216.34-http.png')
  })

  it('strips ports from endpoints', () => {
    expect(defaultPngName('192.168.1.10:54321', '8.8.8.8:53', 'dns')).toBe('192.168.1.10-8.8.8.8-dns.png')
  })
})
