import { describe, expect, test } from 'bun:test'
import { originOverrides } from '../services/config/origin-config'

describe('explicit LAN and VPN routes', () => {
  const config = { NEXT_PUBLIC_LEARNHOUSE_ORIGIN_ROUTES: JSON.stringify({
    'http://192.168.1.34:3000': 'http://192.168.1.34:4300',
    'https://dev.example.ts.net:9443': 'https://dev.example.ts.net',
  }) }
  test('uses the active Academy host for browser API requests', () => {
    const got = originOverrides(config, 'http://192.168.1.34:3000')
    expect(got.NEXT_PUBLIC_LEARNHOUSE_API_URL).toBe('http://192.168.1.34:3000/api/v1/')
    expect(got.NEXT_PUBLIC_WC_LOGIN_URL).toBe('http://192.168.1.34:4300/login')
    expect(got.NEXT_PUBLIC_LEARNHOUSE_HTTPS).toBe('false')
  })
  test('retains HTTPS and its ports on the configured VPN domain', () => {
    expect(originOverrides(config, 'https://dev.example.ts.net:9443').NEXT_PUBLIC_LEARNHOUSE_DOMAIN).toBe('dev.example.ts.net:9443')
  })
  test('does not trust unknown hosts, malformed JSON, or unsafe schemes', () => {
    expect(originOverrides(config, 'https://evil.test')).toEqual({})
    expect(originOverrides({ NEXT_PUBLIC_LEARNHOUSE_ORIGIN_ROUTES: 'bad' }, 'http://x')).toEqual({})
    expect(originOverrides({ NEXT_PUBLIC_LEARNHOUSE_ORIGIN_ROUTES: '{"http://x":"javascript:alert(1)"}' }, 'http://x')).toEqual({})
  })
})
