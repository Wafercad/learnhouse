import { expect, test } from 'bun:test'
import { suiteAdminUrl } from '../services/config/suite-navigation'
import { originOverrides } from '../services/config/origin-config'

test('returns to the same configured LAN or VPN suite without carrying tokens', () => {
  for (const host of ['192.168.1.34', '100.121.53.38']) {
    const academy = `http://${host}:3000`
    const suite = `http://${host}:4300`
    const config = { NEXT_PUBLIC_LEARNHOUSE_ORIGIN_ROUTES: JSON.stringify({ [academy]: suite }) }
    expect(suiteAdminUrl(originOverrides(config, academy).NEXT_PUBLIC_WC_DASHBOARD_URL)).toBe(`${suite}/admin`)
  }
  expect(suiteAdminUrl('https://dev.example.ts.net/path?token=secret#secret')).toBe('https://dev.example.ts.net/admin')
})

test('rejects unsafe navigation configuration', () => {
  for (const value of ['javascript:alert(1)', '/admin', 'https://user:secret@example.test', 'bad']) {
    expect(suiteAdminUrl(value)).toBeNull()
  }
})

test('uses the deployment address for staging and production', () => {
  for (const base of ['https://stage.wafercad.com', 'https://app.wafercad.com']) {
    expect(suiteAdminUrl(base)).toBe(`${base}/admin`)
  }
})
