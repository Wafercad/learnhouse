/** Public, explicit deployment aliases. Never derive a redirect from an arbitrary host. */
export function originOverrides(config: Record<string, string>, browserOrigin: string): Record<string, string> {
  try {
    const routes: unknown = JSON.parse(config['NEXT_PUBLIC_LEARNHOUSE_ORIGIN_ROUTES'] || '{}')
    if (!routes || typeof routes !== 'object' || Array.isArray(routes)) return {}
    const consoleOrigin = (routes as Record<string, unknown>)[browserOrigin]
    if (typeof consoleOrigin !== 'string') return {}
    const academy = new URL(browserOrigin)
    const suite = new URL(consoleOrigin)
    if (![academy, suite].every(url => ['http:', 'https:'].includes(url.protocol) &&
      !url.username && !url.password && !url.search && !url.hash && url.pathname === '/')) return {}
    return {
      NEXT_PUBLIC_LEARNHOUSE_DOMAIN: academy.host,
      NEXT_PUBLIC_LEARNHOUSE_TOP_DOMAIN: academy.hostname,
      NEXT_PUBLIC_LEARNHOUSE_HTTPS: String(academy.protocol === 'https:'),
      NEXT_PUBLIC_LEARNHOUSE_API_URL: academy.origin + '/api/v1/',
      NEXT_PUBLIC_LEARNHOUSE_BACKEND_URL: academy.origin + '/',
      NEXT_PUBLIC_WC_LOGIN_URL: suite.origin + '/login',
      NEXT_PUBLIC_WC_DASHBOARD_URL: suite.origin,
      NEXT_PUBLIC_LEARNHOUSE_PLATFORM_URL: suite.origin,
    }
  } catch { return {} }
}
