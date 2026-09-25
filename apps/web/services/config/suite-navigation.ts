/** Config is resolved through the explicit LAN/VPN map before calling this. */
export function suiteAdminUrl(suiteBase: string): string | null {
  try {
    const url = new URL(suiteBase)
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null
    // Never forward query parameters, fragments or authentication tokens.
    return new URL('/admin', url.origin).href
  } catch { return null }
}
