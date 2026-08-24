import { NextRequest, NextResponse } from 'next/server'
import { isSubdomainOf, isSameHost, isLocalhost, stripPort } from '@services/utils/ts/hostUtils'
import { getConfig } from '@services/config/config'

export const ACCESS_TOKEN_COOKIE = 'LH_access'
export const REFRESH_TOKEN_COOKIE = 'LH_refresh'
// Non-httpOnly "a session exists" marker. The client reads this
// (hasSessionMarker) to decide whether to restore a session WITHOUT a network
// round-trip. Kept here next to the token cookies so the marker and the tokens
// it stands for are always set/cleared from one place.
export const SESSION_MARKER_COOKIE = 'LH_session'
export const ACCESS_TOKEN_MAX_AGE = 8 * 60 * 60 // 8 hours
export const REFRESH_TOKEN_MAX_AGE = 30 * 24 * 60 * 60 // 30 days

export function getDomainFromRequest(request: NextRequest): { domain: string; topDomain: string } {
  const envDomain = getConfig('NEXT_PUBLIC_LEARNHOUSE_DOMAIN')
  const envTopDomain = getConfig('NEXT_PUBLIC_LEARNHOUSE_TOP_DOMAIN')
  if (envDomain) {
    return {
      domain: envDomain,
      topDomain: stripPort(envTopDomain || envDomain),
    }
  }

  const cookieDomain = request.cookies.get('LH_frontend_domain')?.value
  const cookieTopDomain = request.cookies.get('LH_top_domain')?.value
  if (cookieDomain) {
    return {
      domain: cookieDomain,
      topDomain: stripPort(cookieTopDomain || cookieDomain),
    }
  }

  return { domain: 'localhost', topDomain: 'localhost' }
}

export function getCookieDomain(request: NextRequest): string | undefined {
  // Tenancy is the source of truth: in single mode cookies are always
  // host-only on whatever Host the request arrived with, regardless of
  // whether that's localhost or a self-hosted VPS hostname. In multi mode
  // we use the configured top domain so subdomains share the session.
  const tenancy = request.cookies.get('LH_tenancy')?.value || 'single'
  if (tenancy === 'single') return undefined

  const host = request.headers.get('host')
  const { domain, topDomain } = getDomainFromRequest(request)

  if (isLocalhost(host)) return undefined
  if (topDomain === 'localhost') return undefined
  if (isSubdomainOf(host, domain) || isSameHost(host, domain)) {
    return `.${topDomain}`
  }
  // Custom (per-org) domain in multi mode → host-only.
  return undefined
}

export function getCookieOptions(request: NextRequest) {
  const isSecure = request.nextUrl.protocol === 'https:'
  const domain = getCookieDomain(request)
  return {
    httpOnly: true,
    secure: isSecure,
    sameSite: 'lax' as const,
    path: '/',
    ...(domain ? { domain } : {}),
  }
}

/**
 * (Re)set the non-httpOnly session marker on a response, using the same
 * domain/secure/sameSite scoping as the token cookies.
 *
 * MUST be called on EVERY path that issues or returns a token — login, oauth,
 * token-exchange, AND the refresh fast-path — so the marker can never drift out
 * of sync with the httpOnly refresh cookie. A drift where the tokens are valid
 * but the marker is absent silently strands the client: it cannot tell a
 * session exists and never restores it. Centralising the write here is the
 * single guarantee that no token-issuing path forgets the marker.
 */
export function setSessionMarkerCookie(
  response: NextResponse,
  request: NextRequest,
): void {
  response.cookies.set(SESSION_MARKER_COOKIE, '1', {
    ...getCookieOptions(request),
    httpOnly: false,
    maxAge: REFRESH_TOKEN_MAX_AGE,
  })
}
