import { redirect } from 'next/navigation'
import { Metadata } from 'next'
import {
  getBackendUrl,
  getDefaultOrg,
  getServerAPIUrl,
} from '@services/config/config'

// Cloud Campus (LearnHouse) does NOT host its own login. Identity is owned by
// Wafercad — the account service is the IdP — so /auth/login never renders a
// form; it leaves.
//
// WHERE it leaves to is the whole point. When this instance is wired to the
// account service as an OIDC relying party, "log in" means START that flow:
// /auth/sso/start bounces through the IdP and comes back with a LearnHouse
// session. Sending the browser to the console's own login page instead only
// proves the user is signed in THERE and mints nothing here, so a platform
// admin following the Course Studio link went round in a circle — signed into
// Wafercad, anonymous in the Studio, one click from the same loop.
//
// Without OIDC configured (stock CE) the console login remains the only sane
// destination, so it stays the fallback.
export const metadata: Metadata = {
  title: 'Redirecting to Wafercad…',
  robots: { index: false, follow: false },
}

const WC_LOGIN_URL =
  process.env.NEXT_PUBLIC_WC_LOGIN_URL || 'https://app.wafercad.com/login'

/** A destination on this site, or null — never an origin we do not own. */
function safeNext(candidate: string | undefined): string | null {
  if (!candidate || !candidate.startsWith('/') || candidate.startsWith('//')) return null
  return candidate.includes('\\') ? null : candidate
}

/** The browser-facing SSO entry point, or null when this instance has no IdP. */
async function ssoStartUrl(next: string | null): Promise<string | null> {
  const org = getDefaultOrg()
  try {
    const res = await fetch(
      `${getServerAPIUrl()}auth/sso/check?org_slug=${encodeURIComponent(org)}`,
      { cache: 'no-store' },
    )
    if (!res.ok) return null
    const body = await res.json()
    if (!body?.sso_enabled) return null
  } catch {
    // An unreachable API is not a reason to dead-end: fall back to the console.
    return null
  }
  // The BROWSER's spelling of the API, not this server's — they differ wherever
  // the API is reachable from the container under another address.
  const backend = getBackendUrl().replace(/\/+$/, '')
  const destination = next ? `&next=${encodeURIComponent(next)}` : ''
  return `${backend}/api/v1/auth/sso/start?org_slug=${encodeURIComponent(org)}${destination}`
}

const Login = async ({
  searchParams,
}: {
  searchParams: Promise<{ next?: string }>
}) => {
  // Where the guard that bounced them here was sending them. It rides in the
  // login state and comes back as the post-login destination, so a deep link
  // survives the hop instead of dumping an admin on the org picker.
  const next = safeNext((await searchParams)?.next)
  // `redirect()` throws to unwind, so it MUST stay outside the try above.
  redirect((await ssoStartUrl(next)) ?? WC_LOGIN_URL)
}

export default Login
