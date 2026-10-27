import { NextRequest } from 'next/server'
import { proxyToBackend } from '@services/proxy/backend-proxy'

/**
 * Same-origin media, so stored images load from whatever origin the viewer
 * arrived on — LAN address, tailnet name or a real domain.
 *
 * It lives under `/api/` rather than at `/content/` because a root-level
 * `/content` route handler is not reached by this app's router, while every
 * `/api/*` handler is. The prefix is stripped and the backend's own
 * `/content/...` path is called, so stored URLs are unchanged.
 *
 * Read-only: media is written through the API's block endpoints.
 */
export const maxDuration = 300
export const dynamic = 'force-dynamic'
export const fetchCache = 'force-no-store'

const PREFIX = '/api/media'

function backendPath(request: NextRequest): string {
  return request.nextUrl.pathname.slice(PREFIX.length) || '/'
}

export async function GET(request: NextRequest) {
  return proxyToBackend(request, backendPath(request))
}

export async function HEAD(request: NextRequest) {
  return proxyToBackend(request, backendPath(request))
}
