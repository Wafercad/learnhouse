import { deliverMedia } from '../../../../services/media/platform-release.mjs'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'
type Context = { params: Promise<{ path: string[] }> }

export async function GET(request: Request, context: Context) {
  return deliverMedia(request, (await context.params).path)
}
export const HEAD = GET
