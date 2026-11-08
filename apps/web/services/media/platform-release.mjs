/** Release media is platform-owned. This module never reads tenant credentials. */
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

let cached;
export function readRelease(root = process.cwd(), enabled = process.env.WC_PLATFORM_MEDIA_ENABLED) {
  if (enabled !== 'true') return null;
  if (cached?.root === root) return cached.value;
  const raw = fs.readFileSync(path.join(root, 'release-media-manifest.json'));
  const meta = JSON.parse(fs.readFileSync(path.join(root, 'release-media.json'), 'utf8'));
  const manifest = JSON.parse(raw);
  if (raw.length > 8 * 1024 * 1024 || manifest.product !== 'learnhouse' ||
      meta.product !== 'learnhouse' || createHash('sha256').update(raw).digest('hex') !== meta.release ||
      !manifest.files || Array.isArray(manifest.files)) throw new Error('Invalid platform release');
  const value = { release: meta.release, files: manifest.files };
  cached = { root, value };
  return value;
}

export function isReleaseMedia(pathname, release = readRelease()) {
  let name;
  try { name = decodeURIComponent(pathname).replace(/^\//, ''); } catch { return false; }
  return !!release && Object.hasOwn(release.files, name);
}

export async function deliverMedia(request, segments, options = {}) {
  const release = options.release ?? readRelease();
  const name = segments.join('/');
  if (!release || !Object.hasOwn(release.files, name) ||
      segments.some(v => !v || v.startsWith('.') || /[\\/%?#\x00-\x1f]/.test(v))) {
    return new Response('Media not found', { status: 404, headers: { 'Cache-Control': 'no-store' } });
  }
  if (!['GET','HEAD'].includes(request.method)) return new Response(null, {status:405});
  const origin = options.origin ?? process.env.PLATFORM_MEDIA_ORIGIN;
  if (!origin) return new Response('Media unavailable', { status:503 });
  const headers = new Headers();
  for (const key of ['range','if-none-match','if-range']) {
    const value = request.headers.get(key);
    if (value) headers.set(key,value);
  }
  const target = new URL('/platform-media/v1/learnhouse/'+release.release+'/'+segments.map(encodeURIComponent).join('/'),origin);
  try {
    const upstream = await (options.fetch ?? fetch)(target,{
      method:request.method,headers,redirect:'error',cache:'no-store',
      signal:AbortSignal.any([request.signal,AbortSignal.timeout(30000)]),
    });
    const responseHeaders = new Headers();
    for (const key of ['content-type','content-length','content-range','etag','cache-control',
      'accept-ranges','content-security-policy','x-content-type-options','referrer-policy']) {
      const value = upstream.headers.get(key);
      if (value) responseHeaders.set(key,value);
    }
    return new Response(request.method === 'HEAD' ? null : upstream.body,
      {status:upstream.status,headers:responseHeaders});
  } catch {
    return new Response('Media unavailable',{status:503,headers:{'Cache-Control':'no-store'}});
  }
}
