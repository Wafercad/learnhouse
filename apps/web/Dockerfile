FROM oven/bun:1-alpine AS base

# Install dependencies only when needed
FROM base AS deps
RUN apk update && apk add --no-cache libc6-compat && rm -rf /var/cache/apk/*
WORKDIR /app

COPY package.json bun.lock* ./
RUN bun install --frozen-lockfile

# Rebuild the source code only when needed
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

ENV NEXT_TELEMETRY_DISABLED=1

RUN rm -f .env*

# Remove Enterprise Edition folder for public/OSS builds
ARG LEARNHOUSE_PUBLIC=false
RUN if [ "$LEARNHOUSE_PUBLIC" = "true" ]; then rm -rf /app/ee; fi

ARG release_media_external=false
ENV WC_PLATFORM_MEDIA_ENABLED=$release_media_external
COPY --from=release_media_tools /split.mjs /tmp/split-media.mjs
RUN bun run build
RUN mkdir -p /release-media && \
    if [ "$release_media_external" = true ]; then \
      bun scripts/extract-release-media.mjs /tmp/split-media.mjs; \
    else echo '{}' > release-media.json; echo '{}' > release-media-manifest.json; fi

FROM scratch AS release-media
COPY --from=builder /release-media /


# Production image — use Node for the Next.js standalone server
FROM node:24-alpine AS runner
WORKDIR /app

RUN apk update && apk add --no-cache curl && rm -rf /var/cache/apk/*

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

COPY --from=builder --chown=nextjs:nodejs /app/public ./public

RUN mkdir .next
RUN chown nextjs:nodejs .next

COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

COPY --from=builder --chown=nextjs:nodejs /app/release-media.json /app/release-media-manifest.json ./
COPY --chown=nextjs:nodejs server-wrapper.js ./
RUN chmod +x server-wrapper.js

COPY --chown=nextjs:nodejs docker-entrypoint.sh ./
RUN chmod +x docker-entrypoint.sh

RUN rm -f public/runtime-config.js && touch runtime-config.json && chown nextjs:nodejs runtime-config.json

USER nextjs

EXPOSE 3000

ENV PORT=3000

ENTRYPOINT ["./docker-entrypoint.sh"]
