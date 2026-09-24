import { originOverrides } from './origin-config'

// Runtime configuration cache
let runtimeConfig: Record<string, string> | null = null;
let serverConfigLoaded = false;

// Lazy load runtime configuration
function loadRuntimeConfig(): Record<string, string> {
  if (typeof window !== 'undefined') {
    // Client-side: always read from window.__RUNTIME_CONFIG__ (may be injected after first call)
    if ((window as any).__RUNTIME_CONFIG__) {
      runtimeConfig = (window as any).__RUNTIME_CONFIG__;
    }
    return runtimeConfig || {};
  }

  // Server-side: cache after first successful load
  if (serverConfigLoaded && runtimeConfig) {
    return runtimeConfig;
  }

  runtimeConfig = {};

  if (typeof window === 'undefined') {
    // Server-side: try to read from runtime-config.json
    // Try multiple possible paths for standalone mode
    try {
      const fs = require('fs');
      const path = require('path');

      // In standalone mode, runtime-config.json is in the same directory as server.js
      // Try common possible locations relative to the current working directory and module
      const possiblePaths = [
        path.join(process.cwd(), 'runtime-config.json'),
        path.join(__dirname || process.cwd(), 'runtime-config.json'),
        path.join(__dirname || process.cwd(), '..', 'runtime-config.json'),
      ];

      for (const configPath of possiblePaths) {
        try {
          if (fs.existsSync(configPath)) {
            runtimeConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
            break;
          }
        } catch {
          // Continue to next path
        }
      }
    } catch {
      // fs/path not available (client-side bundle), skip
    }
    serverConfigLoaded = true;
  }

  return runtimeConfig || {};
}

// Helper function to get config value with fallback
export const getConfig = (key: string, defaultValue: string = ''): string => {
  const raw = loadRuntimeConfig();
  const config = typeof window === "undefined" ? raw : { ...raw, ...originOverrides(raw, window.location.origin) };

  // 1. Check runtime config (from runtime-config.json or the generated runtime-config.js)
  if (config && config[key]) {
    return config[key];
  }

  // 2. Fallback to process.env (Server-side only)
  return process.env[key] || defaultValue;
};

// Helper to read a cookie value by name (client-side only)
export const getCookieValue = (name: string): string | null => {
  if (typeof window === 'undefined') return null
  try {
    const match = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'))
    return match ? decodeURIComponent(match[1]) : null
  } catch {
    return null
  }
}
