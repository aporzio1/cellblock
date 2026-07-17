// Lightning Rod token/data proxy — Cloudflare Worker port of server/index.js.
//
// Same three jobs as the Node version (see server/index.js for the full
// rationale):
//   POST /api/token    — auth-code exchange; holds CLIENT_SECRET server-side
//   POST /api/refresh  — refresh-token exchange
//   GET  /api/data/*   — passthrough to Ford's /fcon-query/v1/* (Ford sends
//                        no CORS headers, so browsers can't call it directly)
//
// Secrets/config come from Worker env (never in the repo):
//   wrangler secret put CLIENT_ID
//   wrangler secret put CLIENT_SECRET
//   ALLOWED_ORIGIN is a plain var in wrangler.toml — comma-separated list of
//   allowed origins (supports multiple, e.g. during a domain migration).

const FORD_TOKEN_URL = 'https://api.vehicle.ford.com/dah2vb2cprod.onmicrosoft.com/oauth2/v2.0/token?p=B2C_1A_FCON_AUTHORIZE';
const FORD_DATA_BASE = 'https://api.vehicle.ford.com/fcon-query/v1';
const FORD_BUILDER_URL = 'https://build.ford.com/dig/direct/HD-FULL/Vin[VIN]/EXT/4/vehicle.png';
const DATA_PREFIX = '/api/data/';
const REGISTERED_REDIRECT_URI = 'https://cellblock.cc/';
const FORD_REQUEST_INTERVAL_MS = 30_000;

// One Durable Object per active Ford bearer token serializes requests from
// separate browser tabs. The Worker stores only a SHA-256 digest, never the
// token itself. A token refresh creates a new limiter identity, while the
// browser queue prevents an immediate same-tab burst during that transition.
export class FordRateLimiter {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }

  allow() {
    const now = Date.now();
    const nextAllowedAt = this.ctx.storage.kv.get('nextAllowedAt') || 0;
    if (now < nextAllowedAt) {
      return { allowed: false, retryAfterMs: nextAllowedAt - now };
    }

    this.ctx.storage.kv.put('nextAllowedAt', now + FORD_REQUEST_INTERVAL_MS);
    return { allowed: true, retryAfterMs: 0 };
  }

  defer(retryAfterMs) {
    const now = Date.now();
    const nextAllowedAt = this.ctx.storage.kv.get('nextAllowedAt') || 0;
    const deferredUntil = now + Math.max(retryAfterMs, FORD_REQUEST_INTERVAL_MS);
    this.ctx.storage.kv.put('nextAllowedAt', Math.max(nextAllowedAt, deferredUntil));
  }
}

function corsHeaders(env, request) {
  const allowed = (env.ALLOWED_ORIGIN || '*').split(',').map(o => o.trim());
  const requestOrigin = request.headers.get('origin');
  const matched = allowed.includes('*') ? '*' : (allowed.includes(requestOrigin) ? requestOrigin : allowed[0]);
  return {
    'Access-Control-Allow-Origin': matched,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Expose-Headers': 'Retry-After',
    'Vary': 'Origin'
  };
}

// Server-side origin enforcement rejects explicit origins that are not allowed.
// Native URLSession requests have no Origin header; their route-specific
// credential checks below remain mandatory.
function enforceOrigin(env, request) {
    const allowed = (env.ALLOWED_ORIGIN || '').split(',').map(o => o.trim()).filter(Boolean);
    if (allowed.length === 0 || allowed.includes('*')) return null; // wide open
    const origin = request.headers.get('origin');
    if (origin && !allowed.includes(origin)) {
        return { error: 'Forbidden: origin not allowed' };
    }
  return null;
}

function json(env, request, status, obj) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(env, request) }
  });
}

function retryAfterMilliseconds(value) {
  if (!value) return FORD_REQUEST_INTERVAL_MS;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.ceil(seconds * 1000);
  const date = Date.parse(value);
  return Number.isFinite(date) ? Math.max(0, date - Date.now()) : FORD_REQUEST_INTERVAL_MS;
}

async function limiterFor(env, authorization) {
  const data = new TextEncoder().encode(authorization);
  const digest = await crypto.subtle.digest('SHA-256', data);
  const key = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
  return env.FORD_RATE_LIMITER.get(env.FORD_RATE_LIMITER.idFromName(key));
}

function rateLimitedResponse(env, request, retryAfterMs) {
  const retryAfterSeconds = Math.max(1, Math.ceil(retryAfterMs / 1000));
  return new Response(JSON.stringify({ error: 'Ford request cooldown active', retryAfterSeconds }), {
    status: 429,
    headers: {
      'Content-Type': 'application/json',
      'Retry-After': String(retryAfterSeconds),
      ...corsHeaders(env, request)
    }
  });
}

async function exchangeToken(env, request, params) {
  const resp = await fetch(FORD_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params)
  });
  const body = await resp.text();
  const headers = { 'Content-Type': 'application/json', ...corsHeaders(env, request) };
  // Pass through Retry-After if Ford rate-limited us
  const retryAfter = resp.headers.get('Retry-After');
  if (retryAfter) headers['Retry-After'] = retryAfter;
  return new Response(body, { status: resp.status, headers });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(env, request) });
    }

    if (!env.CLIENT_ID || !env.CLIENT_SECRET) {
      return json(env, request, 500, { error: 'Worker missing CLIENT_ID/CLIENT_SECRET secrets' });
    }
    const scope = `${env.CLIENT_ID} offline_access openid`;

    try {
      // Enforce browser origins on auth/token/data endpoints. Native requests
      // have no Origin header and are admitted only after their credentials are
      // validated by the matching route below.
      if (url.pathname !== DATA_PREFIX + 'vehicle-image') {
        const blocked = enforceOrigin(env, request);
        if (blocked) return json(env, request, 403, blocked);
      }

      if (request.method === 'POST' && url.pathname === '/api/token') {
        const { code, redirect_uri } = await request.json().catch(() => ({}));
        if (!code || !redirect_uri) return json(env, request, 400, { error: 'code and redirect_uri are required' });
        if (redirect_uri !== REGISTERED_REDIRECT_URI) {
          return json(env, request, 400, { error: 'Invalid redirect_uri' });
        }

        return exchangeToken(env, request, {
          grant_type: 'authorization_code',
          code,
          redirect_uri,
          client_id: env.CLIENT_ID,
          client_secret: env.CLIENT_SECRET,
          scope
        });
      }

      if (request.method === 'POST' && url.pathname === '/api/refresh') {
        const { refresh_token, redirect_uri } = await request.json().catch(() => ({}));
        if (!refresh_token) return json(env, request, 400, { error: 'refresh_token is required' });
        if (redirect_uri !== REGISTERED_REDIRECT_URI) {
          return json(env, request, 400, { error: 'Invalid redirect_uri' });
        }

        return exchangeToken(env, request, {
          grant_type: 'refresh_token',
          refresh_token,
          redirect_uri,
          client_id: env.CLIENT_ID,
          client_secret: env.CLIENT_SECRET,
          scope
        });
      }

      // Vehicle image — fetch from Ford's builder directly and cache at edge
      if (request.method === 'GET' && url.pathname === DATA_PREFIX + 'vehicle-image') {
        const vin = url.searchParams.get('vin');
        if (!vin) return json(env, request, 400, { error: 'vin parameter is required' });

        const imageUrl = FORD_BUILDER_URL.replace('[VIN]', '[' + vin + ']');
        const imageResp = await fetch(imageUrl, {
          headers: { 'User-Agent': 'curl/8.4.0' }
        });

        if (imageResp.ok) {
          const headers = new Headers(imageResp.headers);
          headers.set('Cache-Control', 'public, max-age=86400');
          headers.set('Access-Control-Allow-Origin', '*');
          return new Response(imageResp.body, { headers });
        }

        // Do not fall back to Ford's telemetry API for an image. A dashboard
        // image is non-essential and must never consume the 30-second Ford
        // request budget; the browser uses a bundled model image instead.
        return json(env, request, 502, { error: 'Image unavailable' });
      }

      if (request.method === 'GET' && url.pathname.startsWith(DATA_PREFIX)) {
        const suffix = url.pathname.slice(DATA_PREFIX.length) + url.search;
        const auth = request.headers.get('authorization');
        if (!auth) return json(env, request, 401, { error: 'Authorization header is required' });

        const limiter = await limiterFor(env, auth);
        const permission = await limiter.allow();
        if (!permission.allowed) {
          return rateLimitedResponse(env, request, permission.retryAfterMs);
        }

        const fordResp = await fetch(`${FORD_DATA_BASE}/${suffix}`, {
          headers: { 'Authorization': auth, 'Accept': 'application/json' }
        });
        const body = await fordResp.text();
        const headers = {
          'Content-Type': fordResp.headers.get('content-type') || 'application/json',
          ...corsHeaders(env, request)
        };
        // Pass through Retry-After if Ford rate-limited us
        const retryAfter = fordResp.headers.get('Retry-After');
        if (fordResp.status === 429) {
          await limiter.defer(retryAfterMilliseconds(retryAfter));
        }
        if (retryAfter) headers['Retry-After'] = retryAfter;
        return new Response(body, { status: fordResp.status, headers });
      }

      return json(env, request, 404, { error: 'Not found' });
    } catch (err) {
      return json(env, request, 502, { error: 'Proxy request failed' });
    }
  }
};
