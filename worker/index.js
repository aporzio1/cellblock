import { DurableObject } from 'cloudflare:workers';
import { handleInstallationRequest, verifyFordAuthorization } from './installations.js';
import { runScheduledMonitoring } from './monitoring.js';

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
const VIN_AUTHORIZATION_TTL_MS = 5 * 60_000;

// Separate hashed identities for verified vehicles, non-VIN tokens, and
// authorization-check IPs. Membership proof uses a token+VIN object, never
// the shared vehicle object. No raw bearer or VIN is persisted.
// Extending DurableObject is required for `stub.allow()` / `stub.defer()` RPC.
export class FordRateLimiter extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
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

  hasAuthorization() {
    return (this.ctx.storage.kv.get('authorizedUntil') || 0) > Date.now();
  }

  authorize() {
    this.ctx.storage.kv.put('authorizedUntil', Date.now() + VIN_AUTHORIZATION_TTL_MS);
  }

  revokeAuthorization() {
    this.ctx.storage.kv.delete('authorizedUntil');
  }
}

function corsHeaders(env, request) {
  const allowed = (env.ALLOWED_ORIGIN || '*').split(',').map(o => o.trim());
  const requestOrigin = request.headers.get('origin');
  const matched = allowed.includes('*') ? '*' : (allowed.includes(requestOrigin) ? requestOrigin : allowed[0]);
  return {
    'Access-Control-Allow-Origin': matched,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
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

const VIN_PATTERN = /^[A-HJ-NPR-Z0-9]{17}$/;

// Ford's request budget is per vehicle. Telemetry reads carry a vin param,
// so those requests share one limiter bucket keyed by VIN — that is how the
// iOS app and the Live Activities cron serialize instead of blindly
// competing for the same budget. Paths without a vin fall back to the
// per-token bucket.
async function objectFor(env, digestInput) {
  const data = new TextEncoder().encode(digestInput);
  const digest = await crypto.subtle.digest('SHA-256', data);
  const key = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
  return env.FORD_RATE_LIMITER.get(env.FORD_RATE_LIMITER.idFromName(key));
}

// Fail closed BEFORE even looking up the shared vehicle limiter. Durable
// Object storage (rather than eventually consistent KV) makes revocation
// visible on the next request across locations. Only positive proof is cached.
async function authorizeVIN(env, request, token, vin) {
  try {
    const membership = await objectFor(env, `vin-authorization:${JSON.stringify([token, vin])}`);
    if (await membership.hasAuthorization()) return { membership };

    // Cloudflare supplies this header at ingress. Never trust X-Forwarded-For
    // or a caller-selected token/VIN for this budget. Missing ingress identity
    // gets a single shared fallback, not an unlimited/new bucket per request.
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown-ingress';
    const validationLimiter = await objectFor(env, `vin-authorization-ip:${ip}`);
    const permission = await validationLimiter.allow();
    if (!permission.allowed) {
      return { response: rateLimitedResponse(env, request, permission.retryAfterMs) };
    }

    const verification = await verifyFordAuthorization(token, fetch);
    if (verification.error === 'rejected') {
      return { response: json(env, request, 401, { error: 'Ford authorization required' }) };
    }
    const vehicles = verification.garage?.vehicles;
    if (verification.error || !Array.isArray(vehicles) || vehicles.some(vehicle =>
      !vehicle || typeof vehicle.vin !== 'string' || !VIN_PATTERN.test(vehicle.vin))) {
      return { response: json(env, request, 503, { error: 'Authorization service unavailable' }) };
    }
    if (!vehicles.some(vehicle => vehicle.vin === vin)) {
      return { response: json(env, request, 403, { error: 'Vehicle authorization required' }) };
    }
    await membership.authorize();
    return { membership };
  } catch {
    return { response: json(env, request, 503, { error: 'Authorization service unavailable' }) };
  }
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

    // Native installation and Live Activity requests authenticate with the
    // installation credential, independently of Ford proxy secrets.
    if (url.pathname !== DATA_PREFIX + 'vehicle-image') {
      const blocked = enforceOrigin(env, request);
      if (blocked) return json(env, request, 403, blocked);
    }
    const installationResponse = await handleInstallationRequest(request, env);
    if (installationResponse) return installationResponse;

    if (!env.CLIENT_ID && !env.FORD_CLIENT_ID) {
      return json(env, request, 500, { error: 'Worker missing CLIENT_ID/CLIENT_SECRET secrets' });
    }
    const clientId = env.CLIENT_ID || env.FORD_CLIENT_ID;
    const clientSecret = env.CLIENT_SECRET || env.FORD_CLIENT_SECRET;
    const scope = `${clientId} offline_access openid`;

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
          client_id: clientId,
          client_secret: clientSecret,
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
          client_id: clientId,
          client_secret: clientSecret,
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
        const bearer = auth && auth.length <= 8192 && /^Bearer ([A-Za-z0-9._~+/-]+=*)$/i.exec(auth);
        if (!bearer) return json(env, request, 401, { error: 'Ford authorization required' });

        const vins = url.searchParams.getAll('vin');
        if (vins.length > 1 || (vins.length === 1 && !VIN_PATTERN.test(vins[0]))) {
          return json(env, request, 400, { error: 'Invalid vin parameter' });
        }
        const vin = vins[0];
        let membership;
        if (vin !== undefined) {
          const proof = await authorizeVIN(env, request, bearer[1], vin);
          if (proof.response) return proof.response;
          membership = proof.membership;
        }
        const limiter = await objectFor(env, vin === undefined ? `token:${auth}` : `vehicle:${vin}`);
        const permission = await limiter.allow();
        if (!permission.allowed) {
          return rateLimitedResponse(env, request, permission.retryAfterMs);
        }

        const fordResp = await fetch(`${FORD_DATA_BASE}/${suffix}`, {
          headers: { 'Authorization': auth, 'Accept': 'application/json' },
          // Never forward the bearer token to a redirect destination. Handle a
          // Ford auth redirect as a credential failure instead of letting
          // redirect:error turn it into a misleading proxy 502.
          redirect: 'manual'
        });
        if (fordResp.status >= 300 && fordResp.status < 400) {
          if (membership) await membership.revokeAuthorization();
          try { await fordResp.body?.cancel(); } catch { /* release is best-effort */ }
          return json(env, request, 401, { error: 'Ford authorization required', code: 'ford_auth_redirect' });
        }
        if (membership && (fordResp.status === 401 || fordResp.status === 403)) {
          await membership.revokeAuthorization();
        }
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
      // Keep internal details out of client responses, but retain enough
      // context in Workers Logs to diagnose an upstream Ford failure.
      console.error('Proxy request failed', {
        method: request.method,
        path: url.pathname,
        message: err instanceof Error ? err.message : String(err)
      });
      return json(env, request, 502, { error: 'Proxy request failed' });
    }
  },

  async scheduled(_controller, env, ctx) {
    // Keep the cron invocation best-effort: one malformed authorization or
    // unavailable upstream must never abort the remaining installations.
    const work = runScheduledMonitoring(env).catch(() => undefined);
    if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(work);
    else await work;
  }
};
