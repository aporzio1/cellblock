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

function corsHeaders(env, request) {
  const allowed = (env.ALLOWED_ORIGIN || '*').split(',').map(o => o.trim());
  const requestOrigin = request.headers.get('origin');
  const matched = allowed.includes('*') ? '*' : (allowed.includes(requestOrigin) ? requestOrigin : allowed[0]);
  return {
    'Access-Control-Allow-Origin': matched,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Vary': 'Origin'
  };
}

// Server-side origin enforcement: reject requests from non-allowed origins
// (not just CORS headers — actual 403 for curl/bots too).
// Browser-initiated fetches always send Origin; curl/CLI clients won't have one,
// which is fine since only the CellBlock frontend should hit these endpoints.
function enforceOrigin(env, request) {
  const allowed = (env.ALLOWED_ORIGIN || '').split(',').map(o => o.trim()).filter(Boolean);
  if (allowed.length === 0 || allowed.includes('*')) return null; // wide open
  const origin = request.headers.get('origin');
  if (!origin || !allowed.includes(origin)) {
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
      // Enforce origin on auth/token/data endpoints (vehicle-image is proxied separately)
      if (url.pathname !== DATA_PREFIX + 'vehicle-image') {
        const blocked = enforceOrigin(env, request);
        if (blocked) return json(env, request, 403, blocked);
      }

      if (request.method === 'POST' && url.pathname === '/api/token') {
        const { code, redirect_uri } = await request.json().catch(() => ({}));
        if (!code || !redirect_uri) return json(env, request, 400, { error: 'code and redirect_uri are required' });

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

        return exchangeToken(env, request, {
          grant_type: 'refresh_token',
          refresh_token,
          redirect_uri: redirect_uri || '',
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
          headers: { 'User-Agent': 'Mozilla/5.0 (compatible; CellBlock/1.0)' }
        });

        if (imageResp.ok) {
          const headers = new Headers(imageResp.headers);
          headers.set('Cache-Control', 'public, max-age=86400');
          headers.set('Access-Control-Allow-Origin', '*');
          return new Response(imageResp.body, { headers });
        }

        const auth = request.headers.get('authorization');
        const fordResp = await fetch(`${FORD_DATA_BASE}/vehicle-image?vin=${vin}`, {
          headers: { 'Authorization': auth || '', 'Accept': 'application/json' }
        });
        if (fordResp.ok) {
          const data = await fordResp.json();
          const fallbackUrl = data.vehicleImage;
          if (fallbackUrl) {
            const fallbackImg = await fetch(fallbackUrl, {
              headers: { 'User-Agent': 'Mozilla/5.0 (compatible; CellBlock/1.0)' }
            });
            if (fallbackImg.ok) {
              const headers = new Headers(fallbackImg.headers);
              headers.set('Cache-Control', 'public, max-age=86400');
              headers.set('Access-Control-Allow-Origin', '*');
              return new Response(fallbackImg.body, { headers });
            }
          }
        }
        return json(env, request, 502, { error: 'Image unavailable' });
      }

      if (request.method === 'GET' && url.pathname.startsWith(DATA_PREFIX)) {
        const suffix = url.pathname.slice(DATA_PREFIX.length) + url.search;
        const auth = request.headers.get('authorization');
        if (!auth) return json(env, request, 401, { error: 'Authorization header is required' });

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
        if (retryAfter) headers['Retry-After'] = retryAfter;
        return new Response(body, { status: fordResp.status, headers });
      }

      return json(env, request, 404, { error: 'Not found' });
    } catch (err) {
      return json(env, request, 502, { error: 'Proxy request failed' });
    }
  }
};
