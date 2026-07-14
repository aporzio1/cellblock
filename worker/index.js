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
  return new Response(body, {
    status: resp.status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(env, request) }
  });
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

      if (request.method === 'GET' && url.pathname.startsWith(DATA_PREFIX)) {
        const suffix = url.pathname.slice(DATA_PREFIX.length) + url.search;
        const auth = request.headers.get('authorization');
        if (!auth) return json(env, 401, { error: 'Authorization header is required' });

        const fordResp = await fetch(`${FORD_DATA_BASE}/${suffix}`, {
          headers: { Authorization: auth, 'Accept': 'application/json' }
        });
        const body = await fordResp.text();
        return new Response(body, {
          status: fordResp.status,
          headers: {
            'Content-Type': fordResp.headers.get('content-type') || 'application/json',
            ...corsHeaders(env, request)
          }
        });
      }

      return json(env, request, 404, { error: 'Not found' });
    } catch (err) {
      return json(env, request, 502, { error: 'Proxy request failed', detail: String(err) });
    }
  }
};
