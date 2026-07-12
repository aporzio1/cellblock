// Minimal proxy for Lightning Rod. Two jobs:
//
// 1. Token exchange — FordConnect's OAuth token endpoint (Azure AD B2C)
//    requires a client_secret in both the auth-code and refresh-token
//    exchange bodies (see FordConnect-2.0-Postman collection, "Auth Code
//    Exchange" / "Refresh Token Exchange"). A client_secret can never be
//    embedded in browser JS (view-source leaks it instantly), so this holds
//    the secret and performs those two token operations on the browser's
//    behalf via POST /api/token and POST /api/refresh.
//
// 2. Data passthrough — api.vehicle.ford.com sends no CORS headers at all
//    (confirmed live: a direct browser fetch to /fcon-query/v1/garage with a
//    bearer token fails with "TypeError: Failed to fetch" / no
//    Access-Control-Allow-Origin), so the browser can never call the data
//    endpoints directly no matter how valid the bearer token is. GET
//    /api/data/<rest-of-path> forwards to
//    https://api.vehicle.ford.com/fcon-query/v1/<rest-of-path> with the
//    client's Authorization header passed through, and adds the CORS
//    headers Ford doesn't. This proxy never inspects or stores that bearer
//    token — it's forwarded as-is, same as any reverse proxy.
//
// Run with: node --env-file=.env index.js
// Requires: CLIENT_ID, CLIENT_SECRET, PORT (optional, default 8787),
//           ALLOWED_ORIGIN (optional, default *)

import { createServer } from 'node:http';

const {
  CLIENT_ID,
  CLIENT_SECRET,
  PORT = '8787',
  ALLOWED_ORIGIN = '*'
} = process.env;

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error('Missing CLIENT_ID or CLIENT_SECRET in environment. Copy server/env.sample to server/.env and fill it in.');
  process.exit(1);
}

// Real FordConnect endpoints — confirmed from the FordConnect-2.0-Postman
// collection.
const FORD_TOKEN_URL = 'https://api.vehicle.ford.com/dah2vb2cprod.onmicrosoft.com/oauth2/v2.0/token?p=B2C_1A_FCON_AUTHORIZE';
const FORD_DATA_BASE = 'https://api.vehicle.ford.com/fcon-query/v1';
const SCOPE = `${CLIENT_ID} offline_access openid`;
const DATA_PREFIX = '/api/data/';

async function readJsonBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!raw) return {};
  return JSON.parse(raw);
}

async function exchangeToken(params) {
  const resp = await fetch(FORD_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params)
  });
  const body = await resp.text();
  return { status: resp.status, body };
}

function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

function sendJson(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}

const server = createServer(async (req, res) => {
  setCors(res);

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  try {
    if (req.method === 'POST' && req.url === '/api/token') {
      const { code, redirect_uri } = await readJsonBody(req);
      if (!code || !redirect_uri) return sendJson(res, 400, { error: 'code and redirect_uri are required' });

      const { status, body } = await exchangeToken({
        grant_type: 'authorization_code',
        code,
        redirect_uri,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        scope: SCOPE
      });
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(body);
      return;
    }

    if (req.method === 'POST' && req.url === '/api/refresh') {
      const { refresh_token, redirect_uri } = await readJsonBody(req);
      if (!refresh_token) return sendJson(res, 400, { error: 'refresh_token is required' });

      const { status, body } = await exchangeToken({
        grant_type: 'refresh_token',
        refresh_token,
        redirect_uri: redirect_uri || '',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        scope: SCOPE
      });
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(body);
      return;
    }

    if (req.method === 'GET' && req.url.startsWith(DATA_PREFIX)) {
      const suffix = req.url.slice(DATA_PREFIX.length); // path + query, already encoded
      const auth = req.headers['authorization'];
      if (!auth) return sendJson(res, 401, { error: 'Authorization header is required' });

      const fordResp = await fetch(`${FORD_DATA_BASE}/${suffix}`, {
        headers: { Authorization: auth, Accept: 'application/json' }
      });
      const body = await fordResp.text();
      res.writeHead(fordResp.status, { 'Content-Type': fordResp.headers.get('content-type') || 'application/json' });
      res.end(body);
      return;
    }

    sendJson(res, 404, { error: 'Not found' });
  } catch (err) {
    console.error(err);
    sendJson(res, 502, { error: 'Proxy request failed', detail: String(err) });
  }
});

server.listen(Number(PORT), () => {
  console.log(`Lightning Rod token proxy listening on :${PORT}`);
});
