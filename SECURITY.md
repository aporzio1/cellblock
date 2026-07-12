# Security notes

## Backend proxy (server/) — a hard requirement, not an optional hardening step

`server/` exists for two reasons, both hard requirements confirmed against
the live API, not optional hardening:

1. **Token exchange.** FordConnect's real token endpoint (Azure AD B2C)
   requires a `client_secret` in both the auth-code and refresh-token
   exchange bodies — there's no PKCE `code_verifier` field in the real
   request at all. A `client_secret` can never be embedded in browser JS
   (view-source leaks it instantly), so the proxy holds that secret and
   performs the two token operations on the browser's behalf via
   `POST /api/token` and `POST /api/refresh`.
2. **Data passthrough.** `api.vehicle.ford.com` sends no CORS headers at
   all — confirmed live, a direct browser `fetch` to its data endpoints
   fails (`TypeError: Failed to fetch`) no matter how valid the bearer
   token is. So `GET /api/data/<path>` forwards to Ford's real
   `/fcon-query/v1/<path>` with the browser's `Authorization` header passed
   through as-is, and adds the CORS headers Ford doesn't send. The proxy
   doesn't inspect or store that bearer token or the vehicle data it
   returns — it's a passthrough, same as any reverse proxy.

See `server/index.js` for the implementation and `server/env.sample` for the
required environment variables (`CLIENT_ID`, `CLIENT_SECRET`, `PORT`,
`ALLOWED_ORIGIN`) — `.env` itself is gitignored, never commit real values.

Neither of these is "nice to have eventually" — without this proxy, the app
cannot authenticate against or fetch data from the real FordConnect API at
all: the secret can't reach Ford without being exposed, and the browser
can't reach Ford's data endpoints directly regardless.

## Refresh token storage (current: bounded-expiry localStorage)

`app.js` stores the token *returned by the proxy* in `localStorage` as
`{ token, expiresAt }` (see `saveRefreshToken`/`loadRefreshToken`). The proxy
existing does not change this tradeoff — it only keeps `client_secret` out
of the browser. The refresh token itself is still a plain value the browser
holds:

- **Why not sessionStorage:** forces a full Ford re-login every time the
  browser/tab closes. Rejected for UX — this app is meant to persist across
  restarts like a normal "remembered" login.
- **Why an expiry wrapper instead of a bare token:** a bare `localStorage`
  string never expires, so a stolen token (e.g. via an XSS bug in this page
  or a future dependency) would be a permanent skeleton key. The expiry
  bounds that window — 14 days by default, or whatever `refresh_token_expires_in`
  Ford's token response provides.
- **Why not an HttpOnly cookie:** that's the actually-secure option (refresh
  token never readable by JavaScript at all) — and unlike before, a server
  now exists that *could* set one. This just hasn't been done yet.

## To evaluate later

The proxy in `server/` could be extended to set the refresh token as an
`HttpOnly; Secure; SameSite=Strict` cookie scoped to its own origin instead
of returning it to the browser as JSON:

1. `/api/token` and `/api/refresh` set the cookie directly in the response
   instead of returning `refresh_token` in the body.
2. The frontend drops `saveRefreshToken`/`loadRefreshToken`/`localStorage`
   entirely — it just calls the proxy, which attaches the cookie
   automatically and proxies to Ford.
3. `apiCall`'s 401 → refresh flow becomes a plain `fetch` to the proxy with
   `credentials: 'include'`; the browser never touches the refresh token at
   all.

Worth doing if this moves beyond a personal dashboard (shared hosting, a
real domain, multiple users, anything raising the value of a stolen token).
Until then, localStorage + expiry is the pragmatic middle ground: no forced
re-login, bounded exposure if the page is ever compromised.

## Data-layer accuracy caveat

`app.js`'s field mappings for `/telemetry`, `/garage`, etc. (see the comment
at the top of `renderDashboard` and `firstVin`) are best-effort guesses —
the FordConnect-2.0-Postman collection has no saved example responses for
any endpoint. Verify against a real API response and correct the
optional-chaining paths once you have one; this is expected follow-up work,
not a bug in the current implementation.
