# Security notes

## Backend proxy (Cloudflare Worker) — a hard requirement, not optional

The proxy at `proxy.cellblock.cc` exists for two hard requirements confirmed
against the live FordConnect 2.0 API, not optional hardening:

1. **Token exchange.** FordConnect's token endpoint requires a `client_secret`
   in both the auth-code and refresh-token exchange bodies — there's no
   PKCE `code_verifier` field in the real API. A `client_secret` cannot live
   in browser JS, so a server-side proxy is required.

2. **CORS.** `api.vehicle.ford.com` sends no CORS headers. Browsers cannot
   call it directly regardless of how valid the bearer token is, so all
   vehicle-data requests are also routed through the proxy.

The proxy is deployed as a Cloudflare Worker (`cellblock-proxy`) at
`proxy.cellblock.cc`. Source: `worker/index.js`.

## What the Worker holds

- `CLIENT_ID` and `CLIENT_SECRET` — set via `wrangler secret put`, never
  in the repo or accessible from the browser
- `ALLOWED_ORIGIN` — a plain env var listing allowed origins (enforced
  server-side, not just CORS headers)

## What lives in the browser

- **Access token:** memory only, never persisted anywhere.
- **Refresh token:** `localStorage`, wrapped with an explicit expiry so a
  stolen token (e.g. via XSS) is only useful for a bounded window.
  Currently uses a 14-day fallback if Ford doesn't return an explicit
  `refresh_token_expires_in`.

## Threat model & future work

**Current risk:** A stolen refresh token gives an attacker real-time access to
the vehicle's GPS position (lat/lon/heading/speed), door state, tire
pressure, battery level, and VIN. Ford's `/fcon-query/v1/*` endpoints are
READ-ONLY telemetry — an attacker cannot unlock, start, or control the
vehicle — but the surveillance capability (knowing where the owner's truck
is in real time) is real.

The properly secure pattern would be the proxy setting the refresh token as
an **HttpOnly, Secure, SameSite=Strict cookie** so JavaScript never touches
it at all. This would require:

- Using a Workers + Pages integration or a full server framework to set
  cookies on the token/refresh responses
- Modifying the auth flow so the proxy handles token management entirely
  (the browser never sees raw tokens)
- A logout endpoint that clears the cookie

This hasn't been implemented yet because:

- The FordConnect API's auth flow is already complex (Azure AD B2C, custom
  redirect handling, the `/auth/init` wrapper endpoint) and adding cookie
  management would increase surface area
- The current localStorage approach is the same threat model as every other
  SPA OAuth integration (GitHub, Google, etc.) — the primary risk is XSS,
  which would compromise the app regardless of auth token location

**Status:** CellBlock is now live on a public domain (cellblock.cc) with
real vehicle data. The HttpOnly cookie upgrade is the single highest-leverage
security improvement available — worth prioritizing if usage expands beyond
the owner.

## Data accuracy

- `/garage` shape: confirmed live (single-vehicle flat object with `vin`)
- `/telemetry` shape: confirmed live (flat `metrics.<name>.value` bag)
- `/vehicle-health/alerts` shape: confirmed live (`VehicleAlertList` array,
  per-vehicle `ActiveAlerts`)
- Populated alert-object shape (inside `ActiveAlerts`): **still an
  unconfirmed guess** — the test account's alerts were empty. When a
  populated alert is first observed, the raw JSON is logged to console so
  the real field names can be captured.

## Worker origin enforcement

The Worker's token and data endpoints are protected by a server-side origin
check: requests from origins not in `ALLOWED_ORIGIN` receive a 403
response. This prevents external sites or scripts from using the proxy to
mint Ford tokens or consume the account's rate-limit budget.
