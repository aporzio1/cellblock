# Security notes

## Refresh token storage (current: bounded-expiry localStorage)

`app.js` stores the Ford OAuth refresh token in `localStorage` as
`{ token, expiresAt }` (see `saveRefreshToken`/`loadRefreshToken`). This is a
deliberate tradeoff, not the ideal solution:

- **Why not sessionStorage:** forces a full Ford re-login every time the
  browser/tab closes. Rejected for UX — this app is meant to persist across
  restarts like a normal "remembered" login.
- **Why an expiry wrapper instead of a bare token:** a bare `localStorage`
  string never expires, so a stolen token (e.g. via an XSS bug in this page
  or a future dependency) would be a permanent skeleton key. The expiry
  bounds that window — 14 days by default, or whatever `refresh_token_expires_in`
  Ford's token response provides.
- **Why not an HttpOnly cookie:** that's the actually-secure option (refresh
  token never readable by JavaScript at all), but it requires a server-side
  token endpoint to set it. This is currently a static, backend-less SPA —
  no server exists to own that cookie.

## To evaluate later

If this ever moves beyond a personal static-hosted dashboard (shared hosting,
a real domain, multiple users, anything raising the value of a stolen
token), revisit:

1. Stand up a small backend (even a thin proxy in front of Ford's OAuth
   endpoints) whose only job is the token exchange/refresh.
2. Have it set the refresh token as an `HttpOnly; Secure; SameSite=Strict`
   cookie, scoped to that backend's origin.
3. The frontend then never touches the refresh token directly — it just
   calls the backend, which attaches the cookie automatically and proxies
   to Ford.

Until then, the localStorage + expiry approach is the pragmatic middle
ground: no forced re-login, bounded exposure if the page is ever
compromised.
