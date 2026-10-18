# Security hardening guide

Covers Turnstile, rate limiting and client-IP handling, secure file access, what Cloudflare WAF can and cannot protect,
configuration, deployment order, and the risks that remain. Everything here describes what is in the repository; things
that could only be checked after deploying are marked **VERIFY**.

## 1. Cloudflare Turnstile (login, register, forgot password, reset password)

* Browser: `frontend/src/components/Turnstile.tsx` renders the Managed widget (no npm dependency; loads Cloudflare's script)
  with an `action` per form. Site key: `VITE_TURNSTILE_SITE_KEY` (public).
* API: `requireTurnstile(action)` runs after rate limiting and validation, before the controller. It calls
  `https://challenges.cloudflare.com/turnstile/v0/siteverify` with `TURNSTILE_SECRET_KEY` (server only).
* Rejected: missing token, oversized token (> 2048), invalid, expired (> 5 min), already redeemed (Cloudflare's
  `timeout-or-duplicate`, plus a local per-process replay guard), wrong `action` (token minted for another form), wrong
  `hostname` (not your site). The token is stripped from the body so it never reaches services or the database.
* Provider failure **fails closed**: network error, 5 s timeout, non-200, malformed JSON, `internal-error` or a rejected
  secret all return `503 TURNSTILE_UNAVAILABLE`. Nothing is let through.
* Production fails closed at boot: no `TURNSTILE_SECRET_KEY`, or one of Cloudflare's dummy test secrets (which accept any
  token), and the server refuses to start. Development without a secret skips verification (with a logged warning).
* Every rejection writes a `TURNSTILE_FAILED` audit row (reason code only, never the token or secret).
* Not covered: `POST /auth/resend-verification` (no form uses it; it is rate limited per client and per address) and
  `/auth/refresh`, `/auth/logout` (cookie + `X-Requested-With` protected).
* Local development: leave both keys empty, or use Cloudflare's documented dummy pair: site key
  `1x00000000000000000000AA` + secret `1x0000000000000000000000000000000AA` (always passes).

## 2. Rate limiting and client IP

| Limiter | Limit | Bucket |
|---|---|---|
| general API | 300 / 15 min | IP (per process; `/health` exempt) |
| login | 20 / 15 min | IP |
| login (account) | 8 failed / 15 min | account + IP (successful logins are not counted) |
| register | 10 / hour | IP |
| forgot password | 6 / hour (IP), 3 / hour (target address) | IP, address |
| reset password / verify email | 10 / hour, 20 / hour | IP |
| resend verification | 6 / hour (IP), 3 / hour (address) | IP, address |
| upload | 20 / 15 min | account |
| download | 60 / 15 min | account |
| share, link creation, access requests | 30 / 15 min | account |
| link redemption (password brute-force surface) | 30 / 15 min | IP |

Exceeding a limit returns **HTTP 429** with a `Retry-After` header and `{ code: "RATE_LIMITED", retryAfterSeconds }`
(the header is exposed to the browser through CORS). One log line and one `RATE_LIMITED` audit row are written per client per
window, so 429s cannot be used to flood the audit log. IPv6 clients are bucketed by /64.

**Limitations.** The default store is in memory: counters are per process and are wiped on every restart, deploy and Render
free-tier spin-down, and are not shared if you run more than one instance. `RATE_LIMIT_STORE=mongo` moves the strict limiters
(not the general one, which would add a database write to every request) into MongoDB (`ratelimits` collection, TTL index created at
boot). If the store errors the request is allowed and the error is logged (a Mongo outage breaks auth anyway).

### Client IP on Render (**VERIFY before trusting rate limits**)
Express derives `req.ip` from `X-Forwarded-For` using `TRUST_PROXY_HOPS` (default `1`). Community measurements of Render (not Render's
documentation) report that the header keeps whatever the client sent, then the real IP, then Cloudflare/internal hops, and that
requests carry `CF-Connecting-IP` / `True-Client-IP` set by Render's edge (a spoofed `CF-Connecting-IP` is rejected before it reaches
the service). If that is right, `trust proxy = 1` can resolve many visitors to one shared edge IP, which would make per-IP limits
global. Therefore:

1. Deploy with `CLIENT_IP_HEADER` empty. Check the effective value:
   `curl -s -X POST https://secureshare-zt.onrender.com/api/v1/auth/login -H "Content-Type: application/json" -H "X-Forwarded-For: 203.0.113.99" -d "{}"`
   then read the matching request line in Render's logs: the `ip` field.
2. It must be **your** public IP (check https://ifconfig.me), not `203.0.113.99`, and not a `10.x`/Cloudflare address. Repeat from a phone on mobile data: it must differ.
3. If it is wrong, set `CLIENT_IP_HEADER=cf-connecting-ip`, redeploy, repeat the test, and also try with `-H "CF-Connecting-IP: 203.0.113.99"` (must not change the logged IP).
4. Re-run this check after any Render networking change. A header is only safe to trust if clients cannot reach the service without passing through the edge that sets it.

## 3. Secure file access

Already in the codebase and kept as is: authentication on every file, link and room route; the access policy re-derived from
database state on every request (owner, grants, expiry, restricted-file rules, time locks, rooms); `404` instead of `403` so existence
is not revealed; ObjectId validation on every `:id`; server-generated storage keys with traversal checks in the local provider; no
static serving of the upload directory; integrity (SHA-256) check and audit-before-delivery on download; share links stored as
hashes, in the request body (not the URL), with expiry, revocation, download limits and attempt lockout.

Added in this change:
* New-version upload is authorised **before** the multipart body is buffered (a stranger can no longer make the API read 25 MB first).
* Filenames: one sanitiser (`utils/filename.ts`) for uploads and renames: strips path parts, control and bidi-override characters
  (`evil\u202Efdp.exe`), leading dots, trailing dots/spaces, Windows device names; keeps the extension when truncating. Names are metadata
  only; storage keys never contain them.
* Upload signatures: Office Open XML must contain `[Content_Types].xml` and its own part folder (a plain ZIP renamed `.docx` is rejected);
  type lookups use own-property checks (a `constructor` content type used to cause a 500, now a clean 415). Rejections are audited
  (`UPLOAD_REJECTED`, with reason, sanitised name, claimed type, size; never content).
* Downloads: `attachment` with an ASCII fallback and RFC 5987 name (no header injection), `Content-Type` only from the allow-list
  (otherwise `application/octet-stream`), `nosniff`, a sandboxing CSP, `no-store`.
* Sharing limiter on user shares, link creation and access requests.

Limits you should know: signature checks are not malware scanning. ZIP and the legacy Office formats (`.doc/.xls/.ppt`) can carry
malicious content or macros; they are served only as downloads. **Render's disk is ephemeral**: files written to `UPLOAD_DIR` disappear on
redeploy/restart unless a paid persistent disk is attached, while MongoDB keeps the metadata. Downloads of lost files then fail with
"The stored file is unavailable" (and an `ACCESS_DENIED / object_missing` audit row). A persistent disk limits you to one instance;
object storage (behind the existing `StorageProvider` interface) is the real fix. Uploads are held in memory while processed (up to
`MAX_UPLOAD_MB` each, 20 per user per 15 min): size your Render instance accordingly.

## 4. Cloudflare WAF: what protects what

| Target | Cloudflare WAF (managed rules, custom rules, rate-limit rules)? | What does apply today |
|---|---|---|
| `secureshare-zt.pages.dev` (frontend) | **No.** WAF rules are zone features and `pages.dev` is not your zone. | Cloudflare's platform-level DDoS mitigation for Pages, HTTPS, `frontend/public/_headers` (security headers), Turnstile on the forms. |
| `secureshare-zt.onrender.com` (API) | **No.** The hostname is Render's, not in your Cloudflare account. Render runs its own edge in front of the service, but you cannot configure it with your Cloudflare rules. | Everything in this repository: Turnstile, rate limits, CORS, validation, auth. |

Full zone-based protection requires **your own domain on Cloudflare** (Free plan is enough to start):
1. Add the domain to Cloudflare. Pages: add `app.example.com` as a custom domain of the Pages project.
2. Render: add `api.example.com` as a custom domain of the web service. Cloudflare DNS: `api` CNAME `secureshare-zt.onrender.com`, **proxied** (orange cloud). SSL/TLS mode **Full (strict)**.
3. Update: `CLIENT_URL=https://app.example.com`, `VITE_API_URL=https://api.example.com/api/v1`, the Turnstile widget hostnames, and (see below) `TRUST_PROXY_HOPS` / `CLIENT_IP_HEADER=cf-connecting-ip`.
4. Lock the origin: otherwise attackers simply call `*.onrender.com` and skip the WAF. Create a Transform Rule (Modify Request Header, static) setting `X-Origin-Verify: <random 32+ chars>` for `api.example.com`, then set `ORIGIN_VERIFY_SECRET` to the same value on Render (the API then rejects any request without it, except `/health`). Enable it only after step 2 works, never before.
5. Same-site cookies: `app.` and `api.` share a registrable domain, so the refresh cookie stops being third-party. Revisit `sameSite` in `auth.controller.ts` then (it is `none` today because `pages.dev` and `onrender.com` are different sites).

Suggested rules (free-plan quotas are small and change: check your dashboard; at the time of writing Free had the Free Managed Ruleset,
a handful of custom rules and **one** rate-limiting rule with a fixed 10 s window; the full Managed and OWASP rulesets need Pro):
* Enable the **Free Managed Ruleset** (on by default; Pro+: Cloudflare Managed + OWASP Core in log mode first, then block).
* Custom rule, Block: `http.host eq "api.example.com" and not starts_with(http.request.uri.path, "/api/v1/") and http.request.uri.path ne "/health"`.
* Custom rule, Block: `http.host eq "api.example.com" and not http.request.method in {"GET" "POST" "PATCH" "DELETE" "OPTIONS"}`.
* Rate limit (your one free rule): `http.request.uri.path eq "/api/v1/auth/login"` , ~10 requests / 10 s per IP, Block. With Pro add `/auth/register`, `/auth/forgot-password`, upload/download paths.
* **Do not use Managed Challenge / JS Challenge on the API hostname**: browser `fetch`/XHR calls cannot complete an interstitial challenge and the app would break. Use Block or Log there. Test Bot Fight Mode before enabling it on a zone that serves an API.
* Keep the application limiters: the WAF is an extra layer, not a replacement.

**Cloudflare Access stays disabled** (`CLOUDFLARE_ACCESS_ENABLED=false`). The existing middleware requires an Access JWT on every `/api/v1`
request; a browser app calling the API cross-site gets no such token, so enabling it would lock everyone out. It needs the API behind
an Access application on a shared parent domain plus a tested login flow. That configuration was not built or tested here.

## 5. Configuration reference

| Variable | Where | Value |
|---|---|---|
| `VITE_TURNSTILE_SITE_KEY` | Cloudflare Pages > Settings > Variables (build time) | public site key |
| `TURNSTILE_SECRET_KEY` | Render > Environment | secret key (required in production) |
| `CLIENT_URL` | Render | `https://secureshare-zt.pages.dev` |
| `ALLOWED_ORIGINS` | Render | **empty** (production only accepts exact https origins) |
| `NODE_ENV` | Render | `production` |
| `RATE_LIMIT_STORE` | Render | `mongo` (recommended) |
| `TRUST_PROXY_HOPS` | Render | `1` (see section 2) |
| `CLIENT_IP_HEADER` | Render | empty until verified, then `cf-connecting-ip` |
| `ORIGIN_VERIFY_SECRET` | Render | empty until the custom-domain setup (section 4) |
| `TURNSTILE_EXPECTED_HOSTNAMES` | Render | optional override |
| existing | Render | `MONGODB_URI`, `JWT_*`, `BREVO_API_KEY`, `EMAIL_FROM_*`, `STORAGE_PROVIDER`, `UPLOAD_DIR`, `MAX_UPLOAD_MB`, `CLOUDFLARE_ACCESS_ENABLED=false` |

Secrets live only in Render's and Pages' dashboards. `.env` is git-ignored and was never committed; `VITE_*` values are public.

## 6. Deployment order (matters)

1. Cloudflare dashboard > Turnstile > Add widget, mode **Managed**, hostname `secureshare-zt.pages.dev`. Copy site key and secret key.
2. Commit and push this change.
3. **Frontend first**: Pages > Variables: `VITE_TURNSTILE_SITE_KEY` (Production). Trigger a new deployment (Vite bakes the value in at build time). The old API ignores the extra field, so the site keeps working.
4. **Then the backend**: Render env: set `TURNSTILE_SECRET_KEY`, `RATE_LIMIT_STORE=mongo`; make sure `ALLOWED_ORIGINS` is empty and `CLIENT_URL` is exactly `https://secureshare-zt.pages.dev`. Deploy. If the env is wrong the service refuses to start and the log says which variable.
5. Read the boot line `Security configuration` in the Render log (no secrets): CORS origins, `turnstile: enforced`, `rateLimitStore: mongo`.
6. Run the client-IP verification (section 2); set `CLIENT_IP_HEADER` if needed.
7. Smoke test in a browser: sign in, register, forgot password, upload, download, share. Then: `curl -i -X OPTIONS https://secureshare-zt.onrender.com/api/v1/auth/login -H "Origin: https://evil.example" -H "Access-Control-Request-Method: POST"` must give 403; submit a wrong password nine times quickly: 429 with `Retry-After`.
8. Optional: promote the CSP in `frontend/public/_headers` from Report-Only after checking the browser console.

## 7. Remaining risks

* Client-IP resolution on Render is based on community measurements, not documentation (section 2). Until verified, per-IP limits may be too loose or too tight.
* The MongoDB rate-limit store uses plain `$inc`/`$set`/upsert operations and is unit-tested against an in-memory fake only (no MongoDB was available here).
* Ephemeral disk and in-memory upload buffering (section 3). No antivirus scanning.
* The refresh cookie is third-party (`SameSite=None`) until you move to a shared parent domain; Safari and some privacy browsers block it.
* Turnstile replay tracking is per process; Cloudflare remains the authority across instances. Preview deployments (`<hash>.secureshare-zt.pages.dev`) are intentionally not allowed by CORS or Turnstile hostname checks.
* Without a custom domain there is no WAF in front of the API, and `*.onrender.com` stays directly reachable even after you add one unless `ORIGIN_VERIFY_SECRET` is used.
* Access tokens remain valid for `ACCESS_TOKEN_TTL` (15 min) after logout; failed-login log lines contain the submitted email address.
* Rotate any secret that has ever been placed in a shared archive: the zip supplied for this work contained a populated `backend/.env`. Also, the seeded admin password in that file is shorter than the app's own password policy.
