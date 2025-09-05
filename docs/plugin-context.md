# Simple Auth0 – Context & Development Plan

## 1) General Description

Simple Auth0 is a WordPress plugin that integrates an Auth0 tenant and can (optionally) replace the native WordPress login flow. By default it is non-invasive: after install/activate, WordPress continues using its own login until an admin explicitly enables Auth0 login in the plugin's Settings screen.

The plugin provides an admin dashboard under **Settings → Simple Auth0** with three tabs:

- **Settings** — enter and validate Auth0 credentials and options.
- **Sync** — export existing WP users to an Auth0-compatible Bulk User Import JSON (preview + downloadable file) and show instructions.
- **Help** — short, actionable docs (what to configure in Auth0, callback URLs, common pitfalls).

When enabled, the plugin redirects the WordPress login to Auth0's `/authorize` endpoint and handles the OAuth callback, creating or linking WordPress users. It can also auto-sync WordPress user changes to Auth0 (create/update) via hooks.

## 2) Needed Packages / Tools

### WordPress & PHP

- WordPress 6.4+
- PHP 8.1+
- Composer (for SDKs)

### PHP Libraries

- **Auth0 PHP SDK** (`auth0/auth0-php`) – handles OAuth code exchange, JWKS verification, logout building.
- **guzzlehttp/guzzle** (if not using WP HTTP API through the SDK).
- **ramsey/uuid** (for stable user_id prefixes in exports).
- **Optional encryption-at-rest** for secrets: ext-sodium or OpenSSL (use WP salts as part of the key).

### WordPress Features/APIs

- Settings API (register, sanitize, validate settings).
- Admin Menu API (add options page).
- REST API (register routes for `/callback`, optional `/logout`).
- Authentication hooks (`login_form_…`, `authenticate`, `wp_login_url`, `login_init`).
- User hooks (`user_register`, `profile_update`, `deleted_user`, `password_reset`) for sync.

### Dev & QA

- WP-CLI for local testing.
- PHPUnit + Brain Monkey (unit), or Codeception.
- Postman/Insomnia for callback testing.
- Browser devtools for cookie/header inspection.

### Code Practices and Considerations

- Please follow WordPress standards
- Use Classes and Namespaces
- Use DRY principles (Do Not Repeat Yourself)

## 3) Architecture (High Level)

- **Admin UI** (Settings → Simple Auth0): React-free classic WP admin pages with tabs.
- **Options storage**: single options array `simple_auth0_options` in `wp_options` (autoload = no). Sensitive fields (client secret) stored encrypted or masked on display.
- **Login enable/disable**: boolean flag `enable_auth0_login` (off by default). When ON, plugin hooks into login URL and authenticate to start Auth0 flow.
- **OAuth flow**: Authorization Code + PKCE. Callback implemented as WP REST route:

  ```
  POST/GET /wp-json/simple-auth0/v1/callback
  ```
- **User linking**: look up by email; if no WP user, create one and store `auth0_sub` in user meta.

### Sync

- **Auto**: on `user_register` / `profile_update`, call Auth0 Management API to upsert user (if configured).
- **Bulk export**: generate JSON following Auth0 bulk import schema; show preview and allow download.
- **Status indicator**: "Connected to Auth0" badge—runs a lightweight check (e.g., fetch OIDC metadata or exchange Client Credentials if configured) and displays result.

## 4) Configuration Keys (stored under `simple_auth0_options`)

- `domain` (e.g., your-tenant.us.auth0.com)
- `client_id`
- `client_secret` (write-only; masked in UI; only updated when field has a new non-empty value)
- `audience` (optional, for API access)
- `redirect_uri` (auto-calculated, but editable): `https://<site>/wp-json/simple-auth0/v1/callback`
- `logout_redirect_uri` (optional)
- `scopes` (default: openid profile email)
- `enable_auth0_login` (bool; default false)
- `auto_sync_users` (bool; default true)
- `export_hash_algorithm` (auto-detected; overrideable: bcrypt, argon2id, phpass (legacy – warn))
- `status_last_checked` / `status_ok` (for dashboard badge)

## 5) Auth0 Tenant Setup (to display in Help tab)

- **Allowed Callback URLs**: `https://<site>/wp-json/simple-auth0/v1/callback`
- **Allowed Logout URLs**: `https://<site>/wp-login.php`, `https://<site>/`
- **Allowed Web Origins**: `https://<site>`
- **Application Type**: Regular Web App
- **Token Endpoint Auth Method**: client_secret_post (or client_secret_basic)
- **Connections**: enable Database connection you'll import into (or use for migration)

## 6) User Stories & Acceptance Criteria

### Story 1 — Install without takeover

**As an admin, I can activate the plugin and keep the native WP login until I enable Auth0.**

**Acceptance criteria:**
- After activation, `wp-login.php` works as usual.
- `enable_auth0_login` defaults to off.
- No redirects to Auth0 occur until explicitly enabled.

### Story 2 — Settings menu entry

**As an admin, I see Settings → Simple Auth0 in the WP sidebar.**

**Acceptance criteria:**
- A single menu item appears under Settings.
- Clicking it opens the Simple Auth0 dashboard with tabs.

### Story 3 — Dashboard tabs & toggle

**As an admin, I see tabs Settings, Sync, Help and a connection status badge. If credentials are valid, I can toggle Auth0 Login on/off.**

**Acceptance criteria:**
- Tabs render and switch without page errors.
- Status badge shows Connected when a lightweight test passes; Not connected with helpful error otherwise.
- An Enable Auth0 Login toggle becomes clickable only when required settings pass validation; flipping it persists the setting.

### Story 4 — Settings form (secure & validated)

**As an admin, I can configure Auth0 safely.**

**Acceptance criteria:**

**Fields:** domain, client ID, client secret (masked), redirect URI (pre-filled), scopes, audience (optional).

**Validation:**
- Domain is a valid Auth0 domain.
- Redirect URI is a valid URL on the current site.
- Client ID non-empty.
- Client secret: only updated if field has a non-empty value. If left blank on save, the existing secret remains unchanged.

**Security:**
- Nonces and capability checks (`manage_options`).
- Client secret stored encrypted if possible; always masked in UI and never printed in HTML source.
- On save, a connection check runs and updates the status badge.
- Error messages are clear and non-technical.

### Story 5 — Replace WP login when enabled

**As a user, when Auth0 Login is enabled, hitting wp-login.php starts the Auth0 flow; when disabled, WP native login works.**

**Acceptance criteria:**
- With toggle on: visiting `wp-login.php` (or clicking Log In) redirects to Auth0 `/authorize` with correct parameters (client_id, scope, state, nonce, PKCE).
- With toggle off: default WP login functions normally.
- "Log out" ends WP session; if configured, also calls Auth0 logout and returns to a safe URL.

### Story 6 — OAuth callback

**As a user, after Auth0 I return to WP and get logged in or created.**

**Acceptance criteria:**
- REST route `/wp-json/simple-auth0/v1/callback` accepts GET/POST.
- Verifies state and nonce; exchanges code for tokens.
- Finds existing WP user by sub or email; otherwise creates a new user with mapped role (default subscriber).
- Stores `auth0_sub` in user meta.
- Ends by redirecting to the originally requested WP page (or dashboard).

### Story 7 — Sync tab: preview & export JSON

**As an admin, I can preview and download a JSON file to import users to Auth0.**

**Acceptance criteria:**
- "Preview" shows the first N users (e.g., 20) in Auth0 Bulk Import format.
- "Download" streams the full JSON with correct schema:
  - `email`, `email_verified` (best-effort), `user_id` (e.g., `wp|{ID}`), and if supported:
  - `custom_password_hash: { algorithm: "<algo>", hash: { value: "<stored-hash>", salt?: "<salt>" } }`
- If WP uses an unsupported/unknown hash (e.g., legacy phpass), the tool:
  - Marks users with `"password_import_unavailable": true` and
  - Shows guidance to use Automatic Migration instead.
- No secrets (tokens) are exposed in the file.

### Story 8 — Sync tab: instructions

**As an admin, I see concise instructions to import the JSON into Auth0.**

**Acceptance criteria:**
- Step-by-step: where to go in the Auth0 Dashboard, size limits, connection to import into, and caveats about algorithms.
- Links to Auth0 docs.
- Warning that passwords import only when the algorithm is supported.

### Story 9 — Auto-sync new/updated users

**As an admin, new or updated WP users are reflected in Auth0 automatically.**

**Acceptance criteria:**
- On `user_register`: creates the user in Auth0 (email + metadata). If password sync isn't possible, relies on migration or password reset flow.
- On `profile_update` / role change / email change: updates Auth0 user.
- Network failures surface as admin notices and are logged; retries or a "Retry failed sync" action is available.

### Story 10 — Help tab

**As an admin, I can quickly set up Auth0 using the Help tab.**

**Acceptance criteria:**
- Shows required Auth0 settings (Allowed Callback/Logout URLs, Web Origins).
- Describes enabling/disabling login, troubleshooting (cookies, headers, clocks).
- Link to support or GitHub issues.

### Story 11 — Connection status on dashboard

**As an admin, I immediately see whether Auth0 is configured correctly.**

**Acceptance criteria:**
- Badge shows Connected when:
  - OIDC discovery document is reachable and
  - a small test (e.g., Client Credentials or JWKS fetch) succeeds.
- Shows Not connected with the last error message and a "Re-check" button.

### Story 12 — Security & privacy

**As a site owner, my secrets and user data are safe.**

**Acceptance criteria:**
- Nonces on all form actions; capability checks (`manage_options`).
- Secrets masked in UI; never returned via AJAX or REST.
- Options autoload disabled; secrets stored encrypted if possible.
- Uses PKCE for the login flow; validates state & nonce.
- Logout prevents open-redirects; only whitelisted return URLs are used.

### Story 13 — Uninstall behavior

**As an admin, I control what's left behind.**

**Acceptance criteria:**
- On uninstall, plugin can remove its options (toggleable), but never deletes WP users.
- A warning explains what is removed.

## 7) Non-Functional Requirements

- **Performance**: admin pages load <200ms server time; network calls async where possible.
- **i18n**: strings wrapped in `__()`/`_e()` with a text domain.
- **Accessibility**: forms labelled, tabs keyboard-navigable.
- **Error logging**: use `error_log`/`WC_Log` or PSR-3 to a dedicated log file with redaction.
- **Multisite**: out of scope for v1 (note this).

## 8) Open Questions / Decisions

- Should we force PKCE only, or allow non-PKCE? (Recommend PKCE only.)
- User role mapping strategy (static default vs. claim-based).
- Encryption-at-rest approach for client secret (sodium vs. OpenSSL + WP salts).
- Handling legacy WordPress password hashes (offer automatic migration guidance when bulk-import is not feasible).

## 9) Milestones

1. Settings UI + validation + status check
2. Login enable/disable hooks + PKCE flow + callback route
3. User linking/creation + logout
4. Sync tab: preview + full JSON export + docs
5. Auto-sync hooks (create/update)
6. Help content + polish + i18n + hardening