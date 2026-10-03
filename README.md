# SafeVault - Secure Code Project (Copilot-assisted)

## Vulnerabilities identified and fixes applied

| # | Vulnerability | Where | Fix applied |
|---|---|---|---|
| 1 | SQL injection via string-concatenated queries | login, register, secrets | All DB access uses parameterized `?` placeholders (`dbGet/dbAll/dbRun`). Verified: login with `' OR '1'='1` returns 400/401, not bypass |
| 2 | Stored XSS via secret title/body | GET /secrets | `escapeHtml()` on all output (`&<>"'` encoded). Verified: `<script>` returns as `&lt;script&gt;` |
| 3 | Plaintext passwords | register/login | `bcryptjs` hash (cost 10) + `bcrypt.compare`; passwords never stored or returned |
| 4 | Missing auth / broken access control | /secrets, /admin/* | JWT (`jsonwebtoken`, 1h expiry) via `requireAuth`; `requireRole('admin')` for admin routes. Verified: no token 401, user on admin route 403 |
| 5 | Invalid/malicious input | all writes | `validateUsername` (3-30 alnum/_), `validatePassword` (min 8), `validateSecret` (length caps). Invalid returns 400 |
| 6 | Missing security headers | all responses | `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy` |

## How Copilot assisted (for rubric)

- Activity 1 (secure code): Copilot suggested parameterized sqlite queries, the username/password regex validators, and the `escapeHtml` output encoder. I reviewed each suggestion and replaced string-concatenated SQL with `?` bindings.
- Activity 2 (auth/RBAC): Copilot scaffolded bcrypt hashing, JWT sign/verify middleware, and the `requireRole('admin')` pattern. I wired roles into register/login and restricted `/admin/users` plus separated owner-vs-admin views on `/secrets`.
- Activity 3 (debug): Copilot helped reproduce SQLi (`' OR '1'='1`) and XSS (`<script>`) payloads and proposed fixes; I confirmed with `npm test` (11/11 PASS) before submitting.

## Run and test

```bash
npm install
npm start   # SafeVault on port 3000
npm test    # 11/11 PASS
```

## Endpoints

- POST /register {username, password, role?}
- POST /login {username, password} -> {token, role}
- GET /secrets (Bearer token; user sees own, admin sees all)
- POST /secrets {title, body} (Bearer token)
- GET /admin/users (Bearer admin token only)
