# ShopCart: Initial Vulnerabilities (documented before fixes)

| # | Flaw | Location | Cause | Impact | OWASP 2021 |
|---|------|----------|-------|--------|-----------|
| 1 | SQL injection in product search | app/server.js, GET /api/products | `q` concatenated into SQL string | Read or modify any table, dump users and password hashes | A03 Injection |
| 2 | Price tampering at checkout | app/server.js, POST /api/orders | Total computed from client-supplied `price` | Buy items for any price, including 0 | A04 Insecure Design |
| 3 | IDOR on orders | app/server.js, GET /api/orders/:id | No check that order belongs to requester | Read other customers' orders and addresses | A01 Broken Access Control |
| 4 | Hardcoded secrets | app/server.js (JWT_SECRET, admin123), docker-compose.yml (DB password) | Secrets committed to repo | Forge admin tokens, access database | A07 Auth Failures / A05 Misconfiguration |

Exploit before fixing. Example SQL injection:
  GET /api/products?q=' OR '1'='1
