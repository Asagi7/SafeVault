const app = require('./server');
const http = require('http');

const server = http.createServer(app);
server.listen(0, async () => {
  const base = `http://127.0.0.1:${server.address().port}`;
  let pass = 0, fail = 0;
  async function req(method, path, body, token) {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers.Authorization = 'Bearer ' + token;
    const res = await fetch(base + path, {
      method, headers, body: body ? JSON.stringify(body) : undefined
    });
    let json = null;
    try { json = await res.json(); } catch (e) { /* ignore */ }
    return { status: res.status, json };
  }
  function check(name, cond, extra) {
    if (cond) { pass++; console.log('PASS', name); }
    else { fail++; console.log('FAIL', name, JSON.stringify(extra)); }
  }

  // 1. Register user + admin
  let r = await req('POST', '/register', { username: 'alice', password: 'Password123' });
  check('register user 201', r.status === 201, r);
  r = await req('POST', '/register', { username: 'admin1', password: 'AdminPass123', role: 'admin' });
  check('register admin 201', r.status === 201 && r.json.role === 'admin', r);

  // 2. Input validation: bad username/password rejected
  r = await req('POST', '/register', { username: 'a', password: 'short' });
  check('validation rejects bad input 400', r.status === 400, r);

  // 3. SQL injection attempt in login is neutralized (parameterized query)
  r = await req('POST', '/login', { username: "' OR '1'='1", password: 'x' });
  check('SQLi login blocked 400/401', r.status === 400 || r.status === 401, r);

  // 4. Login OK
  r = await req('POST', '/login', { username: 'alice', password: 'Password123' });
  check('login user 200 + token', r.status === 200 && r.json.token, r);
  const userTok = r.json.token;
  r = await req('POST', '/login', { username: 'admin1', password: 'AdminPass123' });
  const adminTok = r.json.token;
  check('login admin 200 + token', r.status === 200 && !!adminTok, r);

  // 5. Auth required
  r = await req('GET', '/secrets');
  check('no token 401', r.status === 401, r);

  // 6. Create secret with XSS payload; verify output is escaped
  const xss = '<script>alert(1)</script>';
  r = await req('POST', '/secrets', { title: xss, body: 'hello' }, userTok);
  check('create secret 201', r.status === 201, r);
  r = await req('GET', '/secrets', null, userTok);
  const escaped = r.json && r.json[0] && r.json[0].title.includes('&lt;script&gt;');
  check('XSS output escaped', r.status === 200 && escaped, r);

  // 7. RBAC: user cannot access admin route, admin can
  r = await req('GET', '/admin/users', null, userTok);
  check('user forbidden admin route 403', r.status === 403, r);
  r = await req('GET', '/admin/users', null, adminTok);
  check('admin can list users 200', r.status === 200 && Array.isArray(r.json), r);

  console.log(`DONE pass=${pass} fail=${fail}`);
  server.close();
  process.exit(fail === 0 ? 0 : 1);
});
