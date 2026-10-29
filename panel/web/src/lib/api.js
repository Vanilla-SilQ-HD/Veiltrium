// The panel's API (same origin). Every request carries the anti-CSRF header; the
// session is an HttpOnly cookie the page never sees.
export class AuthError extends Error {}

const headers = { 'Content-Type': 'application/json', 'X-Veiltrium': '1' };

async function call(method, path, body) {
  const r = await fetch('/api' + path, {
    method,
    headers,
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (r.status === 401 && path !== '/login') throw new AuthError('sign in');
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

export const api = {
  session: () => call('GET', '/session'),
  login: (password) => call('POST', '/login', { password }),
  logout: () => call('POST', '/logout'),
  status: () => call('GET', '/status'),
  standby: () => call('GET', '/standby'),
  verifyStandby: (receipt) => call('POST', '/standby/verify', { receipt }),
  russiaCheck: () => call('POST', '/russia-check'),
  clients: () => call('GET', '/clients'),
  client: (name) => call('GET', '/clients/' + encodeURIComponent(name)),
  addClient: (name, onStep) => stream('POST', '/clients', { name }, onStep),
  removeClient: (name, onStep) => stream('DELETE', '/clients/' + encodeURIComponent(name), undefined, onStep),
  resetClient: (name, onStep) => stream('POST', '/clients/' + encodeURIComponent(name) + '/reset', undefined, onStep),
  setClientLimits: (name, body, onStep) => stream('POST', '/clients/' + encodeURIComponent(name) + '/limits', body, onStep),
  disableClient: (name, onStep) => stream('POST', '/clients/' + encodeURIComponent(name) + '/disable', undefined, onStep),
  enableClient: (name, onStep) => stream('POST', '/clients/' + encodeURIComponent(name) + '/enable', undefined, onStep),
  audit: () => call('GET', '/audit'),
};

// A client change: NDJSON lines {"step"}, then {"result"} or {"error"}.
async function stream(method, path, body, onStep) {
  const r = await fetch('/api' + path, {
    method,
    headers,
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (r.status === 401 && path !== '/login') throw new AuthError('sign in');
  if (!r.ok || !r.body) {
    const data = await r.json().catch(() => ({}));
    throw new Error(data.error || r.statusText);
  }
  const reader = r.body.getReader();
  const dec = new TextDecoder();
  let buf = '';
  for (;;) {
    const { value, done } = await reader.read();
    if (value) buf += dec.decode(value, { stream: true });
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      const msg = JSON.parse(line);
      if (msg.step) onStep?.(msg.step);
      if (msg.error) throw new Error(msg.error);
      if (msg.result) return msg.result;
    }
    if (done) break;
  }
  throw new Error('the connection to the panel was cut off; check the clients list');
}
