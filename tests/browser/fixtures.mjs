// Synthetic accounts only. Unexpected API calls fail the test instead of reaching a VPS.
export function client(name = 'main', disabled = false) {
  return {
    schema: 'veiltrium-client/1', name, main: name === 'main', node_name: 'Veiltrium-Test', server: '203.0.113.10',
    state: disabled ? 'disabled' : 'active', reset: 'none', limit: null, expires: null, reason: disabled ? 'manual' : '',
    traffic: null, standby: [],
    hysteria2: { auth: `${name}:synthetic-password`, link: `hysteria2://${name}:synthetic-password@203.0.113.10:443/`,
      outbound: { type: 'hysteria2' }, awg_group: [{ type: 'hysteria2', password: 'synthetic-password' }] },
    vless: { link: `vless://${name}-synthetic-uuid@203.0.113.10:443?pbk=synthetic-key&sid=1234#Test`, outbound: { type: 'vless' } },
    trusttunnel: { link: 'tt://?synthetic-profile' },
    singbox_profile: { outbounds: [{ type: 'vless', uuid: `${name}-synthetic-uuid` }] },
    subscription_base64: 'c3ludGhldGljLXN1YnNjcmlwdGlvbg==',
  };
}
export async function mockAPI(page, { disabled = false } = {}) {
  const errors = [];
  page.on('pageerror', err => errors.push(err.message));
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname;
    const accounts = [client(), client('alice', disabled)];
    const data = path === '/api/session' ? { ok: true }
      : path === '/api/clients' ? { schema: 'veiltrium-clients/1', node_name: 'Veiltrium-Test', server: '203.0.113.10', clients: accounts, standby: [] }
      : accounts.find(c => path === `/api/clients/${c.name}`);
    if (!data) { errors.push(`Unexpected API: ${path}`); return route.abort(); }
    return route.fulfill({ json: data });
  });
  return errors;
}
