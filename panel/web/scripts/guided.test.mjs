import test from 'node:test';
import assert from 'node:assert/strict';
import { health, fresh } from '../src/lib/health.js';
import { setupChoices, setupPayload } from '../src/lib/setup.js';

const now = Date.parse('2026-10-30T12:00:00Z');
const iso = (age = 0) => new Date(now - age).toISOString();
const base = () => ({ services: { 'hysteria-server': 'active', xray: 'inactive' },
  protection: { firewall: true }, hysteria2: { home_network: 'untested' }, reality: null, trusttunnel: null });
test('active services and a successful TCP ping never confirm a tunnel', () => {
  const st = { ...base(), russia: { verdict: 'reachable', checked_at: iso() } };
  assert.equal(health(st, now).title, 'unconfirmed');
  assert.equal(health(st, now).total, 1); // disabled protocols do not look broken
});
test('home evidence must be fresh, timestamped and route-verified', () => {
  for (const [state, at] of [['ok', null], ['ok', iso(15 * 86400000)], ['route_unverified', iso()], ['ok', iso(-600000)]]) {
    assert.equal(health({ ...base(), hysteria2: { home_network: state, home_checked_at: at } }, now).home, 'unconfirmed');
  }
  const st = { ...base(), hysteria2: { home_network: 'ok', home_checked_at: iso() } };
  assert.equal(health(st, now).title, 'confirmed');
  st.services['hysteria-server'] = 'failed';
  assert.equal(health(st, now).title, 'servicesDown');
});
test('a working protocol and a stalled one give a partial result', () => {
  const st = base();
  st.hysteria2 = { home_network: 'stalled', home_checked_at: iso() };
  st.reality = { home_network: 'ok', home_checked_at: iso() };
  st.services.xray = 'active';
  assert.equal(health(st, now).title, 'partial');
  st.reality = null;
  assert.equal(health(st, now).title, 'homeFailed');
});
test('address evidence expires independently; a stale failure is not current', () => {
  const st = { ...base(), russia: { verdict: 'blocked', checked_at: iso(13 * 3600000) } };
  assert.equal(health(st, now).title, 'unconfirmed');
  st.russia.checked_at = iso();
  assert.equal(health(st, now).title, 'address');
  assert.equal(fresh(null, now, 1), false);
});
test('wizard offers only available formats and treats disabled clients as unavailable', () => {
  const c = { state: 'active', vless: { link: 'vless://test' }, hysteria2: { link: 'hysteria2://test', awg_group: [{ password: 'pin-preserving' }] },
    singbox_profile: { outbounds: [{ tag: 'auto' }] }, trusttunnel: { link: 'tt://test' } };
  assert.deepEqual(setupChoices('android', c), ['vless', 'singbox']);
  assert.deepEqual(setupChoices('router', c), ['vless', 'awg', 'tt']);
  assert.equal(setupPayload('vless', c), 'vless://test');
  assert.deepEqual(JSON.parse(setupPayload('awg', c)), c.hysteria2.awg_group);
  assert.deepEqual(JSON.parse(setupPayload('singbox', c)), c.singbox_profile);
  assert.deepEqual(setupChoices('ios', { ...c, state: 'disabled' }), []);
  assert.deepEqual(setupChoices('windows', { ...c, vless: null }), ['singbox', 'hy2']);
});
