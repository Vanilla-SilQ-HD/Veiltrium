// Evidence is deliberately separated: a listening service or a TCP ping is not a VPN test.
export function fresh(iso, now, maxAge) {
  const ts = Date.parse(iso);
  return Number.isFinite(ts) && ts <= now + 300000 && now - ts <= maxAge;
}

export function health(st, now = Date.now()) {
  const protocols = [
    ['hysteria-server', st.hysteria2, 'home_network', 'home_checked_at'],
    ['xray', st.reality, 'home_network', 'home_checked_at'],
    ['trusttunnel', st.trusttunnel, 'home_network_h2', 'home_checked_at_h2'],
    ['trusttunnel', st.trusttunnel, 'home_network_h3', 'home_checked_at_h3'],
  ].filter(([, p]) => p);
  const services = [...new Set(protocols.map(([name]) => name))];
  const active = services.filter((name) => st.services?.[name] === 'active').length;
  const homeAge = (st.home_max_age_days ?? 14) * 86400000;
  const tested = protocols.filter(([, p, key, date]) => fresh(p[date], now, homeAge) && p[key] !== 'route_unverified');
  const good = tested.filter(([, p, key]) => p[key] === 'ok');
  const failed = tested.filter(([, p, key]) => ['fail', 'degraded', 'stalled'].includes(p[key]));
  const ruFresh = fresh(st.russia?.checked_at, now, 12 * 3600000);
  let title = 'unconfirmed', tone = 'warn', action = 'home';
  if (active !== services.length || services.length === 0) {
    title = 'servicesDown'; tone = 'danger'; action = 'diagnose';
  } else if (!st.protection?.firewall) {
    title = 'firewall'; tone = 'danger'; action = 'diagnose';
  } else if (good.length && failed.length) {
    title = 'partial'; action = 'working';
  } else if (good.length) {
    title = 'confirmed'; tone = 'ok'; action = 'connect';
  } else if (failed.length) {
    title = 'homeFailed'; tone = 'danger'; action = 'home';
  } else if (ruFresh && ['blocked', 'partly'].includes(st.russia?.verdict)) {
    title = 'address'; action = 'russia';
  }
  return { title, tone, action, active, total: services.length,
    home: good.length ? 'confirmed' : failed.length ? 'failed' : 'unconfirmed',
    russia: ruFresh ? st.russia.verdict : 'stale' };
}
