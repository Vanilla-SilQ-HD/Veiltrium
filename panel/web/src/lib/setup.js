// Device-specific choices use explicit formats; a sing-box core does not imply
// that an arbitrary app accepts a complete sing-box configuration.
export function setupChoices(device, client) {
  if (client.state === 'disabled') return [];
  const options = [];
  if (device === 'router') {
    if (client.vless) options.push('vless');
    options.push('awg');
    if (client.trusttunnel) options.push('tt');
  } else {
    if (client.vless) options.push('vless');
    if (client.singbox_profile) options.push('singbox');
    if (!client.vless && client.hysteria2) options.push('hy2');
  }
  return options;
}

export function setupPayload(kind, client) {
  if (kind === 'singbox') return JSON.stringify(client.singbox_profile, null, 2);
  if (kind === 'awg') return JSON.stringify(client.hysteria2.awg_group, null, 2);
  return ({ vless: client.vless?.link, hy2: client.hysteria2?.link, tt: client.trusttunnel?.link })[kind] ?? '';
}
