# Veiltrium

**Secure Multi-Protocol VPN Deployment**

Automated, security-focused deployment of Hysteria2, VLESS Reality and TrustTunnel on Ubuntu VPS.

Veiltrium is a single, self-contained Bash installer (`hy2-secure-install.sh`) that turns a fresh Ubuntu server into a hardened node for three VPN protocols. It uses only the official release binaries of each protocol, pinned by version and SHA-256. No third-party panels, install scripts or `curl | sh` steps are involved.

The name: *Veil* (privacy), *Tri* (three protocols), *-ium* (an element, symbol **Vt**).

---

## Features

- One non-interactive run as root: system upgrade, automatic security updates, SSH hardening, firewall, fail2ban, kernel tuning, three VPN protocols, end-to-end verification and client links.
- Each protocol runs as its own system user in a systemd sandbox and cannot reach the server itself, private networks or SMTP.
- **Separate TLS identities.** Each protocol has its own server name and certificate, kept between runs. Changing one never touches the others.
- **Measured VLESS Reality site selection.** Candidate sites are checked directly and with a real Reality client on an isolated loopback instance. The choice comes from a reproducible score, with no random picks and no rotation on re-runs.
- **Transactional changes with automatic rollback.** Every change to a working node is checked with a real client before it is kept. If a run fails, is interrupted, is killed or the server loses power, the previous settings come back without any manual step.
- **Safe re-runs.** A plain re-run keeps passwords, keys, certificates, links and service configs byte for byte. It restarts no service, drops no client connection and does not reboot a working node.
- **Home-network diagnostics** from a Keenetic router (`keenetic-vpn-probe.sh`). Results are signed with HMAC-SHA256 and imported on the server.
- **Several clients.** `--add-client NAME` gives one more person or device its own credentials for every protocol; `--remove-client NAME` revokes them at once. Each change is checked with real clients and rolled back if it fails.
- Client apps show the node as `Veiltrium-<country>` (for example `Veiltrium-PL`).
- **A small web panel** on every node: overview and clients (links, QR codes, add, revoke). It listens on `127.0.0.1` only and is reached through an SSH tunnel.
- A JSON report without secrets (`/var/lib/hy2-secure/report.json`), plus `--diagnose` and `--dry-run` modes that change nothing.

## Protocols

| Protocol | Default port | TLS identity | Clients verify the server by |
|---|---|---|---|
| Hysteria 2 (`v2.13.0`) | 443/UDP (QUIC) | own self-signed certificate (EC P-256) | certificate pin: `pinSHA256` in links, `certificate_public_key_sha256` in sing-box |
| VLESS + Reality + Vision (Xray `v26.3.27`) | 443/TCP | a real third-party HTTPS site (Reality `target`/`serverNames`) | the Reality public key, UUID and shortId |
| TrustTunnel (endpoint `v1.1.0`) | 8443/TCP+UDP (HTTP/2 and HTTP/3) | own self-signed certificate, embedded in the `tt://` link | the embedded certificate as the only trust anchor |

Xray is intentionally pinned to `v26.3.27`. From `26.9.8` on, the Reality server rejects a ClientHello without an X25519MLKEM768 key share, which sing-box clients do not send by default.

## Supported systems

- Ubuntu **26.04** (primary target) and **24.04** (also covered by CI).
- amd64 and arm64.
- systemd, nftables and OpenSSH, as shipped with Ubuntu.

## Architecture and security

- **Firewall (nftables, own table `inet hy2fw`).** Only SSH and the proxy ports are reachable from outside. SSH is rate-limited. Scanner networks from public lists (refreshed weekly) see only SSH, never the proxy ports. Other tables (e.g. fail2ban) are left alone.
- **Egress isolation.** The proxy users may not connect to the server's own addresses, private ranges or port 25.
- **SSH.** Hardened (`MaxAuthTries`, `LoginGraceTime`, `MaxStartups`, verbose logging) **without** disabling password or root login. This is by design; brute force is handled by nftables limits, fail2ban and OpenSSH `PerSourcePenalties`.
- **Updates.** Unattended security upgrades with a nightly reboot window. `needrestart` is told never to restart the proxies, so a library update does not drop clients.
- **Secrets.** Root-only state files (`0600`). Connection details are printed to the terminal and saved to `/root/hy2-client.txt`, never into the install log. Reports and probe results contain no secrets.
- **Crash safety.** A change is a transaction: backup, pending marker, real client check, then commit. Rollback happens through the EXIT trap (errors, Ctrl+C, SIGTERM), a systemd watchdog timer (SIGKILL or a hung run), and `hy2-secure-recover.service` at boot (power loss).

### Self-signed certificates: what they do and do not give you

Without a domain, Hysteria 2 and TrustTunnel use self-signed certificates.

- **They are secure only when the client really checks them.** A Hysteria client must pin the certificate (`pinSHA256`, or `certificate_public_key_sha256` in sing-box). A TrustTunnel client must trust only the embedded certificate.
- **A client that sets `insecure=true` without a pin accepts any certificate.** An interceptor can then read the password.
- **A self-signed certificate never looks like the real site it is named after.** An active prober can tell. Only VLESS Reality shows a prober the genuine certificate of a real site. The Hysteria HTTP/3 masquerade page is served behind the self-signed certificate.
- Hysteria's built-in ACME cannot obtain IP-address certificates (no ACME profile support), and its challenges need port 80 or TCP 443, which Reality uses. So self-signed with pinning is the only supported mode.

## Installation on a fresh VPS

On the server, as root:

```bash
curl -fsSLO https://raw.githubusercontent.com/Vanilla-SilQ-HD/Veiltrium/main/hy2-secure-install.sh
bash hy2-secure-install.sh
```

Or copy it from your computer:

```bash
git clone https://github.com/Vanilla-SilQ-HD/Veiltrium.git
scp Veiltrium/hy2-secure-install.sh root@SERVER_IP:/root/
ssh root@SERVER_IP "bash /root/hy2-secure-install.sh"
```

Read the script before you run it: it changes the firewall, SSH settings and system updates of the server.

The run takes a few minutes. At the end it prints, and saves to `/root/hy2-client.txt` (root only):

- a `hysteria2://` link and a sing-box outbound with key pinning;
- a `vless://` link and a sing-box outbound;
- a `tt://` link;
- a sing-box JSON block for AWG Manager (see below).

Copy links without passing them through chat apps or Markdown renderers, which break `&` and `_`. For example, from PowerShell:

```powershell
ssh root@SERVER_IP "grep -m1 '^vless://' /root/hy2-client.txt" | Set-Clipboard
```

Optional settings are environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `REALITY_CANDIDATES` (old name `MASK_SITES`) | built-in list of 10 sites | Reality candidates; saved; `default` restores the built-in list |
| `REALITY_SNI` | – | use exactly this Reality site (checked first) |
| `HY2_SNI` | chosen separately | Hysteria SNI and certificate name; saved; `auto` picks a new independent name |
| `TT_SNI` | chosen separately | TrustTunnel hostname and certificate name; saved; `auto` as above |
| `HY2_MASQUERADE_URL` | `auto` (`https://<Hysteria SNI>`) | page served to HTTP/3 probers; saved |
| `REALITY_ENABLE`, `TT_ENABLE` | `1` | `0` turns VLESS Reality or TrustTunnel off |
| `HY2_PORT` | `443` | Hysteria UDP port; an existing node keeps its port |
| `REALITY_PORT`, `TT_PORT` | `443`, `8443` | Reality TCP port, TrustTunnel TCP+UDP port; an existing node keeps its ports unless they are given explicitly |
| `PUBLIC_IP` | detected | server address for the links (behind NAT) |
| `PANEL_ENABLE`, `PANEL_PORT` | `1`, `2096` | `0` turns the web panel off; the panel's port on `127.0.0.1` |
| `NODE_NAME` | the server's country | node name in client apps, `Veiltrium-<NODE_NAME>`; saved; `auto` detects the country again, `none` gives just `Veiltrium` |
| `SCANNER_BLOCK` | `1` | `0` turns the scanner blocklist off |
| `HY2_AUTO_REBOOT`, `AUTO_REBOOT_TIME` | `1`, `01:30` | a **new** node reboots right away if updates need it; nightly reboot time |
| `HY2_RECONFIGURE` | `0` | `1` issues new passwords, keys and certificates, for the added clients too (all clients must be updated) |

## Re-running the installer

Re-run the same command to update or repair a node:

```bash
ssh root@SERVER_IP "bash /root/hy2-secure-install.sh"
```

A plain re-run:

- keeps every password, key, UUID, shortId, certificate, server name and link;
- rewrites configs only with identical content, so no service restarts and active connections stay up;
- never reboots a working node (it reports a pending reboot; the nightly window applies);
- restores the settings of any interrupted earlier change first.

Maintenance modes. Each takes the same lock as the installer; the first three change nothing on the server.

```bash
bash /root/hy2-secure-install.sh --diagnose            # check the node, change nothing
bash /root/hy2-secure-install.sh --diagnose --json /root/diag.json
bash /root/hy2-secure-install.sh --dry-run             # what --reselect-reality would choose, change nothing
bash /root/hy2-secure-install.sh --help
```

## Clients

The first client, `main`, is created by the installer (`/root/hy2-client.txt`). More clients get their own credentials for all three protocols: a Hysteria user and password, a VLESS UUID and a TrustTunnel login. Revoking one never affects the others.

```bash
bash /root/hy2-secure-install.sh --add-client anna      # prints the details, saves /root/hy2-clients/anna.txt
bash /root/hy2-secure-install.sh --list-clients
bash /root/hy2-secure-install.sh --show-client anna
bash /root/hy2-secure-install.sh --remove-client anna
```

- Names: 1-32 characters, `a-z`, `0-9`, `_` and `-`.
- Adding or removing a client rewrites the three server configs as one change and restarts the services: connected clients reconnect within a few seconds. Real clients then check that the main client and the new one work, or that a removed one no longer does. Otherwise the previous settings come back.
- Hysteria uses a password per client (`user:password`). A node installed before this version has one shared password. Its first `--add-client` switches it, so the main client's Hysteria link and JSON change once; its VLESS and TrustTunnel links stay the same.
- A plain re-run keeps every client and their links. If a server name or certificate changes, their detail files are rewritten with the new links.

## Web panel

Every node gets a small web panel: an overview of the node and its protocols, and the clients with their links, QR codes and the AWG Manager JSON; clients can be added and revoked there.

```bash
ssh -N -L 2096:127.0.0.1:2096 root@SERVER_IP     # keep it open, then browse to http://localhost:2096/
```

- The password is printed at the end of the install and kept in `/root/hy2-panel.txt` (root only). `bash /root/hy2-secure-install.sh --panel-password` sets a new one and signs everybody out.
- **Nothing new is open on the internet.** The panel listens on `127.0.0.1` only; the SSH tunnel is the way in. The proxies cannot reach it (the firewall keeps them off the server's own addresses), and the panel itself has no internet access (systemd `IPAddressDeny`).
- **No privileges in the web process.** `veiltrium-panel` (Go, one static binary with the interface embedded) runs as its own user in a systemd sandbox. Every action goes over a unix socket, open only to that user's group, to a root helper that systemd starts per request: this installer in `--helper` mode, which accepts five requests (status, list, show, add, remove) with checked names and runs the same tested code as the command line.
- Web rules: a session cookie (`HttpOnly`, `SameSite=Strict`), a custom header and same-origin check on every change, only `localhost` host names (no DNS rebinding), a strict Content Security Policy with no external resources, and a lockout after failed logins.
- The binary comes from this repository's releases (`panel-v*`), SHA-256 pinned in the installer like the proxies. `PANEL_ENABLE=0` leaves it out.
- The command line has the same machine interface: `--status`, `--list-clients`, `--show-client NAME`, `--add-client NAME` and `--remove-client NAME` take `--json -`.

## Managing the REALITY SNI

The Reality site is chosen on a new node, and only changes when you ask for it:

```bash
bash /root/hy2-secure-install.sh --dry-run             # see the scores first
bash /root/hy2-secure-install.sh --reselect-reality    # re-evaluate and switch if clearly better
REALITY_SNI=www.example.com bash /root/hy2-secure-install.sh --reselect-reality
```

**How a site is evaluated.**
- Direct checks:
  - DNS gives only public IPv4 addresses;
  - on every address (up to 4): TLS 1.3 with X25519, ALPN h2 and a certificate valid for the name;
  - at least 2 of 3 HTTPS handshakes over h2 succeed.
- Then a throwaway Reality server with the node's own keys runs on loopback, so the live service is not touched, and is tested with a real client:
  - at least 2 of 3 requests through the tunnel succeed;
  - a prober without the key must receive the site's real certificate.

**Score** (lower is better): TLS median + spread + 250 × TLS failures + Reality median + 250 × Reality failures, −200 for a verified home-network success, +600 for a verified home-network failure. Ties keep the list order. The current site stays unless another one is better by more than max(50, 25 %).

**On a switch, only the `sni` / `server_name` of the VLESS link changes.** UUID, keys and shortId stay, and Hysteria and TrustTunnel are not touched. If the new site fails on the live port, the previous config comes back (exit code 2).

**Trial from home.** `--trial-reality` adds extra server names for a limited time through a runtime drop-in and a timer. A reboot also ends it. While it runs, a prober using a trial name sees the production site's certificate, so keep trials short.

```bash
bash /root/hy2-secure-install.sh --trial-reality www.example.com --trial-minutes 30
bash /root/hy2-secure-install.sh --trial-stop
```

## Diagnostics from a Keenetic router (Entware)

A result measured from a European VPS says nothing about reachability from a home provider. `keenetic-vpn-probe.sh` runs on the router (POSIX sh, BusyBox) and tests each server through the physical WAN. It uses temporary clients with a local SOCKS port only: no TUN, no routes, no firewall changes, and AWG Manager keeps running.

The examples use the Entware SSH server on the router (often port 222); adjust address and port.

1. Each install writes a probe profile `/root/hy2-probe.env` (contains passwords; keep it `0600`). Copy it to the router, one file per server:

   ```bash
   ssh root@SERVER_IP "cat /root/hy2-probe.env" | ssh -p 222 root@ROUTER "mkdir -p /opt/etc/vpn-probe && cat > /opt/etc/vpn-probe/server1.env && chmod 600 /opt/etc/vpn-probe/server1.env"
   scp -O -P 222 keenetic-vpn-probe.sh root@ROUTER:/opt/bin/
   ```

2. On the router, install the tools and run the probe. Pass your physical WAN interface; PPPoE is usually `ppp0`.

   ```sh
   opkg update && opkg install tcpdump jq curl
   ip -4 route get SERVER_IP; ip -4 rule show
   sh /opt/bin/keenetic-vpn-probe.sh --all --check-awg --wan ppp0 --output /opt/tmp/vpn-probe.json
   ```

   Options: `--reality`, `--hysteria`, `--trusttunnel`, `--trial-sni a,b`, `--runs N`, `--payload-bytes N`, `--profile FILE`, `--singbox PATH`, `--tt-client PATH`, `--help`.

3. Import the result on each server:

   ```bash
   ssh -p 222 root@ROUTER "cat /opt/tmp/vpn-probe.json" | ssh root@SERVER_IP "bash /root/hy2-secure-install.sh --import-mts -"
   ```

**What counts as proof.**
- A result counts only with `route: verified`: packets from the test client's own sockets were seen leaving through the physical WAN (tcpdump, with conntrack for NAT).
- Anything else is `route_unverified` and does not count. That includes a VPN interface given as the WAN, a local redirect, or missing evidence.
- A single success does not prove that DPI is bypassed.

**Signatures.**
- Results are signed with HMAC-SHA256 using the server's probe key.
- Each server's lines are bound by a signed header (count and hash) and a run id. Changed, dropped, foreign, old or replayed results are rejected.
- A signature proves which profile produced a result, not where the probe ran. That is what the route evidence is for.

## AWG Manager and sing-box compatibility

- **Hysteria 2.** AWG Manager deliberately drops `pinSHA256` from `hysteria2://` links and imports them with `insecure=true`, i.e. **without any certificate check**. Instead, use section 6 of `/root/hy2-client.txt`: a sing-box JSON block with `certificate_public_key_sha256`, imported as a server group (sing-box JSON). The router's sing-box build (`1.15.0-alpha.12-awgm.33`) enforces the pin, including over QUIC; CI checks this with the same build. `keenetic-vpn-probe.sh --check-awg` shows whether the router's config actually pins the key.
- **VLESS Reality.** The `vless://` link imports as is (`fp=chrome`, `flow=xtls-rprx-vision`).
- **TrustTunnel.** The `tt://` link carries the certificate. AWG Manager verifies it, but uses HTTP/2 only.
- **sing-box clients in general.** Use the JSON outbounds from the client file. `certificate_public_key_sha256` is the base64 SHA-256 of the public key (SPKI), which is not the same value as Hysteria's hex `pinSHA256`.

## Testing and CI

Two levels:

- **FAST** (`tests/fast.sh`, workflow `fast.yml`, on every push, seconds): `bash -n`, shellcheck, `dash` and BusyBox syntax for the probe, unit tests of scoring, choice, home-network records, client configs and links, and HMAC (RFC 4231 vectors and agreement with OpenSSL for both the server and the BusyBox implementation).
- **FULL** (workflow `e2e.yml`, about 30 minutes; manual only, on any branch including `main`, before merge or release). It runs on Ubuntu 26.04 and 24.04:
  - a fresh install, with the firewall checked from a separate network namespace;
  - real clients of all three protocols;
  - the exact router sing-box build;
  - fail2ban bans;
  - reboot simulation;
  - re-runs with live connections through all three protocols;
  - added clients: real clients on every protocol, a re-run with clients, rollback of a failed change, revocation;
  - the web panel: loopback only, out of reach of the proxies, the helper's request rules, login and CSRF rules, a client change through the API, a new password, a re-run that changes nothing;
  - rollback: SIGINT, SIGTERM, SIGKILL with the watchdog, a simulated power loss, systemd start failures;
  - local test sites for Reality selection (invalid certificate, no HTTP/2, a dead CDN address, timeouts, NXDOMAIN);
  - the Keenetic probe under BusyBox with policy routing, redirects, NAT and a VPN given as the WAN;
  - a separate upgrade job from the release in use: it must change nothing, and its first added client switches Hysteria to per-client passwords.

CI has no Russian home network: everything about reachability from a home provider is a simulation there, and needs the probe on a real router.

## Known limitations

- **No domain.** Hysteria 2 and TrustTunnel are self-signed; an active prober can see that (see above).
- **Pinning depends on the client.** It protects only clients that pin. AWG Manager's link import does not; use the JSON import.
- **The Reality score is measured from the server.** Reachability from a home network needs the Keenetic probe, and a verified route needs `tcpdump` on the router.
- **TrustTunnel HTTP/3 is not available in AWG Manager.** The router imports TrustTunnel as HTTP/2 only.
- **The installer is written for Ubuntu.** Other distributions are not supported.

## License

MIT, see [LICENSE](LICENSE).
