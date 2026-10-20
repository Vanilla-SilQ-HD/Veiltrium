# Veiltrium

**Secure Multi-Protocol VPN Deployment**

Automated, security-focused deployment of Hysteria2, VLESS Reality and TrustTunnel on Ubuntu VPS.

Veiltrium is a single, self-contained Bash installer (`veiltrium.sh`) that turns a fresh Ubuntu server into a hardened node for three VPN protocols. It uses only the official release binaries of each protocol, pinned by version and SHA-256. No third-party panels, install scripts or `curl | sh` steps are involved.

The name: *Veil* (privacy), *Tri* (three protocols), *-ium* (an element, symbol **Vt**).

---

## Features

- One non-interactive run as root: system upgrade, automatic security updates, SSH hardening, firewall, fail2ban, kernel tuning, three VPN protocols, end-to-end verification and client links.
- Each protocol runs as its own system user in a systemd sandbox and cannot reach the server itself, private networks or SMTP.
- **Separate TLS identities.** Each protocol has its own server name and certificate, kept between runs. Changing one never touches the others.
- **Measured VLESS Reality site selection.** Candidate sites are checked directly and with a real Reality client on an isolated loopback instance. The choice comes from a reproducible score, with no random picks and no rotation on re-runs.
- **Transactional changes with automatic rollback.** Every change to a working node is checked with a real client before it is kept. If a run fails, is interrupted, is killed or the server loses power, the previous settings come back without any manual step.
- **Safe re-runs.** A plain re-run keeps passwords, keys, certificates, links and service configs byte for byte. It restarts no service, drops no client connection and does not reboot a working node.
- **What Russia sees, checked from the server.** A site on the RKN block list is never chosen as a server name, and Globalping probes in Russian networks (MTS, Rostelecom and others) check that the server's address answers, so a blocked IP shows at install time, not as a dead tunnel later.
- **Several clients.** `--add-client NAME` gives one more person or device its own credentials for every protocol; `--remove-client NAME` revokes them at once. Each change is checked with real clients and rolled back if it fails.
- Client apps show the node as `Veiltrium-<country>` (for example `Veiltrium-PL`).
- **A small web panel** on every node: overview and clients (links, QR codes, add, revoke). It listens on `127.0.0.1` only and is reached through an SSH tunnel.
- A JSON report without secrets (`/var/lib/veiltrium/report.json`), plus `--diagnose` and `--dry-run` modes that change nothing.

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

- **Firewall (nftables, own table `inet veiltrium`).** Only SSH and the proxy ports are reachable from outside. SSH is rate-limited. Scanner networks from public lists (refreshed weekly) see only SSH, never the proxy ports. Other tables (e.g. fail2ban) are left alone.
- **Egress isolation.** The proxy users may not connect to the server's own addresses, private ranges or port 25.
- **SSH.** Hardened (`MaxAuthTries`, `LoginGraceTime`, `MaxStartups`, verbose logging) **without** disabling password or root login. This is by design; brute force is handled by nftables limits, fail2ban and OpenSSH `PerSourcePenalties`.
- **Updates.** Unattended security upgrades with a nightly reboot window. `needrestart` is told never to restart the proxies, so a library update does not drop clients.
- **Secrets.** Root-only state files (`0600`). Connection details are printed to the terminal and saved to `/root/veiltrium/client.txt`, never into the install log. Reports and probe results contain no secrets.
- **Crash safety.** A change is a transaction: backup, pending marker, real client check, then commit. Rollback happens through the EXIT trap (errors, Ctrl+C, SIGTERM), a systemd watchdog timer (SIGKILL or a hung run), and `veiltrium-recover.service` at boot (power loss).

### Self-signed certificates: what they do and do not give you

Without a domain, Hysteria 2 and TrustTunnel use self-signed certificates.

- **They are secure only when the client really checks them.** A Hysteria client must pin the certificate (`pinSHA256`, or `certificate_public_key_sha256` in sing-box). A TrustTunnel client must trust only the embedded certificate.
- **A client that sets `insecure=true` without a pin accepts any certificate.** An interceptor can then read the password.
- **A self-signed certificate never looks like the real site it is named after.** An active prober can tell. Only VLESS Reality shows a prober the genuine certificate of a real site. The Hysteria HTTP/3 masquerade page is served behind the self-signed certificate.
- Hysteria's built-in ACME cannot obtain IP-address certificates (no ACME profile support), and its challenges need port 80 or TCP 443, which Reality uses. So self-signed with pinning is the only supported mode.

## Installation on a fresh VPS

On the server, as root:

```bash
curl -fsSLO https://raw.githubusercontent.com/Vanilla-SilQ-HD/Veiltrium/main/veiltrium.sh
bash veiltrium.sh
```

Or copy it from your computer:

```bash
git clone https://github.com/Vanilla-SilQ-HD/Veiltrium.git
scp Veiltrium/veiltrium.sh root@SERVER_IP:/root/
ssh root@SERVER_IP "bash /root/veiltrium.sh"
```

Read the script before you run it: it changes the firewall, SSH settings and system updates of the server.

The run takes a few minutes. At the end it prints, and saves to `/root/veiltrium/client.txt` (root only):

- a `hysteria2://` link and a sing-box outbound with key pinning;
- a `vless://` link and a sing-box outbound;
- a `tt://` link;
- a sing-box JSON block for AWG Manager (see below).

Copy links without passing them through chat apps or Markdown renderers, which break `&` and `_`. For example, from PowerShell:

```powershell
ssh root@SERVER_IP "grep -m1 '^vless://' /root/veiltrium/client.txt" | Set-Clipboard
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
| `PANEL_ENABLE`, `PANEL_PORT` | `1`, `2096` | `0` turns the web panel off; the panel's port on `127.0.0.1` (saved) |
| `GLOBALPING` | `1` | `0` turns off the check from Russian networks (it sends the server's address to Globalping); saved |
| `RU_BLOCKLISTS` | itdoginfo `Categories/block.lst` | URLs of RKN block lists (domains, one per line) |
| `NODE_NAME` | the server's country | node name in client apps, `Veiltrium-<NODE_NAME>`; saved; `auto` detects the country again, `none` gives just `Veiltrium` |
| `STANDBY_HOSTS` | none | up to 3 public IPv4 addresses of standby servers, comma-separated; saved; `none` clears. Every client link and config (hysteria2, vless, tt, sing-box outbounds with a `urltest` group, the AWG Manager server group) then also lists them, so phones and the router switch by themselves if this address is blocked. The standby servers must be copies of this node using the same ports: deploy the second VPS from an export of this node, then set `STANDBY_HOSTS` here and re-run; export again after adding or removing clients |
| `SCANNER_BLOCK` | `1` | `0` turns the scanner blocklist off |
| `VT_AUTO_REBOOT`, `AUTO_REBOOT_TIME` | `1`, `01:30` | a **new** node reboots right away if updates need it; nightly reboot time |
| `VT_RECONFIGURE` | `0` | `1` issues new passwords, keys and certificates, for the added clients too (all clients must be updated) |

## Re-running the installer

Re-run the same command to update or repair a node:

```bash
ssh root@SERVER_IP "bash /root/veiltrium.sh"
```

A plain re-run:

- keeps every password, key, UUID, shortId, certificate, server name and link;
- rewrites configs only with identical content, so no service restarts and active connections stay up;
- never reboots a working node (it reports a pending reboot; the nightly window applies);
- restores the settings of any interrupted earlier change first.

**Nodes installed by `hy2-secure-install.sh`** (the project's earlier name, up to `v2026.10.13.1`) move to the Veiltrium names on their first run of `veiltrium.sh`:

- `/etc/hy2-secure` → `/etc/veiltrium`, `/var/lib/hy2-secure` → `/var/lib/veiltrium`;
- root's files → `/root/veiltrium/` (`client.txt`, `clients/`, `probe.env`, `panel.txt`);
- the firewall table `inet hy2fw` → `inet veiltrium`, the helper units and drop-ins (`veiltrium-scanner-block`, `veiltrium-recover`, sysctl, SSH, fail2ban, needrestart, apt) to their `veiltrium` names;
- keys, passwords, certificates, clients and links stay as they are; the three proxy services restart once (the comments in their configs change), so connected clients reconnect within seconds;
- the old files are removed at the end of the run. `HY2_RECONFIGURE` and `HY2_AUTO_REBOOT` still work as old names of `VT_RECONFIGURE` and `VT_AUTO_REBOOT`; results of an older `keenetic-vpn-probe.sh` are still accepted.

Maintenance modes. Each takes the same lock as the installer; the first three change nothing on the server.

```bash
bash /root/veiltrium.sh --diagnose            # check the node, change nothing
bash /root/veiltrium.sh --diagnose --json /root/diag.json
bash /root/veiltrium.sh --dry-run             # what --reselect-reality would choose, change nothing
bash /root/veiltrium.sh --check-russia        # do Russian networks reach this server? (Globalping)
bash /root/veiltrium.sh --help
```

## Moving to a new server

If the address of a server gets blocked, move the node with all its secrets: every client keeps working after changing only the server address in its link.

```bash
bash veiltrium.sh --export /root/node.vt        # old server; asks for a passphrase (12+ characters)
scp /root/node.vt root@NEW_IP:/root/
bash veiltrium.sh --import /root/node.vt        # new server; a normal install that starts from the export
```

- The export holds the Hysteria, Reality and TrustTunnel keys, passwords and certificates, the server names, the added clients and the probe key. It is a tar of a fixed list of files encrypted with `openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -md sha256` (the file is plain openssl output, mode 600, never overwritten). Anyone with the file and the passphrase owns the node: keep them apart and delete the file afterwards.
- Without a terminal give the passphrase in `VT_EXPORT_PASSPHRASE` / `VT_IMPORT_PASSPHRASE` (the script removes it from its environment at once).
- The import checks the file name by name (regular files from the fixed list only, sizes, SHA-256 manifest, the exact format of every state file, certificate and key pairs) before it places anything. It runs only on a server with no node, or with the same node (a standby copy being refreshed); a different node is refused.
- The new server gets a new web panel password and detects its country name again. Ports of the old node are kept unless you set `REALITY_PORT` / `TT_PORT` yourself.

## Clients

The first client, `main`, is created by the installer (`/root/veiltrium/client.txt`). More clients get their own credentials for all three protocols: a Hysteria user and password, a VLESS UUID and a TrustTunnel login. Revoking one never affects the others.

```bash
bash /root/veiltrium.sh --add-client anna      # prints the details, saves /root/veiltrium/clients/anna.txt
bash /root/veiltrium.sh --list-clients
bash /root/veiltrium.sh --show-client anna
bash /root/veiltrium.sh --remove-client anna
```

- Names: 1-32 characters, `a-z`, `0-9`, `_` and `-`, starting with a letter or digit; `main` is the first client.
- Adding or removing a client rewrites the three server configs as one change and restarts the services: connected clients reconnect within a few seconds. Real clients then check that the main client and the new one work, or that a removed one no longer does. Otherwise the previous settings come back.
- Hysteria uses a password per client (`user:password`). A node installed before this version has one shared password. Its first `--add-client` switches it, so the main client's Hysteria link and JSON change once; its VLESS and TrustTunnel links stay the same.
- A plain re-run keeps every client and their links. If a server name or certificate changes, their detail files are rewritten with the new links.

## Web panel

Every node gets a small web panel: an overview of the node and its protocols, and the clients with their links, QR codes and the AWG Manager JSON; clients can be added and revoked there.

```bash
ssh -N -L 2096:127.0.0.1:2096 root@SERVER_IP     # keep it open, then browse to http://localhost:2096/
```

- The password is printed at the end of the install and kept in `/root/veiltrium/panel.txt` (root only). `bash /root/veiltrium.sh --panel-password` sets a new one and signs everybody out.
- **Nothing new is open on the internet.** The panel listens on `127.0.0.1` only; the SSH tunnel is the way in. The proxies cannot reach it (the firewall keeps them off the server's own addresses), and the panel itself has no internet access (systemd `IPAddressDeny`).
- **No privileges in the web process.** `veiltrium-panel` (Go, one static binary with the interface embedded) runs as its own user in a systemd sandbox. Every action goes over a unix socket, open only to that user's group, to a root helper that systemd starts per request: this installer in `--helper` mode, which accepts six requests (status, list, show, add, remove, check-russia) with checked names and runs the same tested code as the command line.
- Web rules: a session cookie (`HttpOnly`, `SameSite=Strict`), a custom header and same-origin check on every change, only `localhost` host names (no DNS rebinding), a strict Content Security Policy with no external resources, and a lockout after failed logins.
- The binary comes from this repository's releases (`panel-v*`), SHA-256 pinned in the installer like the proxies. `PANEL_ENABLE=0` leaves it out.
- The command line has the same machine interface: `--status`, `--list-clients`, `--show-client NAME`, `--add-client NAME`, `--remove-client NAME`, `--check-russia`, `--diagnose` and `--dry-run` take `--json -`.

## Managing the REALITY SNI

The Reality site is chosen on a new node, and only changes when you ask for it:

```bash
bash /root/veiltrium.sh --dry-run             # see the scores first
bash /root/veiltrium.sh --reselect-reality    # re-evaluate and switch if clearly better
REALITY_SNI=www.example.com bash /root/veiltrium.sh --reselect-reality
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
bash /root/veiltrium.sh --trial-reality www.example.com --trial-minutes 30
bash /root/veiltrium.sh --trial-stop
```

## What Russia sees

A check from a European server says nothing about a home provider in Russia. Two things the installer checks by itself:

- **Server names on the RKN block list.** The list is downloaded at every site choice (`RU_BLOCKLISTS`, by default itdoginfo's curated `Categories/block.lst`: RKN blocks only, without the sites that geoblock Russians themselves, which do not matter for Reality). A candidate on it is never chosen as the Reality site or as a Hysteria / TrustTunnel name; `--diagnose` warns if a name in use is on it.
- **Is the server's address reachable from Russia?** At the end of every install, in `--diagnose`, with `--check-russia` and with the panel's *Check now*, [Globalping](https://globalping.io) probes in Russian networks (two at MTS, two at Rostelecom, four more anywhere in Russia) ping the address and connect to the Reality and TrustTunnel TCP ports. No answer from any of them means the address is blocked: ask the hoster for another one. The result is kept in `/var/lib/veiltrium/russia.json` and shown in the panel.
- **The check repeats every 6 hours** (`veiltrium-russia-check.timer`, started 20 minutes after boot, with a random delay; output in the journal) while `GLOBALPING` is on. `russia.json` keeps `bad_streak`, the number of checks in a row that were `partly` or `blocked` (a `reachable` check resets it; a check Globalping did not answer changes nothing). From 2 in a row, `--status` warns that the address is not reachable from Russia: consider moving to a new server or switching clients to a standby address.
- The server's address goes to Globalping's public measurement service. `GLOBALPING=0` (saved) turns the automatic check off; `--check-russia` still runs on request.
- Neither check sees whether DPI lets a protocol through: that shows only in a real client (for example, the tunnel's status in AWG Manager).

### Optional: a probe from a Keenetic router

`tools/keenetic-vpn-probe.sh` tests every protocol with real clients from the home network itself, through the router's physical WAN, and signs the results for the server (`--import-mts`), where a verified success counts in the Reality site score. It is not needed for a working setup.

Home-network status values on the server: `ok`, `fail`, `degraded`, `stalled`, `route_unverified`, `stale` (older than 14 days) and `untested`. `stalled` means the tunnel connects, but transfers freeze after a few KB (the TSPU 16-20 KB cut-off): the probe got only part of the payload download. Such a result is a penalty in the Reality site score, like `degraded`.

A result measured from a European VPS says nothing about reachability from a home provider. `keenetic-vpn-probe.sh` runs on the router (POSIX sh, BusyBox) and tests each server through the physical WAN. It uses temporary clients with a local SOCKS port only: no TUN, no routes, no firewall changes, and AWG Manager keeps running.

The examples use the Entware SSH server on the router (often port 222); adjust address and port.

1. Each install writes a probe profile `/root/veiltrium/probe.env` (contains passwords; keep it `0600`). Copy it to the router, one file per server:

   ```bash
   ssh root@SERVER_IP "cat /root/veiltrium/probe.env" | ssh -p 222 root@ROUTER "mkdir -p /opt/etc/vpn-probe && cat > /opt/etc/vpn-probe/server1.env && chmod 600 /opt/etc/vpn-probe/server1.env"
   curl -fsSLO https://raw.githubusercontent.com/Vanilla-SilQ-HD/Veiltrium/main/tools/keenetic-vpn-probe.sh
   scp -O -P 222 keenetic-vpn-probe.sh root@ROUTER:/opt/bin/
   ```

2. On the router, install the tools and run the probe. Pass your physical WAN interface; PPPoE is usually `ppp0`.

   ```sh
   opkg update && opkg install tcpdump jq curl
   ip -4 route get SERVER_IP; ip -4 rule show
   sh /opt/bin/keenetic-vpn-probe.sh --all --check-awg --wan ppp0 --output /opt/tmp/vpn-probe.json
   ```

   Options: `--reality`, `--hysteria`, `--trusttunnel`, `--trial-sni a,b`, `--runs N`, `--payload-bytes N`, `--payload-url URL`, `--profile FILE`, `--profile-dir DIR`, `--singbox PATH`, `--tt-client PATH`, `--help`.

3. Import the result on each server:

   ```bash
   ssh -p 222 root@ROUTER "cat /opt/tmp/vpn-probe.json" | ssh root@SERVER_IP "bash /root/veiltrium.sh --import-mts -"
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

- **Hysteria 2.** AWG Manager deliberately drops `pinSHA256` from `hysteria2://` links and imports them with `insecure=true`, i.e. **without any certificate check**. Instead, use section 6 of `/root/veiltrium/client.txt`: a sing-box JSON block with `certificate_public_key_sha256`, imported as a server group (sing-box JSON). The router's sing-box build (`1.15.0-alpha.12-awgm.33`) enforces the pin, including over QUIC; CI checks this with the same build. `keenetic-vpn-probe.sh --check-awg` shows whether the router's config actually pins the key.
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
