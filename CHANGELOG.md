English | [Русский](CHANGELOG.ru.md)

# Changelog

All notable changes to Veiltrium are recorded here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), adapted to date versions.

- Installer versions are dates: tags look like `vYYYY.MM.DD` or `vYYYY.MM.DD.N`, and the
  script prints the version as `YYYY-MM-DD.N`. There is no tag `v2026.10.13.2`; its changes
  are listed under 2026-10-13.3.
- The web panel has its own versions (`panel-vX.Y.Z`, see [Web panel](#web-panel)). Each
  installer release pins exactly one panel release by SHA-256.

## Unreleased

- CI now selects FAST, INTEGRATION or FULL by PR risk; draft installer changes defer FULL until ready for review. Removed duplicate FAST triggers/builds and preserved the tested source panel across installer re-runs.

## [2026-10-30] - 2026-10-30

Web panel: 0.1.8

### Added
- Evidence-based connection overview with freshness, per-protocol home check dates and a suggested next action.
- Four-step device setup for Android, Apple devices, Windows and Keenetic/AWG Manager, with explicit import formats and manual connection checks.
- Authenticated standby state snapshots: `standby-receipt`, `verify-standby` and `standby-status`, a panel comparison and local-only warnings before client changes. Snapshots expire after 24 hours; there is no remote synchronization or shared traffic quota.

### Fixed
- Copy fields offer manual selection when the browser clipboard API is unavailable over HTTP.
- Globalping failures are described as missing replies, without asserting a confirmed block.

## [2026-10-23] - 2026-10-23

Web panel: 0.1.7

### Added
- The web panel through the VPN, without SSH (`PANEL_VPN`, on by default, saved): a separate
  VLESS Reality profile only for the admin, in `/root/veiltrium/panel.txt`. With it connected,
  `http://SERVER_IP:2096/` opens the panel (the password is still asked). Xray routes only that
  profile's connections to the panel's port to the panel, from the source address `127.0.0.2`,
  and the firewall lets Xray reach the panel from that address only: client profiles, the other
  protocols and the internet do not get there, and no port is opened. The installer checks it
  with a real client. `PANEL_VPN=0` removes the profile.
- Web panel: `--host IP` accepts the server's own address as a host name (IP addresses only).

### Changed
- Web panel: failed logins pause all logins after the fifth, for 1, 2, 4 minutes and so on up
  to an hour (was: 5 failures in 5 minutes, then a fixed pause); a success or a day without
  failures starts the count again.
- `panel.txt` is kept up to date on every run (the password stays).

### Upgrade notes
- The first run of this version adds the panel profile to the Xray config, so Xray restarts
  once. Client links do not change.

## [2026-10-21] - 2026-10-21

Web panel: 0.1.6

### Added
- Per-client base64 subscription and sing-box profile (as files and as JSON), a "Phones and
  apps" section in the client files, and a subscription QR code.
- The panel gets an "Import to apps" section (subscription, sing-box profile, app hints); standby
  links are included in the downloaded `.txt`.

### Changed
- The sing-box profile notes that it needs sing-box 1.12 or newer.

## [2026-10-20.5] - 2026-10-20

Web panel: 0.1.5

### Fixed
- Traffic counters, and therefore traffic limits, did not work in 2026-10-20.3 and 2026-10-20.4:
  the egress firewall rules for the proxy users dropped the services' replies from their loopback
  statistics ports, so the collector never got an answer. Replies on established loopback
  connections are now allowed; new connections from the proxies to local addresses stay blocked.
- `apt-get` retries while unattended-upgrades or apt-daily holds the archive lock.
- No stray `#` lines in `--help`; `veiltrium help` prints the full help and an unknown word
  shows the short usage.

### Tests
- The full test run now covers the 2026-10-20 features (traffic, limits, reset, standby,
  alerts, short command, export, uninstall, import).

### Upgrade notes
- The firewall reloads; no service restarts.

## [2026-10-20.4] - 2026-10-20

Web panel: 0.1.5

### Added
- Per-client traffic limit, expiry date, periodic reset, and disable/enable
  (`--set-client`, `--disable-client`, `--enable-client`, `--enforce`).
- The panel gets limits, disable/enable, usage badges, and a Russian interface with a
  language switch.

### Changed
- The panel shows traffic in decimal units, the same as the limits.

## [2026-10-20.3] - 2026-10-20

Web panel: 0.1.4

### Added
- Per-client traffic counters for all three protocols (`--traffic`, `--traffic-reset`,
  `--collect-traffic`), with daily totals kept for 90 days; traffic appears in the client,
  clients and status output.
- `--reset-client`, `--uninstall`, an audit log, and server load in `--status`.
- Opt-in outbound alerts (Telegram, webhook), `--check-update` and `--update`.
- A short `veiltrium` command, terminal QR codes (`--qr`), and a full settings list in `--help`.
- The panel shows server load, traffic, standby links, credential reset and recent actions.

### Fixed
- A standby deployed from an export drops its own address from the saved standby list.
- The export/import validator accepts the standby list, fixing `--export` failing on a node
  with `STANDBY_HOSTS` set in 2026-10-20.2.

### Upgrade notes
- The first run restarts Hysteria, Xray and TrustTunnel once (traffic statistics are added to
  their configs). Links and credentials do not change.
- Traffic counters do not work in this release; fixed in 2026-10-20.5.

## [2026-10-20.2] - 2026-10-20

Web panel: 0.1.3

### Added
- `STANDBY_HOSTS`: up to three public IPv4 standby servers get their own client links and
  sing-box outbounds (with a urltest group) and are added to the AWG Manager server group.
  Output is unchanged without standby servers.
- `--export` and `--import` move a node to a new server with the same secrets, through an
  encrypted archive that is validated before anything is placed.
- A `stalled` home-network status (the 16-20 KB connection freeze seen on some Russian
  networks) and a check from Russia every six hours.

### Upgrade notes
- `--export` fails on a node with `STANDBY_HOSTS`; fixed in 2026-10-20.3.

## [2026-10-20.1] - 2026-10-20

Web panel: 0.1.3

### Added
- `--check-russia --json` reports `{"verdict":"unchecked"}` instead of `null`.

### Changed
- Maintenance modes wait for the installer lock (`VEILTRIUM_LOCK_WAIT`, default 90 s) and exit
  with code 75 when it stays busy; the panel helper gives reads 10 s.
- The panel reports a busy lock as HTTP 503 instead of hanging for 90 seconds, and shows
  "Globalping did not answer" instead of silently keeping the old result.

### Fixed
- Panel shutdown waits for requests in flight; unknown `/api/` paths return 404.
- The selected client is reloaded after an add (the Hysteria link of `main` can change) and
  after an interrupted add or remove.

### Security
- An already installed panel of the pinned version is also checked against its SHA-256.

## [2026-10-20] - 2026-10-20

Web panel: 0.1.2

### Fixed
- An existing but empty `reality.env` on a node with client files stops the run instead of
  generating new Reality keys.
- TrustTunnel restarts when its certificate is regenerated for the same hostname.
- The router probe's startup cleanup no longer deletes its own result file.

## [2026-10-13.4] - 2026-10-13

Web panel: 0.1.2

### Changed
- Panel actions are served one at a time, so the Overview tiles no longer collide on the
  installer lock; maintenance modes wait up to 90 s for the lock.
- The panel port (`PANEL_PORT`) is validated and kept between runs.

### Fixed
- A long `check-russia` request is no longer cancelled by an HTTP read timeout.
- A wrong panel password is reported as such, and lockout counting is exact.
- A failed panel download no longer fails the whole install; the panel is installed on the
  next run. A checksum mismatch still stops it.
- A Globalping check with no answer keeps the last real result and is bounded to two minutes.
- A failed country lookup is retried on the next run.

## [2026-10-13.3] - 2026-10-13

Web panel: 0.1.1

Includes the changes of 2026-10-13.2, which was never tagged.

### Added
- Web panel on loopback only (reached through an SSH tunnel) with a root helper: Overview and
  Clients (links, QR codes, AWG Manager JSON, add, revoke). The web process is unprivileged
  and sandboxed; login uses PBKDF2, strict session cookies, CSRF protection and a lockout.
- `--panel-password` sets a new panel password and signs everyone out.
- Check from Russia: Globalping probes in Russian networks (MTS, Rostelecom and others) ping
  the server and connect to its TCP ports, at the end of the install, in `--diagnose`, with
  `--check-russia` and the panel's "Check now" button. `GLOBALPING=0` (saved) turns it off.
- `--status` and the report show the result; the panel Overview gets a "From Russia" tile.
- Server names on the RKN block list (itdoginfo `Categories/block.lst`) are never chosen for
  Reality, Hysteria or TrustTunnel; `--diagnose` warns about one in use.
- JSON interface: `--status`, `--list-clients`, `--show-client`, `--add-client`,
  `--remove-client`, `--diagnose` and `--dry-run` accept `--json -` or `--json FILE`.

### Changed
- The project is renamed to Veiltrium: `veiltrium.sh`, `/etc/veiltrium`, `/var/lib/veiltrium`,
  `/root/veiltrium/`, firewall table `inet veiltrium`, `VT_RECONFIGURE` and `VT_AUTO_REBOOT`
  (the old `HY2_RECONFIGURE` and `HY2_AUTO_REBOOT` are still accepted).
- The router probe `keenetic-vpn-probe.sh` moves to `tools/` and becomes optional.

### Fixed
- A move from `hy2-secure-install.sh` that is cut off leaves a loadable firewall, so a reboot
  in the middle of the move still boots a filtered server.
- The move also removes the old scanner timer's systemd stamp, leftover temp folders, backups
  and stray files of the old version.

### Upgrade notes
- From 2026-10-13.1 or earlier (`hy2-secure-install.sh`): the first run moves the node to the
  Veiltrium names. Keys, passwords, certificates, clients and links stay; old files are removed
  at the end of the run. The proxies restart once because the markers in their configs changed.
  Maintenance modes refuse an unmoved node and ask you to run the installer. A still running
  old installer blocks the move.

## [2026-10-13.1] - 2026-10-13

Last release of `hy2-secure-install.sh`.

### Fixed
- Router probe: reads iptables 1.4.21 rules (Keenetic) and follows mangle jumps instead of
  always ending in `iptables_unreadable`.
- `--diagnose` no longer prints a false error on a node without added clients.

## [2026-10-13] - 2026-10-13

First public release. Automated, security-focused deployment of Hysteria 2, VLESS Reality and
TrustTunnel on Ubuntu, with checksum-verified official binaries, a nftables firewall, scanner
blocking and transactional changes with automatic rollback.

## Web panel

The panel is released separately (`panel-vX.Y.Z`; amd64 and arm64 with SHA256SUMS).

### [0.1.8] - 2026-10-30
- Connection health distinguishes service status, address replies and verified home-network tunnel tests, with dates and a next action.
- Four-step device setup for Android, Apple devices, Windows and Keenetic/AWG Manager.
- Standby state comparison with authenticated snapshots, expiry and warnings before local client changes.
- Manual copy fallback when Clipboard API access is unavailable; shared secret visibility across the client card and setup guide.

### [0.1.7] - 2026-10-23
- `--host IP`: the server's own address is accepted as a host name (the panel through the VPN).
- Failed logins pause all logins with an escalating delay (1 min doubling up to 1 h).

### [0.1.6] - 2026-10-21
- "Import to apps" section: subscription, sing-box profile and app hints.
- Standby links in the downloaded client `.txt`.

### [0.1.5] - 2026-10-20
- Per-client limits, disable and enable, with usage badges.
- Russian interface with a language switch.
- Traffic shown in decimal units, matching the limits.

### [0.1.4] - 2026-10-20
- Server load, traffic, standby links and recent actions.
- Credential reset.

### [0.1.3] - 2026-10-20
- A busy installer lock gives HTTP 503 instead of a long hang; unknown API paths give 404.
- "Check now" reports when Globalping did not answer; the selected client is reloaded after changes.
- Graceful shutdown waits for requests in flight.

### [0.1.2] - 2026-10-13
- Helper calls run one at a time; no HTTP read timeout, so long checks complete.
- A wrong password is reported as such; lockout counting is exact.

### [0.1.1] - 2026-10-13
- "From Russia" tile and "Check now" button.

### [0.1.0] - 2026-10-13
- First release: Overview and Clients (links, QR codes, AWG Manager JSON, add, revoke), loopback
  only with password login.

[2026-10-30]: https://github.com/Vanilla-SilQ-HD/Veiltrium/compare/v2026.10.23...v2026.10.30
[2026-10-23]: https://github.com/Vanilla-SilQ-HD/Veiltrium/compare/v2026.10.21...v2026.10.23
[2026-10-21]: https://github.com/Vanilla-SilQ-HD/Veiltrium/compare/v2026.10.20.5...v2026.10.21
[2026-10-20.5]: https://github.com/Vanilla-SilQ-HD/Veiltrium/compare/v2026.10.20.4...v2026.10.20.5
[2026-10-20.4]: https://github.com/Vanilla-SilQ-HD/Veiltrium/compare/v2026.10.20.3...v2026.10.20.4
[2026-10-20.3]: https://github.com/Vanilla-SilQ-HD/Veiltrium/compare/v2026.10.20.2...v2026.10.20.3
[2026-10-20.2]: https://github.com/Vanilla-SilQ-HD/Veiltrium/compare/v2026.10.20.1...v2026.10.20.2
[2026-10-20.1]: https://github.com/Vanilla-SilQ-HD/Veiltrium/compare/v2026.10.20...v2026.10.20.1
[2026-10-20]: https://github.com/Vanilla-SilQ-HD/Veiltrium/compare/v2026.10.13.4...v2026.10.20
[2026-10-13.4]: https://github.com/Vanilla-SilQ-HD/Veiltrium/compare/v2026.10.13.3...v2026.10.13.4
[2026-10-13.3]: https://github.com/Vanilla-SilQ-HD/Veiltrium/compare/v2026.10.13.1...v2026.10.13.3
[2026-10-13.1]: https://github.com/Vanilla-SilQ-HD/Veiltrium/compare/v2026.10.13...v2026.10.13.1
[2026-10-13]: https://github.com/Vanilla-SilQ-HD/Veiltrium/tree/v2026.10.13
[0.1.8]: https://github.com/Vanilla-SilQ-HD/Veiltrium/compare/panel-v0.1.7...panel-v0.1.8
[0.1.7]: https://github.com/Vanilla-SilQ-HD/Veiltrium/compare/panel-v0.1.6...panel-v0.1.7
[0.1.6]: https://github.com/Vanilla-SilQ-HD/Veiltrium/compare/panel-v0.1.5...panel-v0.1.6
[0.1.5]: https://github.com/Vanilla-SilQ-HD/Veiltrium/compare/panel-v0.1.4...panel-v0.1.5
[0.1.4]: https://github.com/Vanilla-SilQ-HD/Veiltrium/compare/panel-v0.1.3...panel-v0.1.4
[0.1.3]: https://github.com/Vanilla-SilQ-HD/Veiltrium/compare/panel-v0.1.2...panel-v0.1.3
[0.1.2]: https://github.com/Vanilla-SilQ-HD/Veiltrium/compare/panel-v0.1.1...panel-v0.1.2
[0.1.1]: https://github.com/Vanilla-SilQ-HD/Veiltrium/compare/panel-v0.1.0...panel-v0.1.1
[0.1.0]: https://github.com/Vanilla-SilQ-HD/Veiltrium/tree/panel-v0.1.0
