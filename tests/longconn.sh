#!/usr/bin/env bash
# CI only: slow downloads through all three protocols, from the "ext" namespace
# (a client outside), to check that a re-run of the installer does not drop them.
#   bash tests/longconn.sh start    starts them (needs tests/sites-setup.sh and /tmp/ttc)
#   bash tests/longconn.sh running  fails unless all of them are still going
#   bash tests/longconn.sh finish   waits for them; each must have downloaded the whole file
set -euxo pipefail
W=/tmp/lc
URL=http://11.22.33.44/big          # 30 MB at 150 KB/s from nginx in the sitesa namespace
SIZE=31457280
PORTS="18301 18302 18303"

start() {
    mkdir -p "$W"
    # Hysteria: the share link as delivered, pointed at the server's outside address
    local url u pub sid user pass sni ttc i p
    url="$(sudo grep -m1 '^hysteria2://' /root/veiltrium/client.txt | sed -E 's#@[^:/]+:#@192.0.2.1:#')"
    printf 'server: "%s"\nsocks5:\n  listen: 127.0.0.1:18301\n' "$url" > "$W/h.yaml"
    sudo ip netns exec ext /usr/local/bin/hysteria client -c "$W/h.yaml" > "$W/h.log" 2>&1 &
    # VLESS Reality
    u="$(sudo awk -F= '$1=="R_UUID"{print $2}' /usr/local/etc/xray/reality.env)"
    pub="$(sudo awk -F= '$1=="R_PUB"{print $2}' /usr/local/etc/xray/reality.env)"
    sid="$(sudo awk -F= '$1=="R_SID"{print $2}' /usr/local/etc/xray/reality.env)"
    sni="$(sudo awk -F= '$1=="R_SITE"{print $2}' /usr/local/etc/xray/reality.env)"
    cat > "$W/x.json" <<EOF
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":18302,"protocol":"socks"}],
 "outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"192.0.2.1","port":443,
   "users":[{"id":"$u","encryption":"none","flow":"xtls-rprx-vision"}]}]},
   "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"$sni",
   "fingerprint":"chrome","publicKey":"$pub","shortId":"$sid"}}}]}
EOF
    sudo ip netns exec ext /usr/local/bin/xray run -c "$W/x.json" > "$W/x.log" 2>&1 &
    # TrustTunnel (official client, HTTP/2)
    ttc="$(find /tmp/ttc -type f -name trusttunnel_client | head -1)"
    user="$(sudo awk -F= '$1=="T_USER"{print $2}' /etc/trusttunnel/node.env)"
    pass="$(sudo awk -F= '$1=="T_PASS"{print $2}' /etc/trusttunnel/node.env)"
    sni="$(sudo awk -F= '$1=="T_SNI"{print $2}' /etc/trusttunnel/node.env)"
    {
        printf 'loglevel = "info"\nvpn_mode = "general"\nkillswitch_enabled = false\n\n[endpoint]\n'
        printf 'hostname = "%s"\naddresses = ["192.0.2.1:8443"]\nusername = "%s"\npassword = "%s"\n' "$sni" "$user" "$pass"
        printf 'has_ipv6 = false\nskip_verification = false\nupstream_protocol = "http2"\n'
        printf "certificate = '''\n%s\n'''\n" "$(sudo cat /etc/trusttunnel/cert.pem)"
        printf '\n[listener.socks]\naddress = "127.0.0.1:18303"\n'
    } > "$W/t.toml"
    sudo ip netns exec ext "$ttc" --config "$W/t.toml" > "$W/t.log" 2>&1 &
    for p in $PORTS; do
        for i in $(seq 1 40); do [ -n "$(sudo ip netns exec ext ss -Htln "sport = :$p")" ] && break; sleep 0.5; done
    done
    sleep 2
    for p in $PORTS; do
        sudo ip netns exec ext curl -s -o /dev/null -w '%{http_code} %{size_download}\n' --max-time 600 \
            --socks5-hostname "127.0.0.1:$p" "$URL" > "$W/dl-$p.txt" 2>&1 &
        echo $! > "$W/dl-$p.pid"
    done
    sleep 5
    running
}

running() {
    local p
    for p in $PORTS; do
        if ! kill -0 "$(cat "$W/dl-$p.pid")" 2>/dev/null; then
            echo "download through port $p is not running any more: $(cat "$W/dl-$p.txt")"; exit 1
        fi
    done
    echo "all three downloads are still running"
}

finish() {
    local p
    for p in $PORTS; do
        while kill -0 "$(cat "$W/dl-$p.pid")" 2>/dev/null; do sleep 2; done
        echo "port $p: $(cat "$W/dl-$p.txt")"
        [ "$(cat "$W/dl-$p.txt")" = "200 $SIZE" ] || { tail -20 "$W"/*.log; exit 1; }
    done
    sudo pkill -f "$W/h.yaml" || true
    sudo pkill -f "$W/x.json" || true
    sudo pkill -f "$W/t.toml" || true
}

"$@"
