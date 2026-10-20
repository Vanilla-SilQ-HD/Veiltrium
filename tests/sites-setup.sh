#!/usr/bin/env bash
# CI only: local HTTPS "mask site" candidates with known properties, in network
# namespaces, trusted through a local CA. Names resolve through /etc/hosts.
#   good1.cand.test    198.51.100.10  valid certificate, TLS 1.3, h2
#   good2.cand.test    198.51.100.20  valid certificate, TLS 1.3, h2, +80 ms delay (namespace sitesb)
#   badcert.cand.test  198.51.100.10  certificate from an untrusted CA
#   noh2.cand.test     198.51.100.11  valid certificate, no HTTP/2
#   multi.cand.test    198.51.100.10 + 198.51.100.12 (nothing answers there: one bad CDN address)
#   timeout.cand.test  198.51.100.13  packets dropped (timeout)
#   nxdomain.cand.test (not resolvable)
set -euxo pipefail
D=/tmp/sites
mkdir -p "$D"
cd "$D"

sudo apt-get -q install -y nginx-light >/dev/null 2>&1 || sudo apt-get -q install -y nginx >/dev/null
sudo systemctl disable --now nginx >/dev/null 2>&1 || true

# local CA (trusted system-wide) and an untrusted one
openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 30 \
    -subj "/CN=hy2 CI test CA" -keyout ca.key -out ca.crt \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 30 \
    -subj "/CN=untrusted CA" -keyout bad-ca.key -out bad-ca.crt \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
sudo cp ca.crt /usr/local/share/ca-certificates/veiltrium-ci-test-ca.crt
sudo update-ca-certificates >/dev/null
leaf() {   # name, ca
    openssl req -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -subj "/CN=$1" -keyout "$1.key" -out "$1.csr"
    printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n' "$1" > "$1.ext"
    openssl x509 -req -in "$1.csr" -CA "$2.crt" -CAkey "$2.key" -CAcreateserial -days 30 -extfile "$1.ext" -out "$1.crt"
}
for n in good1 good2 noh2 multi; do leaf "$n.cand.test" ca; done
leaf badcert.cand.test bad-ca

# namespace sitesa: 198.51.100.10-13 ; namespace sitesb: 198.51.100.20 with delay
mkns() {   # ns, host-side veth, ns-side veth, host addr, addresses...
    local ns="$1" vh="$2" vn="$3" haddr="$4"; shift 4
    sudo ip netns add "$ns"
    sudo ip link add "$vh" type veth peer name "$vn"
    sudo ip link set "$vn" netns "$ns"
    sudo ip addr add "$haddr" dev "$vh"
    sudo ip link set "$vh" up
    sudo ip netns exec "$ns" ip link set lo up
    sudo ip netns exec "$ns" ip link set "$vn" up
    for a in "$@"; do sudo ip netns exec "$ns" ip addr add "$a/32" dev "$vn"; sudo ip route add "$a/32" dev "$vh"; done
    sudo ip netns exec "$ns" ip route add default dev "$vn"
}
# 11.22.33.44: a "global" address for the slow download (TrustTunnel refuses private and test ranges)
mkns sitesa veth-sa-h veth-sa-n 198.51.100.1/32 198.51.100.10 198.51.100.11 198.51.100.13 11.22.33.44
mkns sitesb veth-sb-h veth-sb-n 198.51.100.2/32 198.51.100.20
sudo ip netns exec sitesb tc qdisc add dev veth-sb-n root netem delay 40ms
sudo tc qdisc add dev veth-sb-h root netem delay 40ms
# timeout.cand.test: silently dropped
sudo ip netns exec sitesa nft add table inet t
sudo ip netns exec sitesa nft add chain inet t in '{ type filter hook input priority 0; }'
sudo ip netns exec sitesa nft add rule inet t in ip daddr 198.51.100.13 drop

conf() {   # listen address, http2 on|off, servers...
    local addr="$1" h2="$2"; shift 2
    local n
    for n in "$@"; do
        cat <<EOF
server {
    listen $addr:443 ssl;
    http2 $h2;
    server_name $n;
    ssl_certificate $D/$n.crt;
    ssl_certificate_key $D/$n.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    location / { return 200 "ok $n\n"; }
}
EOF
    done
}
nginx_ns() {   # ns, conf body
    local ns="$1" body="$2"
    sudo mkdir -p "$D/$ns"
    printf 'worker_processes 1;\npid %s/%s/nginx.pid;\nerror_log %s/%s/error.log;\nevents {}\nhttp {\n access_log off;\n%s\n}\n' \
        "$D" "$ns" "$D" "$ns" "$body" | sudo tee "$D/$ns/nginx.conf" >/dev/null
    sudo ip netns exec "$ns" nginx -t -c "$D/$ns/nginx.conf"
    sudo ip netns exec "$ns" nginx -c "$D/$ns/nginx.conf"
}
# nginx 1.25.1+ knows "http2 on|off"; older ones take "listen ... http2"
if nginx -V 2>&1 | grep -E 'nginx/1\.(2[5-9]|[3-9][0-9])' >/dev/null; then
    A="$(conf 198.51.100.10 on good1.cand.test badcert.cand.test multi.cand.test; conf 198.51.100.11 off noh2.cand.test)"
    B="$(conf 198.51.100.20 on good2.cand.test)"
else
    A="$(conf 198.51.100.10 on good1.cand.test badcert.cand.test multi.cand.test | sed 's/ssl;/ssl http2;/; /http2 on;/d')
$(conf 198.51.100.11 off noh2.cand.test | sed '/http2 off;/d')"
    B="$(conf 198.51.100.20 on good2.cand.test | sed 's/ssl;/ssl http2;/; /http2 on;/d')"
fi
# a slow 30 MB download (150 KB/s) for the "connections survive a re-run" test
mkdir -p "$D/www"
dd if=/dev/urandom of="$D/www/big" bs=1M count=30 status=none
dd if=/dev/urandom of="$D/www/fast" bs=1M count=8 status=none   # full speed: traffic counters test (tests/features-ci.sh)
chmod 755 "$D/www"; chmod 644 "$D/www/big" "$D/www/fast"
A="$A
server {
    listen 11.22.33.44:80;
    root $D/www;
    location = /big { limit_rate 150k; }
    location / { }
}"
nginx_ns sitesa "$A"
nginx_ns sitesb "$B"

sudo tee -a /etc/hosts >/dev/null <<'EOF'
198.51.100.10 good1.cand.test badcert.cand.test multi.cand.test
198.51.100.12 multi.cand.test
198.51.100.11 noh2.cand.test
198.51.100.13 timeout.cand.test
198.51.100.20 good2.cand.test
EOF
getent ahostsv4 multi.cand.test | awk '{print $1}' | sort -u
curl -s --http2 -o /dev/null -w '%{http_version} %{http_code}\n' https://good1.cand.test/
curl -s --http2 -o /dev/null -w '%{http_version} %{http_code}\n' https://good2.cand.test/
curl -s --http2 -o /dev/null -w '%{http_version} %{http_code}\n' https://noh2.cand.test/
if curl -s -o /dev/null https://badcert.cand.test/; then echo "badcert must not verify"; exit 1; fi
