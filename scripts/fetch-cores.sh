#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

SB=1.14.4
XR=26.10.31
T2S=2.7.0

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
get() { curl -fL --retry 3 -o "$T/$2" "$1"; }

get "https://github.com/SagerNet/sing-box/releases/download/v$SB/sing-box-$SB-windows-amd64.zip" sbw.zip
get "https://github.com/XTLS/Xray-core/releases/download/v$XR/Xray-windows-64.zip" xrw.zip
get "https://github.com/SagerNet/sing-box/releases/download/v$SB/sing-box-$SB-android-arm64.tar.gz" sba.tgz
get "https://github.com/XTLS/Xray-core/releases/download/v$XR/Xray-android-arm64-v8a.zip" xra.zip
get "https://github.com/xjasonlyu/tun2socks/releases/download/v$T2S/tun2socks-linux-arm64.zip" t2s.zip

mkdir -p "$T/w" "$T/a"
unzip -q -o -j "$T/sbw.zip" "sing-box-$SB-windows-amd64/sing-box.exe" "sing-box-$SB-windows-amd64/libcronet.dll" -d "$T/w"
unzip -q -o -j "$T/xrw.zip" xray.exe -d "$T/w"
tar -xzf "$T/sba.tgz" -C "$T/a" --strip-components=1 "sing-box-$SB-android-arm64/sing-box"
unzip -q -o -j "$T/xra.zip" xray -d "$T/a"
unzip -q -o -j "$T/t2s.zip" tun2socks-linux-arm64 -d "$T/a"

(cd "$T" && sha256sum -c --quiet) <<SUM
8f30682ee198855440d2a7fe070d5d3653793b2d01bb8c85eea88f93bbe7c8b9  w/sing-box.exe
3217c6260fbca5f16072e0b79735742f40109a63bb0ff88fd6b96dd6b54a2928  w/libcronet.dll
d5b558191cccb1e92a5772b68b8cab67717b26f634b0f15153215f65ae982a7e  w/xray.exe
2ce1c1c2a265e7be21ffa7aaf2b58619986629e9caecfc2d3f80ef4d25b7f965  a/sing-box
ce8f18c44eb40cbd4563433109e0ede36c38b89c2fe71d1e583b4332ebefb622  a/xray
7d1b86a1f8cb681fcdf54d535372ad52c6e3f4731d5a8942b09bee2061f37053  a/tun2socks-linux-arm64
SUM

mkdir -p assets
for f in sing-box.exe libcronet.dll xray.exe; do
  zstd -q -f -19 -T0 "$T/w/$f" -o "assets/$f.zst"
done

L=android/libs/arm64-v8a
mkdir -p "$L"
install -m 755 "$T/a/sing-box" "$L/libsingbox.so"
install -m 755 "$T/a/xray" "$L/libxray.so"
install -m 755 "$T/a/tun2socks-linux-arm64" "$L/libtun2socks.so"

mkdir -p rules
G=https://raw.githubusercontent.com
curl -fL --retry 3 -o rules/geoip-ru.srs "$G/SagerNet/sing-geoip/rule-set/geoip-ru.srs"
curl -fL --retry 3 -o rules/geosite-category-ru.srs "$G/SagerNet/sing-geosite/rule-set/geosite-category-ru.srs"
curl -fL --retry 3 -o rules/geoip-ru-blocked.srs "$G/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geoip/geoip-ru-blocked.srs"
curl -fL --retry 3 -o rules/geosite-ru-blocked.srs "$G/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-ru-blocked.srs"

case "$(uname -m)" in
  x86_64|amd64) HA=amd64; HS=1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a ;;
  aarch64|arm64) HA=arm64; HS=d953af885f11d6b547c21a3c0ffe70796963afc802fab959d548311002b4908a ;;
  *) echo "unsupported host" >&2; exit 1 ;;
esac
get "https://github.com/SagerNet/sing-box/releases/download/v$SB/sing-box-$SB-linux-$HA.tar.gz" sbh.tgz
mkdir -p "$T/h"
tar -xzf "$T/sbh.tgz" -C "$T/h" --strip-components=1 "sing-box-$SB-linux-$HA/sing-box"
echo "$HS  $T/h/sing-box" | sha256sum -c --quiet
get "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt" adguard.txt
[ "$(grep -c '^||' "$T/adguard.txt")" -gt 50000 ]
"$T/h/sing-box" rule-set convert -t adguard -o rules/adguard-dns.srs "$T/adguard.txt"
rm -f rules/geosite-category-ads-all.srs

echo "ok"
