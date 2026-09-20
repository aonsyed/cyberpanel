#!/bin/sh
# Offline Ubuntu 24.04 package build. Run only inside a QEMU build guest.
# Inputs are the official release archives, never a checkout with unknown changes.
set -eu
umask 022
test "$(uname -s)" = Linux
test "${CYBERPANEL_QEMU_NATIVE_BUILD:-}" = 1
test "$#" = 2 || { echo "usage: $0 INPUT_DIRECTORY OUTPUT_DIRECTORY" >&2; exit 2; }
recipe=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
inputs=$(realpath "$1")
output=$(realpath "$2")
. /etc/os-release
test "$ID:$VERSION_ID" = ubuntu:24.04
test "$(df -Pk /var/tmp | awk 'NR==2 {print $4}')" -ge 2097152
arch=$(dpkg --print-architecture)
case "$arch" in arm64|amd64) ;; *) exit 2 ;; esac
version=1.9.2-1+noble+cpmodsec3.0.16.2
package="$output/ols-modsecurity_${version}_${arch}.deb"
test ! -e "$package"
cd "$inputs"
printf '%s\n' \
  '739be3c71b1939f14e91afe1eeae654acbd440da11bd29790458840bc315b4c0  modsecurity-v3.0.16.tar.gz' \
  '7df47b8ea046267c03483ab967c230cbc6236bbd983696361e152ac33992875f  openlitespeed-1.9.2.tar.gz' | sha256sum -c -
# OLS v1.9.2 resolves to bcd05f4048226cbd0adc75ce6b825527ffe4b6e5.
work=$(mktemp -d /var/tmp/cyberpanel-waf-build.XXXXXX)
cleanup() {
  result=$?
  trap - 0
  for log in configure make; do
    if test -f "$work/$log.log"; then
      cp "$work/$log.log" "$output/ols-modsecurity-$arch-$log.log"
    fi
  done
  case "$work" in /var/tmp/cyberpanel-waf-build.??????) rm -rf -- "$work" ;; esac
  exit "$result"
}
trap cleanup 0
printf 'Native build workspace: %s\n' "$work"
tar --no-same-owner -xzf modsecurity-v3.0.16.tar.gz -C "$work"
tar --no-same-owner -xzf openlitespeed-1.9.2.tar.gz -C "$work"
modsec="$work/modsecurity-v3.0.16"
ols="$work/openlitespeed-bcd05f4048226cbd0adc75ce6b825527ffe4b6e5"
patch --batch --fuzz=0 -d "$ols" -p1 < "$recipe/ols-modsecurity-body-limit.patch"
cd "$modsec"
# Match the connector's documented C++ ABI; no automatic fetch/build scripts.
# Lua execution, remote rules and persistent IP collections are not panel APIs.
CFLAGS='-O2 -g0' CXXFLAGS='-O2 -g0 -D_GLIBCXX_USE_CXX11_ABI=0' \
  ./configure --disable-shared --enable-static --with-pic \
  --without-lua --without-ssdeep --without-geoip --without-lmdb \
  --without-curl --with-yajl --with-libxml --with-pcre2 \
  > "$work/configure.log" 2>&1
make -j2 > "$work/make.log" 2>&1
# OLS itself exports selected functions from its bundled old libstdc++. A
# partly interposed random_device (vendor initializer + system getter) crashes
# at live startup. Keep the module's C++ runtime private; export only the LSI
# entrypoint. Undefined LSI host callbacks still resolve from the server.
printf '%s\n' '{ global: mod_security; local: *; };' > "$work/exports.map"
g++ -std=gnu++17 -O2 -g0 -fPIC -fvisibility=hidden \
	-D_REENTRANT -D_GLIBCXX_USE_CXX11_ABI=0 -shared \
	-static-libstdc++ -static-libgcc -Wl,--version-script="$work/exports.map" \
  -I"$ols/include" -I"$ols/src" -I"$modsec/headers" \
  "$ols/src/modules/modsecurity-ls/mod_security.cpp" \
  "$modsec/src/.libs/libmodsecurity.a" \
  $(pkg-config --libs libxml-2.0 yajl libpcre2-8) \
  -lpthread -o "$work/mod_security.so"
strip --strip-unneeded "$work/mod_security.so"
stage="$work/package"
install -d "$stage/DEBIAN" "$stage/usr/local/lsws/modules" \
  "$stage/usr/share/doc/ols-modsecurity"
install -m 0644 "$work/mod_security.so" "$stage/usr/local/lsws/modules/mod_security.so"
install -m 0644 "$ols/LICENSE" "$stage/usr/share/doc/ols-modsecurity/OLS-LICENSE"
install -m 0644 "$ols/GPL.txt" "$stage/usr/share/doc/ols-modsecurity/OLS-GPL"
install -m 0644 "$modsec/LICENSE" "$stage/usr/share/doc/ols-modsecurity/ModSecurity-LICENSE"
install -m 0644 "$recipe/ols-modsecurity-body-limit.patch" "$stage/usr/share/doc/ols-modsecurity/body-limit.patch"
printf '%s\n' \
  'Package: ols-modsecurity' "Version: $version" "Architecture: $arch" \
  'Maintainer: CyberPanel <security@cyberpanel.net>' \
  'Section: httpd' 'Priority: optional' \
  'Depends: openlitespeed (= 1.9.2-1+noble), libc6 (>= 2.38), libstdc++6, libgcc-s1, libxml2, libyajl2, libpcre2-8-0' \
  'Description: OpenLiteSpeed connector with pinned ModSecurity 3.0.16' \
  ' Offline QEMU-built security update; contains no service-start scripts.' \
  > "$stage/DEBIAN/control"
export SOURCE_DATE_EPOCH=1787011200
find "$stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
dpkg-deb --root-owner-group --build "$stage" "$package"
sha256sum "$package"
printf 'Build logs retained in %s; temporary sources and objects are cleaned automatically.\n' "$output"
