#!/bin/sh
# Offline CRS runtime package. No downloads, activation or maintainer scripts.
set -eu
test "$(uname -s)" = Linux
test "${CYBERPANEL_QEMU_NATIVE_BUILD:-}" = 1
test "$#" = 2 || { echo "usage: $0 INPUT_DIRECTORY OUTPUT_DIRECTORY" >&2; exit 2; }
inputs=$(realpath "$1")
output=$(realpath "$2")
package="$output/cyberpanel-waf-crs_4.29.0-1_all.deb"
test ! -e "$package"
cd "$inputs"
printf '%s\n' \
  '1aa1c5c8fc29e532d35293bcea36bf72de61db8f6ed4716a0f91ab14552b7fed  crs.tar.gz' \
  '739be3c71b1939f14e91afe1eeae654acbd440da11bd29790458840bc315b4c0  modsecurity-v3.0.16.tar.gz' | sha256sum -c -
work=$(mktemp -d /var/tmp/cyberpanel-crs-package.XXXXXX)
cleanup() {
  result=$?
  trap - 0
  case "$work" in /var/tmp/cyberpanel-crs-package.??????) rm -rf -- "$work" ;; esac
  exit "$result"
}
trap cleanup 0
install -d -m 0700 "$work/keyring"
gpg --homedir "$work/keyring" --batch --import crs-security.asc
gpg --homedir "$work/keyring" --batch --status-fd 1 \
  --verify crs.tar.gz.asc crs.tar.gz > "$work/signature.status"
grep -q '^\[GNUPG:\] VALIDSIG 36006F0E0BA167832158821138EEACA1AB8A6E72 ' "$work/signature.status"
tar --no-same-owner -xzf crs.tar.gz -C "$work"
stage="$work/package"
share="$stage/usr/share/modsecurity-crs"
crs="$share/4.29.0"
install -d "$stage/DEBIAN" "$crs" "$share/modsecurity-3.0.16" \
  "$stage/usr/share/doc/cyberpanel-waf-crs"
# The upstream minimal archive removes development material, not runtime rules.
# Retain every rule, plugin ordering stub and referenced data file unchanged.
cp -R "$work/coreruleset-4.29.0/rules" "$work/coreruleset-4.29.0/plugins" "$crs/"
install -m 0644 "$work/coreruleset-4.29.0/crs-setup.conf.example" "$crs/crs-setup.conf"
install -m 0644 "$work/coreruleset-4.29.0/LICENSE" "$stage/usr/share/doc/cyberpanel-waf-crs/CRS-LICENSE"
for file in modsecurity.conf-recommended unicode.mapping LICENSE; do
  tar -xOzf modsecurity-v3.0.16.tar.gz "modsecurity-v3.0.16/$file" > "$share/modsecurity-3.0.16/$file"
done
printf '%s\n' \
  'Include /usr/share/modsecurity-crs/4.29.0/crs-setup.conf' \
  'Include /usr/share/modsecurity-crs/4.29.0/plugins/*-config.conf' \
  'Include /usr/share/modsecurity-crs/4.29.0/plugins/*-before.conf' \
  'Include /usr/share/modsecurity-crs/4.29.0/rules/*.conf' \
  'Include /usr/share/modsecurity-crs/4.29.0/plugins/*-after.conf' \
  > "$share/owasp-crs.load"
printf '%s\n' \
  'Package: cyberpanel-waf-crs' 'Version: 4.29.0-1' 'Architecture: all' \
  'Maintainer: CyberPanel <security@cyberpanel.net>' \
  'Section: httpd' 'Priority: optional' \
  'Conflicts: modsecurity-crs' 'Replaces: modsecurity-crs' \
  'Description: Pinned complete OWASP CRS runtime for CyberPanel' \
  ' Includes upstream runtime rules and engine configuration reference.' \
  ' Installation does not enable, replace or reload the live WAF policy.' \
  > "$stage/DEBIAN/control"
find "$stage/usr" -type d -exec chmod 0755 {} +
find "$stage/usr" -type f -exec chmod 0644 {} +
# Commit the complete recursive runtime bytes, not merely its Include entrypoint.
(cd "$stage" && find usr/share/modsecurity-crs -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum) \
  > "$stage/usr/share/doc/cyberpanel-waf-crs/runtime.sha256"
install -m 0644 "$work/signature.status" "$stage/usr/share/doc/cyberpanel-waf-crs/CRS-signature.status"
export SOURCE_DATE_EPOCH=1787011200
find "$stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
dpkg-deb --root-owner-group --build "$stage" "$package"
sha256sum "$package"
printf 'Complete runtime hashes and signature evidence retained inside the package.\n'
