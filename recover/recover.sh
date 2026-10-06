#!/bin/sh
# Get your 1Password Secret Key from your hardware key.        Linux and macOS
#
#   curl -fsSL https://lambdasistemi.net/recover/recover.sh | sh
#
# You need: the key (and its PIN) and an internet connection. Nothing is
# installed: two public programs are downloaded, checked against the checksums
# pinned below, run once, and deleted. Your Secret Key is copied to the clipboard.
# Then sign in at https://my.1password.com with your email, the Secret Key
# (paste) and your account password.
set -eu

AGE_V=1.3.2
PLUGIN_V=0.5.0
MIRROR=${RECOVER_MIRROR:-https://recovery.plutimus.com}
RAW=${RECOVER_RAW:-https://raw.githubusercontent.com/paolino/paolino/main}
EMAIL=paolo.veronelli@gmail.com

os=$(uname -s)-$(uname -m)
case "$os" in
  Linux-x86_64)
    t=linux-amd64
    age_sum=cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10
    pl_sum=f837ee7eea5a94c33366b7a78cd143a2a64a1cbae8532b58f16335ca05cccc92 ;;
  Darwin-x86_64)
    t=darwin-amd64
    age_sum=1d1e4bc66e1427edad7739ae7616157de0e79db8b6d2a1497d7d9925fb06a539
    pl_sum=fa7934dd622c62116683cd10760012a894905c7a01db0659d2e3a60ac37679a7 ;;
  Darwin-arm64)
    t=darwin-arm64
    age_sum=e2020b073c44f692685a24d6abc378817eb81ffaaf49fd0531ef8565f767f2f5
    pl_sum=7cde3e1d8418b218146241e7e68b0d5c2fb3b9dcdb0c7622deb6d9f4417a1245 ;;
  *) echo "recover: no build for $os (Windows: use recover.ps1)" >&2; exit 1 ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
say() { printf '%s\n' "$*" >&2; }

sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
get() { # url file sum
  curl -fsSL "$1" -o "$2" || { say "recover: cannot download $1"; exit 1; }
  [ "$(sha "$2")" = "$3" ] || { say "recover: CHECKSUM MISMATCH for $1 - refusing to run it"; exit 1; }
}
# a bundle file: the epyc mirror first, then GitHub
bundle() {
  curl -fsSL --connect-timeout 8 "$MIRROR/$1" -o "$tmp/$1" 2>/dev/null && [ -s "$tmp/$1" ] && return 0
  curl -fsSL --connect-timeout 8 "$RAW/$1" -o "$tmp/$1" 2>/dev/null && [ -s "$tmp/$1" ] && return 0
  say "recover: cannot fetch $1 from the mirror or GitHub"; exit 1
}

say "1/3 downloading and checking the two public programs..."
get "https://github.com/FiloSottile/age/releases/download/v$AGE_V/age-v$AGE_V-$t.tar.gz" "$tmp/age.tgz" "$age_sum"
get "https://github.com/olastor/age-plugin-fido2-hmac/releases/download/v$PLUGIN_V/age-plugin-fido2-hmac-v$PLUGIN_V-$t.tar.gz" "$tmp/plugin.tgz" "$pl_sum"
tar xzf "$tmp/age.tgz" -C "$tmp"; tar xzf "$tmp/plugin.tgz" -C "$tmp"
PATH="$tmp/age:$tmp/age-plugin-fido2-hmac:$PATH"; export PATH

if [ "$(uname -s)" = Linux ] && ldd "$tmp/age-plugin-fido2-hmac/age-plugin-fido2-hmac" 2>/dev/null | grep -q "not found"; then
  say "recover: libfido2 is missing. Debian/Ubuntu: sudo apt install libfido2-1"; exit 1
fi

say "2/3 fetching your public recovery bundle..."
bundle recovery.age; bundle recovery.ids

say "3/3 plug in your key. Enter its PIN when asked, then touch it."
key=$(age -d -i "$tmp/recovery.ids" "$tmp/recovery.age" | grep -oE 'A3-[A-Z0-9]{6}(-[A-Z0-9]{5,6}){5}' | head -1 || true)
[ -n "$key" ] || { say "recover: could not decrypt (wrong PIN, key not touched, or the key is not enrolled)."; say "On Linux without a desktop session you may need: sudo chmod a+rw /dev/hidraw*"; exit 1; }

copy() {
  if [ -n "${WAYLAND_DISPLAY:-}" ] && command -v wl-copy >/dev/null 2>&1; then printf %s "$1" | wl-copy
  elif command -v xclip >/dev/null 2>&1 && [ -n "${DISPLAY:-}" ]; then printf %s "$1" | xclip -selection clipboard
  elif command -v xsel >/dev/null 2>&1 && [ -n "${DISPLAY:-}" ]; then printf %s "$1" | xsel -ib
  elif command -v pbcopy >/dev/null 2>&1; then printf %s "$1" | pbcopy
  else return 1; fi
}
if [ -z "${RECOVER_SHOW:-}" ] && copy "$key"; then
  say ""
  say "Your Secret Key is on the clipboard (it is cleared in 60 seconds)."
  ( sleep 60; copy " " ) >/dev/null 2>&1 &
else
  say ""
  say "No clipboard available here, so it is shown on screen. Anyone looking can read it:"
  say "$key"
fi
say ""
say "Now sign in at https://my.1password.com"
say "  email:      $EMAIL"
say "  Secret Key: paste (Ctrl+V / Cmd+V)"
say "  password:   yours"
