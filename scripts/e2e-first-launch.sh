#!/usr/bin/env bash
# Test de bout en bout du premier lancement (Linux, Xvfb + xdotool) :
# lance l'application réelle, remplit l'étape « Profil », vérifie que le coffre est créé
# et que la base est chiffrée (ni en-tête SQLite ni texte en clair).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
(cd app && npm run build >/dev/null)
cargo build -p control-center --features tauri/custom-protocol >/dev/null
HOME_DIR=$(mktemp -d)
cat > "$HOME_DIR/run.sh" <<'INNER'
"$BIN" &
sleep 10
t() { xdotool mousemove "$1" "$2" click 1; sleep 1.5; xdotool type --delay 90 "$3"; sleep 1; }
t 640 293 "E2E User"
t 640 377 "correct horse battery staple"
t 640 537 "correct horse battery staple"
xdotool mousemove 427 665 click 1
sleep 10
import -window root "$SHOT" || true
kill %1
INNER
BIN="$ROOT/target/debug/control-center" SHOT="$HOME_DIR/after-setup.png" HOME="$HOME_DIR" \
  XDG_DATA_HOME="$HOME_DIR/data" timeout 90 xvfb-run -a -s "-screen 0 1280x820x24" bash "$HOME_DIR/run.sh" >/dev/null 2>&1 || true
DB="$HOME_DIR/data/dev.chamsoudine.controlcenter/control-center.db"
test -f "$HOME_DIR/data/dev.chamsoudine.controlcenter/vault.json" || { echo "ÉCHEC : vault.json absent"; exit 1; }
test -f "$DB" || { echo "ÉCHEC : base absente"; exit 1; }
python3 - "$DB" <<'PY'
import sys
d = open(sys.argv[1], "rb").read()
assert not d.startswith(b"SQLite format 3"), "base non chiffrée"
for needle in (b"E2E User", b"CREATE TABLE", b"correct horse"):
    assert needle not in d, needle
print("OK : coffre créé, base chiffrée, aucun texte en clair")
PY
