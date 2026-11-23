#!/usr/bin/env python3
"""Régénère app/src-tauri/capabilities/default.json et la liste generate_handler! à partir de
app/src-tauri/commands.txt (source unique des commandes exposées)."""
import json, pathlib, re
root = pathlib.Path(__file__).resolve().parent.parent / "app" / "src-tauri"
cmds = [l.strip() for l in (root / "commands.txt").read_text().splitlines() if l.strip() and not l.startswith("#")]
cap = {
    "$schema": "../gen/schemas/desktop-schema.json",
    "identifier": "default",
    "description": "Capabilities minimales de la fenêtre principale : uniquement les commandes de l'application, aucune API système libre (shell, fs, http).",
    "windows": ["main"],
    "platforms": ["linux", "macOS", "windows", "android", "iOS"],
    "permissions": ["core:event:allow-listen", "core:event:allow-unlisten",
                    "notification:allow-is-permission-granted", "notification:allow-request-permission",
                    "notification:allow-notify"]
                   + ["allow-" + c.replace("_", "-") for c in cmds],
}
(root / "capabilities" / "default.json").write_text(json.dumps(cap, indent=2, ensure_ascii=False) + "\n")
# Liste du handler
lib = (root / "src" / "lib.rs").read_text()
modules = {}
for f in (root / "src").glob("cmd_*.rs"):
    for m in re.finditer(r"#\[tauri::command\]\s*pub (?:async )?fn (\w+)", f.read_text()):
        modules[m.group(1)] = f.stem
missing = [c for c in cmds if c not in modules]
if missing:
    raise SystemExit(f"commandes sans implémentation : {missing}")
handler = ",\n".join(f"            {modules[c]}::{c}" for c in cmds)
lib = re.sub(r"(tauri::generate_handler!\[\n)(.*?)(\n\s*\]\))", lambda m: m.group(1) + handler + "," + m.group(3), lib, flags=re.S)
(root / "src" / "lib.rs").write_text(lib)
print(f"{len(cmds)} commandes")
