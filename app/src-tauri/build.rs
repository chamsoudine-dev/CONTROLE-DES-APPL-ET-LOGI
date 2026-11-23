fn main() {
    // Liste unique des commandes exposées : chacune exige une permission explicite
    // (capabilities/default.json), aucune commande n'est accessible par défaut.
    let list = std::fs::read_to_string("commands.txt").expect("commands.txt");
    let commands: Vec<&'static str> = list
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| &*Box::leak(l.to_owned().into_boxed_str()))
        .collect();
    let commands: &'static [&'static str] = Box::leak(commands.into_boxed_slice());
    println!("cargo:rerun-if-changed=commands.txt");
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(commands)),
    )
    .expect("tauri build");
}
