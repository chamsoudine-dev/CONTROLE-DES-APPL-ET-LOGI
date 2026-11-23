#![no_main]
//! Réponses d'API arbitraires (GitHub) : le parsing ne doit jamais paniquer.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
        for kind in ["commit", "branch", "pull_request", "workflow_run", "release"] {
            let _ = cc_connectors::tracker::parse(kind, "o/r", &v);
        }
    }
});
