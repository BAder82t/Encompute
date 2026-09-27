//! Trust Graph bundles: parse, check edges, walk lineage, rebuild from the
//! bundled evidence and report (no anchors).
#![no_main]
use encompute_trust::{ReportOptions, TrustGraph};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(g) = TrustGraph::from_bytes(data) else {
        return;
    };
    let _ = g.check_edges();
    if let Some(id) = g.nodes.keys().next() {
        let _ = g.upstream(id);
        let _ = g.downstream(id);
    }
    let _ = g.rebuild();
    let _ = g.report(&ReportOptions {
        now: Some(1_700_000_000),
        ..ReportOptions::default()
    });
    let _ = g.to_bytes();
});
