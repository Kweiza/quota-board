//! Probes the OS keychain backend, and — the part that matters on macOS —
//! whether a **packed** entry of realistic size survives a round trip through
//! the shipping code path.
//!
//! `secrets::packed`'s own tests run against `MemoryStore`, which proves the
//! packing logic and nothing about the platform. The 1 MiB figure in that
//! module was measured by calling Security.framework directly, which is not the
//! path the application takes: `KeychainStore` goes through `keyring`, and a
//! limit imposed by that crate would be invisible to both.
//!
//! Uses a throwaway service name, so it can never touch a real account's
//! tokens, and deletes what it writes.

use quota_core::secrets::keychain::{KeychainStore, ENTRY_LIMIT};
use quota_core::secrets::packed::{PackedStore, PACKED_ENTRY};
use quota_core::secrets::SecretStore;

const SERVICE: &str = "quota-board-probe";

fn main() {
    let store = match KeychainStore::probe(SERVICE) {
        Ok(s) => {
            println!("OK: {}", SecretStore::describe(&s));
            s
        }
        Err(e) => {
            println!("FAILED: {e}");
            return;
        }
    };
    println!("entry limit on this platform: {ENTRY_LIMIT} bytes");

    // The shape nine accounts produce: six Anthropic entries and three Codex
    // accounts of three entries each, with values the size of real JWTs.
    let packed = PackedStore::new(&store);
    let token = "x".repeat(1600);
    let mut written = 0usize;
    for i in 0..6 {
        packed.put(&format!("probe-uuid-{i}:tokens"), token.as_bytes()).expect("anthropic put");
        written += 1;
    }
    for i in 0..3 {
        for part in ["access", "refresh", "meta"] {
            packed
                .put(&format!("probe-openai:user-{i}:tokens:{part}"), token.as_bytes())
                .expect("codex put");
            written += 1;
        }
    }

    let blob = store.get(PACKED_ENTRY).expect("read the packed entry").expect("it should exist");
    println!("{written} logical keys -> 1 keychain entry of {} bytes", blob.len());

    let back = packed.get("probe-openai:user-2:tokens:refresh").expect("read back");
    assert_eq!(back.as_deref(), Some(token.as_bytes()), "a packed value did not survive");
    println!("round trip: OK");

    store.delete(PACKED_ENTRY).expect("clean up");
    println!("cleaned up");
}
