fn main() {
    match quota_core::secrets::keychain::KeychainStore::probe("quota-board-probe") {
        Ok(s) => println!("OK: {}", quota_core::secrets::SecretStore::describe(&s)),
        Err(e) => println!("FAILED: {e}"),
    }
}
