fn main() {
    match quoata_core::secrets::keychain::KeychainStore::probe("quoata-board-probe") {
        Ok(s) => println!("OK: {}", quoata_core::secrets::SecretStore::describe(&s)),
        Err(e) => println!("FAILED: {e}"),
    }
}
