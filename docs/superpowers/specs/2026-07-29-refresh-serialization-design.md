# Refresh serialization and refresh-token compare-and-swap

Design for the requirement in `docs/design.md` §10.5 that no task in the
implementation plan owns.

## 1. The requirement

`docs/design.md` §10.5 (lines 647-650) is normative:

> **Concurrency**: serialize refreshes per account. Even in a single process, a
> scheduler poll and a user's manual refresh can overlap. Take a lock, and
> compare-and-swap against the stored refresh token before writing (if the value
> changed underneath us, adopt the new value rather than overwriting it).

`docs/design.md` §14 (line 866) files the test for it under the `auth` target:
"...one-strike `invalid_grant` quarantine, **and serialized concurrent refresh**".

Neither sentence appears anywhere in the 22-task implementation plan.

## 2. Why it has no home today

`auth::token::refresh` (`crates/core/src/auth/token.rs:276`) is a pure network
call: it takes a `&TokenSet`, returns a new one, and never touches a store.
Persisting is the caller's job, and **no caller exists**. Nothing in the
codebase owns the read → refresh → write sequence, so there is nothing to
attach a lock to.

`docs/design.md:117` already declares the dependency edge this component needs —
`| auth | PKCE OAuth flow, token refresh and revocation | secrets, HTTP |` — and
nothing under `crates/core/src/auth/` imports `crate::secrets` yet. That unused
edge is exactly this component.

Neither candidate task can host it:

- **Task 11 (`scheduler`) cannot.** The task exists to be a pure, clock-injected
  state machine ("separate the policy into a pure state machine and leave the
  async loop as a thin driver"); its declared input is `UsageWindow` alone. It
  holds no store and no HTTP client, and giving it a lock to hold across a
  30-second network await destroys the property the task exists for.
- **Task 17 (core wiring) cannot.** The plan states that `src-tauri` handles
  wiring only and holds no logic. Task 17's only automated gate is
  `cargo test -p quoata-core scheduler`; the rest is a manual `npm run tauri dev`
  on a desktop machine. The most concurrency-sensitive code in the project would
  ship with no automated coverage, in the one crate that cannot be built
  headlessly.

Meanwhile the plan ships the defect: the wiring's `poll_one` performs an
unlocked get → `needs_refresh` → `refresh` → `put`, reachable concurrently from
the polling ticker and from the `refresh_account` command. The plan's own
comment — that the scheduler handing back at most one account upholds a global
concurrency of 1 — is true of the ticker and false of `refresh_account`, which
never consults `due()`.

## 3. Decision

A new module, `crates/core/src/auth/stored.rs`, owns the stored token: its key
structure, its serialization, its expiry judgement, and the order in which
refreshes happen. It is scheduled as **Task 10b**, between Tasks 10 and 11, so
no task numbers move.

Task 11 additionally grows a per-account in-flight gate. The lock and the gate
are complementary, not alternatives: the lock orders writers, and the gate is
what lets a caller decline to wait.

`SecretStore` (`crates/core/src/secrets/mod.rs:23`) is not changed. The
compare-and-swap is a read-compare-write performed above the trait while the
per-account lock is held, which is what §10.5 describes.

## 4. Component: `auth::stored`

### 4.1 API

```rust
/// One async mutex per account. Entries are created on first use and never
/// evicted — the map is bounded by the account count, so eviction would be
/// more machinery than it saves.
#[derive(Default)]
pub struct RefreshLocks { /* Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>> */ }

impl RefreshLocks {
    fn for_uuid(&self, uuid: &str) -> Arc<tokio::sync::Mutex<()>>;

    /// Whether a refresh is in flight for this account. Lets a caller answer
    /// "refresh in progress" (§7.1 `AUTH_EXPIRED`) without blocking on the lock.
    pub fn is_refreshing(&self, uuid: &str) -> bool;
}

pub struct Fresh {
    pub tokens: TokenSet,
    /// False when the rotation succeeded over HTTP but the store write did not.
    /// The tokens are live and usable for this cycle; only the next process
    /// start will fail to see them.
    pub persisted: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum StoredTokenError {
    Missing,
    Corrupt,
    Secrets(#[from] SecretError),
    Auth(#[from] AuthError),
}

pub fn token_key(uuid: &str) -> String;

pub async fn ensure_fresh<H: TokenHttp>(
    http: &H,
    cfg: &AuthConfig,
    store: &dyn SecretStore,
    locks: &RefreshLocks,
    uuid: &str,
) -> Result<Fresh, StoredTokenError>;
```

`ensure_fresh` takes a **uuid, never a pre-loaded `TokenSet`**. Re-reading the
store inside the lock is the whole of its correctness; passing the already-loaded
value in as a parameter — an obvious-looking optimization, since the caller has
usually just read it — reopens the race completely. This constraint belongs in a
doc comment on the function, not in this document alone.

`H: TokenHttp` is a function-level generic. `TokenHttp`
(`crates/core/src/auth/token.rs:103`) has generic methods *and* uses RPITIT, so
it is not dyn-compatible for two independent reasons and `Box<dyn TokenHttp>`
will not compile. `SecretStore` has four non-generic `&self` methods and is
dyn-compatible, so it is taken as `&dyn SecretStore`.

`token_key` lives here because this module is the only writer of token keys. The
plan currently re-derives that format at four independent sites; all four
collapse onto this function.

### 4.2 Algorithm

```text
let guard = locks.for_uuid(uuid);
let _held = guard.lock().await;              // serialize per account

for _ in 0..2 {
    let current = load(store, uuid)?;         // MUST be read inside the lock
    if !current.needs_refresh() {
        return Ok(Fresh { tokens: current, persisted: true });
    }

    let witness = current.refresh_token.clone();
    let new = refresh(http, cfg, &current).await?;

    match load(store, uuid) {
        Ok(stored) if stored.refresh_token != witness => continue,
        Ok(_)                     => {}
        Err(Missing)              => return Err(Missing),
        Err(e)                    => return Err(e),
    }

    return match save(store, uuid, &new) {
        Ok(())   => Ok(Fresh { tokens: new, persisted: true }),
        Err(_)   => Ok(Fresh { tokens: new, persisted: false }),
    };
}
return Ok(Fresh { tokens: load(store, uuid)?, persisted: true });
```

Four properties, each of which was a defect in an earlier draft of this design:

**The double check.** The second caller through the lock re-reads, finds the
token the winner just stored, and returns it without a second network call. This
only works because the load is inside the lock (see §4.1).

**`continue` is what "adopt rather than overwrite" means.** When the stored
refresh token no longer matches the witness, someone stored a different chain
underneath us — realistically a re-login landing mid-refresh. We discard the
token we just obtained, re-enter, and read theirs. If theirs is fresh, the
`needs_refresh` check returns it immediately. The loop is capped at two
iterations, so there is no recursion and no unbounded retry; after two, whatever
is in the store is returned and the next poll cycle re-evaluates.

**No catch-all write.** Matching the re-read with `_ => {}` and falling through
to an unconditional write is wrong in two distinct ways. `Err(Missing)` is what
the re-read returns when the settings window's `remove_account` deleted the key
while we were on the network — and `remove_account` has already called `revoke`
on that refresh token (§10.6). Writing then **resurrects a revoked credential for
an account that no longer exists**, with no UI path left to delete it.
`Err(Locked)` (a keychain that locked mid-refresh — §9.2 makes `LOCKED` a
first-class state) means the comparison could not be performed at all; a
compare-and-swap that could not compare must not swap. On the `Missing` path the
freshly rotated token is dropped rather than stored, which is correct: it belongs
to an account the user has just deleted.

**A failed store write does not discard a live token.** After a successful
rotation the server has moved to the new refresh token and the old one is dead.
Returning `Err` there would throw away the only live credential, leave the dead
one on disk, and waste the cycle. `persisted: false` reports the durability
failure while keeping the token usable.

### 4.3 Blocking behaviour

`SecretStore` is synchronous, and its calls run while the async mutex is held.
On the encrypted-file backend `put` takes an unbounded blocking `flock(LOCK_EX)`
and an `fsync`. `tokio`'s `rt` feature is not enabled in `crates/core`, so
`spawn_blocking` is not available and cannot be used to move this off the
runtime thread. For a widget polling a handful of accounts against a 180-second
floor this is acceptable — but it is a decision, not an accident, and belongs in
a comment.

Note a trap for reviewers: `crates/core`'s dev-dependencies enable
`rt-multi-thread`, so an accidental `tokio::spawn_blocking` compiles under both
`cargo test -p quoata-core` and `cargo clippy --all-targets` and fails only under
a plain `cargo build`. Neither project gate catches it.

## 5. Scheduler gate (added to Task 11)

`Entry` gains `in_flight_since: Option<Instant>`, and the scheduler gains
`begin_poll(uuid) -> bool` and `end_poll(uuid)`. `due()` skips accounts already
in flight.

This is what actually establishes §6.1's **"Global concurrency of 1"**, which
the plan currently violates: `refresh_account` calls the wiring's `poll_one`
directly, bypassing `due()` and its `.take(1)`.

The field is an `Option<Instant>` rather than a `bool` because a panic or an
early return that skips `end_poll` would otherwise freeze that account forever.
`due()` reclaims an entry that has been in flight longer than
`IN_FLIGHT_RECLAIM`, a Task 11 constant set to **90 seconds**: comfortably above
the worst legitimate case (a 30-second refresh followed by a 30-second usage
fetch) and comfortably below the 180-second polling floor, so a reclaim can never
race the next scheduled poll for the same account. The judgement is made against
the injected clock, so Task 11 stays a pure state machine and the reclaim path is
itself testable.

The wiring then calls `begin_poll` first and returns immediately when it is
false. When `RefreshLocks::is_refreshing(uuid)` is true, the state returned is
§7.1's `AUTH_EXPIRED` — "Access token expired, refresh in progress", displayed as
loading. Without this, a user's manual refresh blocks on the mutex for up to the
30-second refresh timeout with no signal to the webview, and §7.1 defines a state
that nothing in the product would ever produce.

## 6. Error mapping (Task 17)

| `StoredTokenError` | §7.1 state | Why |
|---|---|---|
| `Missing`, `Corrupt` | `AUTH_DEAD` | §9.2 line 479: "`NOT_FOUND` → treat that account as `AUTH_DEAD` (re-login required)". Routing these to `AUTH_EXPIRED` renders a permanent spinner instead of a clickable re-login |
| `Secrets(Locked)` | `SECRETS_LOCKED` | §9.2 line 477 |
| `Auth(e)` where `e.is_dead_grant()` | `AUTH_DEAD` | §10.5 one-strike quarantine |
| other `Auth(_)` | `STALE` / `NETWORK` | §7.1 |
| `Ok(Fresh { persisted: false, .. })` | no state change, warn | the token is live; only durability failed |

No `StoredTokenError` variant carries a credential. `AuthError::Decode`
deliberately omits the response body, and `SecretError::Backend` is scrubbed on
the one path that could carry a secret. Any type added here that holds a live
credential hand-writes `Debug` in the shape of `TokenSet`
(`crates/core/src/auth/token.rs:69-87`) — printing `"<redacted>"` — rather than
deriving it.

## 7. Testing

All tests live in `crates/core/src/auth/stored.rs` and run under
`cargo test -p quoata-core`: headless, no network, no real limits consumed.

The rig is **wiremock**, matching §14's stated method for the `auth` row ("A
local mock OAuth server") and the fourteen existing async auth tests. No
hand-rolled `TokenHttp` mock is needed: wiremock's closure responders can mutate
the store mid-request (the pattern already used in `token.rs`), and
`ResponseTemplate::set_delay` supplies the await point the interleaving tests
require.

| # | Test | Back-test |
|---|---|---|
| 1 | Serialization: two `ensure_fresh` calls on one uuid under `tokio::join!`, mock delayed → exactly **one** POST | delete the `guard.lock().await` line → two POSTs |
| 2 | CAS adopts: responder writes a foreign `TokenSet` (different refresh token) into the store before responding → the call returns the foreign set and the store still holds it | remove the witness comparison → the store holds ours |
| 3 | CAS does not resurrect: responder deletes the key → `Err(Missing)` and the key is still absent | replace the arms with `_ => {}` → the key reappears |
| 4 | No-op path: a fresh token → zero POSTs and zero writes | — |
| 5 | Write failure after a successful rotation → `persisted: false`, tokens are the new ones | — |
| 6 | No leakage: `{:?}` and `to_string()` of every variant contain no sentinel token | — |

Test 1 asserts a **POST count**, not non-overlapping timestamps, and the mock
must yield unconditionally. Two rigs that look plausible do not work: a
`Barrier(2)` deadlocks precisely when the lock is working, because the second
caller never reaches it; and an interval-overlap assertion on a non-yielding mock
passes with the lock deleted, since `tokio::join!` on the default current-thread
runtime runs the first future to completion before polling the second. That
second rig is the "test that cannot fail" this repository forbids, and it would
have been the one test §14 names by name.

## 8. Known limits

These go in the module's doc comment, in the manner in which
`crates/core/src/secrets/encrypted_file.rs` already documents its Windows flock
gap. They are accepted, not oversights.

- **Cross-process, the CAS is largely inert.** Under §10.7's single-use rotating
  chain premise, the loser's refresh already fails with `invalid_grant` before
  the re-read runs, and §10.5 scopes itself to the single-process case. The
  compare-and-swap's real job is the re-login-lands-mid-refresh case, which is
  in-process.
- **In-process the CAS is correct on both backends**, including the encrypted
  file store, whose `put` updates the cached map that `get` serves.
- **Cross-process on the encrypted file backend the re-read is blind**, because
  `get` serves that cached map rather than re-reading disk. A trait-level
  `compare_and_swap` *would* be genuinely atomic there — `put` already flocks and
  re-reads from disk inside the critical section — but not on the keychain, which
  exposes no such primitive and is the primary backend. A single uniform
  above-the-trait implementation was chosen over two divergent ones.
- **A crash between the HTTP 200 and the store write loses the rotation
  permanently**, and the next launch sees `invalid_grant`. Neither the lock nor
  the compare-and-swap addresses this.
- Nothing structurally prevents a future caller from calling
  `auth::token::refresh` directly and bypassing the lock. The compare-and-swap
  narrows, but does not close, the resulting window.

## 9. Plan edits required

- Insert **Task 10b** after Task 10: new file `crates/core/src/auth/stored.rs`,
  exported from `crates/core/src/auth/mod.rs`, with the six tests above.
- **Task 11**: add `in_flight_since` to `Entry`, the `due()` filter and its
  reclaim rule, `begin_poll`/`end_poll`, and their tests; update the task's
  verification count.
- **Task 17**: replace the inline refresh block with one `ensure_fresh` call,
  add `RefreshLocks` to the application state, drop the local `token_key`, wrap
  `poll_one` in `begin_poll`/`end_poll`, apply §6's error mapping, and correct
  the concurrency comment to say that the ticker upholds concurrency of 1 while
  `refresh_account` does not.
- **Task 12**: replace the CLI's two inline refresh blocks with `ensure_fresh`.
  The CLI is a single-shot Phase 1 binary, so it gains code reuse and the
  compare-and-swap, not serialization.
- **Task 18**: use `stored::token_key` in the login and account-deletion paths.
- **Task 10**: correct the stale note that Task 11 calls `refresh`; Task 10b is
  the sole caller.

Task 10b lands before Task 11. An earlier version of this design sequenced it
before Task 12 on the grounds that the CLI was the first consumer; that is wrong,
because the CLI is a Phase 1 smoke binary that never runs concurrently with the
Phase 2 application it was said to be protected from.

## 10. Out of scope — reported, not fixed

`Account.quarantined` (`crates/core/src/accounts.rs:23`) is written only by a
test fixture. The plan maps `invalid_grant` to an in-memory failure state and
never persists the flag, so **the one-strike quarantine does not survive a
restart**. Task 11 owns the quarantine state transition, which makes it the
natural home, but no step in the plan performs the write. This needs an owner
before release.
