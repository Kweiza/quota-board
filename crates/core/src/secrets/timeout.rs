//! A watchdog around a blocking [`SecretStore`]. docs/design.md §9.2.
//!
//! **Every `SecretStore` method is synchronous, and the keychain backend is an
//! FFI call into Security.framework that can block without bound.** When
//! `securityd` needs a SecurityAgent approval prompt — the item was written by a
//! different binary, or the screen is locked, or the app was launched as a login
//! item before any session exists — the call does not fail and does not return.
//! It waits for an answer that may never come.
//!
//! Measured on macOS 15.6 during Task 17, from a process sample: the app sat in
//!
//! ```text
//!   ensure_fresh -> load -> KeychainStore::get -> keyring_core::Entry::get_secret
//!     -> SecKeychainFindGenericPassword -> ClientSession::decrypt -> mach_msg
//! ```
//!
//! forever, with the screen locked. That call is made from the task that drives
//! the polling loop, so the whole loop stopped: no account was ever polled
//! again, `poll_permit` was never released, and every manual refresh answered
//! with an unchanged state. The same call also runs inside `setup()` before the
//! widget window is shown, where it prevents the window from appearing at all.
//!
//! **`tokio::time::timeout` cannot fix this**, and reaching for it is the
//! obvious mistake: the blocking call never yields, so the timeout future is
//! never polled. The bound has to be imposed on a different thread from the one
//! that waits, which is what this type does.
//!
//! Failing to [`SecretError::Locked`] is deliberate rather than convenient: §9.2
//! makes `LOCKED` first-class, `FailureKind::from_stored_token_error` maps it to
//! `SecretsLocked`, and §7.1 gives that state the "unlock" affordance — which is
//! the correct thing to offer a user whose credential store is not answering.

use super::{SecretError, SecretStore};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::Duration;

/// How long any single store operation may take before it is abandoned.
///
/// A healthy keychain answers in single-digit milliseconds, so this is not a
/// performance budget — it is the point at which "slow" is reclassified as "not
/// coming back". Ten seconds is long enough that a machine under heavy load is
/// never mistaken for a hung one, and short enough that it is tolerable in
/// `setup()`, where the widget window cannot appear until the probe returns.
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;

type Job = Box<dyn FnOnce(&dyn SecretStore) + Send + 'static>;

/// Runs a blocking [`SecretStore`] on its own thread and bounds every call.
///
/// One worker thread, not one per call. When the backend wedges, that single
/// thread is stranded in the FFI call and **no further threads are spawned**:
/// `stuck` short-circuits later calls so a hung store costs one leaked thread
/// for the life of the process rather than one per poll. If the backend ever
/// does answer, the worker clears the flag and normal service resumes.
pub struct TimeoutStore {
    tx: Sender<Job>,
    timeout: Duration,
    stuck: Arc<AtomicBool>,
    description: String,
}

impl TimeoutStore {
    /// Opens a store on the worker thread and bounds the open too.
    ///
    /// The probe is bounded for the same reason the reads are: `KeychainStore::probe`
    /// writes, reads and deletes a canary item, so it can block exactly like any
    /// other keychain call — and it runs in `setup()`, ahead of `widget.show()`.
    pub fn spawn<F>(timeout: Duration, open: F) -> Result<Self, SecretError>
    where
        F: FnOnce() -> Result<Box<dyn SecretStore>, SecretError> + Send + 'static,
    {
        let (job_tx, job_rx) = channel::<Job>();
        let (open_tx, open_rx) = channel::<Result<String, SecretError>>();
        let stuck = Arc::new(AtomicBool::new(false));
        let worker_stuck = Arc::clone(&stuck);

        std::thread::Builder::new()
            .name("quota-secret-store".into())
            .spawn(move || {
                let store = match open() {
                    Ok(s) => {
                        // A failed send means the caller already timed out and
                        // gave up on this thread. Stop rather than serve a store
                        // nobody is holding.
                        if open_tx.send(Ok(s.describe())).is_err() {
                            return;
                        }
                        s
                    }
                    Err(e) => {
                        let _ = open_tx.send(Err(e));
                        return;
                    }
                };
                // Ends when the `TimeoutStore` is dropped and `tx` closes.
                while let Ok(job) = job_rx.recv() {
                    job(store.as_ref());
                    // The backend answered, so whatever made a previous call
                    // time out has cleared.
                    worker_stuck.store(false, Ordering::Relaxed);
                }
            })
            .map_err(|e| SecretError::Backend(format!("could not start the store thread: {e}")))?;

        let description = match open_rx.recv_timeout(timeout) {
            Ok(Ok(d)) => d,
            Ok(Err(e)) => return Err(e),
            Err(RecvTimeoutError::Timeout) => {
                return Err(SecretError::Locked(format!(
                    "the credential store did not open within {}s",
                    timeout.as_secs()
                )))
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(SecretError::Backend("the store thread stopped".into()))
            }
        };

        Ok(Self { tx: job_tx, timeout, stuck, description })
    }

    fn run<T, F>(&self, what: &str, f: F) -> Result<T, SecretError>
    where
        F: FnOnce(&dyn SecretStore) -> Result<T, SecretError> + Send + 'static,
        T: Send + 'static,
    {
        if self.stuck.load(Ordering::Relaxed) {
            // Fail immediately rather than spend the timeout again on every
            // call. Without this, a wedged keychain costs `timeout` per poll
            // forever and the widget's every action is that much slower.
            return Err(SecretError::Locked(format!(
                "the credential store is not responding ({what})"
            )));
        }
        let (rtx, rrx) = channel();
        let job: Job = Box::new(move |s| {
            let _ = rtx.send(f(s));
        });
        if self.tx.send(job).is_err() {
            return Err(SecretError::Backend("the store thread stopped".into()));
        }
        match rrx.recv_timeout(self.timeout) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => {
                self.stuck.store(true, Ordering::Relaxed);
                Err(SecretError::Locked(format!(
                    "the credential store did not answer within {}s ({what})",
                    self.timeout.as_secs()
                )))
            }
            Err(RecvTimeoutError::Disconnected) => {
                Err(SecretError::Backend("the store thread stopped".into()))
            }
        }
    }
}

impl SecretStore for TimeoutStore {
    fn put(&self, key: &str, value: &[u8]) -> Result<(), SecretError> {
        let (k, v) = (key.to_string(), value.to_vec());
        self.run("put", move |s| s.put(&k, &v))
    }
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecretError> {
        let k = key.to_string();
        self.run("get", move |s| s.get(&k))
    }
    fn delete(&self, key: &str) -> Result<bool, SecretError> {
        let k = key.to_string();
        self.run("delete", move |s| s.delete(&k))
    }
    /// Answered from a string captured when the store opened. Routing this
    /// through the worker would make a purely descriptive call block.
    fn describe(&self) -> String {
        self.description.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::MemoryStore;
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

    /// Blocks for `nap` on every read, the way a keychain waiting on an
    /// unanswerable SecurityAgent prompt does. **Finite, not infinite**: an
    /// infinite sleep would make the back-test of these tests hang instead of
    /// fail, and a test that hangs proves nothing.
    struct SleepingStore {
        nap: Duration,
        gets: AtomicUsize,
    }

    impl SleepingStore {
        fn new(nap: Duration) -> Self {
            Self { nap, gets: AtomicUsize::new(0) }
        }
    }

    impl SecretStore for SleepingStore {
        fn put(&self, _k: &str, _v: &[u8]) -> Result<(), SecretError> {
            std::thread::sleep(self.nap);
            Ok(())
        }
        fn get(&self, _k: &str) -> Result<Option<Vec<u8>>, SecretError> {
            self.gets.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(self.nap);
            Ok(Some(b"never observed".to_vec()))
        }
        fn delete(&self, _k: &str) -> Result<bool, SecretError> {
            std::thread::sleep(self.nap);
            Ok(true)
        }
        fn describe(&self) -> String {
            "sleeping (test only)".to_string()
        }
    }

    fn bounded(nap_ms: u64, timeout_ms: u64) -> TimeoutStore {
        TimeoutStore::spawn(Duration::from_millis(timeout_ms), move || {
            Ok(Box::new(SleepingStore::new(Duration::from_millis(nap_ms))) as Box<dyn SecretStore>)
        })
        .expect("the store opens promptly")
    }

    /// The whole point. A store that does not answer must not hold the caller.
    #[test]
    fn a_store_that_never_answers_does_not_block_the_caller_forever() {
        // 20 seconds stands in for "indefinitely"; the bound is 200ms.
        let store = bounded(20_000, 200);
        let started = Instant::now();
        let err = store.get("k").unwrap_err();
        let waited = started.elapsed();

        assert!(
            waited < Duration::from_secs(5),
            "the caller waited {waited:?} — the blocking call was not bounded"
        );
        assert!(
            matches!(err, SecretError::Locked(_)),
            "a store that will not answer must read as LOCKED, so §7.1 can offer the unlock \
             affordance; got {err:?}"
        );
    }

    /// After the first timeout, later calls must not each pay the timeout
    /// again — otherwise a wedged keychain taxes every poll for the life of the
    /// process.
    #[test]
    fn a_wedged_store_fails_fast_on_every_later_call() {
        let store = bounded(20_000, 200);
        store.get("first").unwrap_err();

        let started = Instant::now();
        let err = store.get("second").unwrap_err();
        let waited = started.elapsed();

        assert!(
            waited < Duration::from_millis(150),
            "the second call waited {waited:?}; it must short-circuit, not re-pay the timeout"
        );
        assert!(matches!(err, SecretError::Locked(_)), "got {err:?}");
    }

    /// One stranded thread, not one per call, **and later calls do not queue
    /// behind the stranded one.**
    ///
    /// The elapsed assertion is the half that can fail. The counter alone
    /// cannot: with the short-circuit removed, calls 2..n simply sit in the
    /// worker's channel behind the wedged job and never reach the backend, so
    /// the count stays 1 for a reason that has nothing to do with the property
    /// this test is named for. Measured during the fix-round back-test — the
    /// mutation survived a counter-only version. What actually distinguishes
    /// the two designs is that a queued call waits and a short-circuited one
    /// does not.
    #[test]
    fn a_wedged_store_is_not_re_entered_once_it_has_timed_out() {
        let started = Instant::now();
        let counter = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&counter);
        struct Counting(Arc<AtomicUsize>);
        impl SecretStore for Counting {
            fn put(&self, _k: &str, _v: &[u8]) -> Result<(), SecretError> {
                Ok(())
            }
            fn get(&self, _k: &str) -> Result<Option<Vec<u8>>, SecretError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_secs(20));
                Ok(None)
            }
            fn delete(&self, _k: &str) -> Result<bool, SecretError> {
                Ok(true)
            }
            fn describe(&self) -> String {
                "counting (test only)".into()
            }
        }
        let store =
            TimeoutStore::spawn(Duration::from_millis(200), move || Ok(Box::new(Counting(seen)) as Box<dyn SecretStore>))
                .unwrap();

        for _ in 0..5 {
            store.get("k").unwrap_err();
        }
        let waited = started.elapsed();

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "the wedged backend was entered more than once — every call is stranding a thread"
        );
        // One timeout is paid, then nothing. Five queued calls would be five.
        assert!(
            waited < Duration::from_millis(500),
            "five calls against a wedged store took {waited:?} — they are queueing behind it \
             instead of failing fast"
        );
    }

    /// The bound must be invisible when the backend behaves: this wrapper sits
    /// on the only credential path in the application, so a passthrough defect
    /// would break every account rather than degrade one.
    #[test]
    fn a_healthy_store_round_trips_unchanged_through_the_wrapper() {
        let store = TimeoutStore::spawn(Duration::from_secs(5), || {
            Ok(Box::new(MemoryStore::default()) as Box<dyn SecretStore>)
        })
        .unwrap();

        assert_eq!(store.get("absent").unwrap(), None, "an absent key must still yield None");
        store.put("k1", b"hello").unwrap();
        assert_eq!(store.get("k1").unwrap().as_deref(), Some(&b"hello"[..]));
        store.put("k1", b"replaced").unwrap();
        assert_eq!(store.get("k1").unwrap().as_deref(), Some(&b"replaced"[..]));
        assert!(store.delete("k1").unwrap());
        assert_eq!(store.get("k1").unwrap(), None);
        assert!(!store.delete("k1").unwrap(), "deleting an absent key is false, not an error");
        assert_eq!(store.describe(), "memory (test only)", "describe must pass through");
    }

    /// §9.2's probe runs inside `setup()` ahead of `widget.show()`, so an
    /// unbounded open means the window never appears.
    #[test]
    fn an_open_that_never_answers_does_not_block_startup() {
        let started = Instant::now();
        // Matched rather than `expect_err`, which would force a `Debug` impl on
        // a type whose whole job is to front a credential store. Nothing here
        // needs one.
        let opened = TimeoutStore::spawn(Duration::from_millis(200), || {
            std::thread::sleep(Duration::from_secs(20));
            Ok(Box::new(MemoryStore::default()) as Box<dyn SecretStore>)
        });
        let waited = started.elapsed();
        let Err(err) = opened else {
            panic!("an open that never answers must not succeed");
        };

        assert!(
            waited < Duration::from_secs(5),
            "startup waited {waited:?} on the store probe — the widget window cannot appear"
        );
        assert!(matches!(err, SecretError::Locked(_)), "got {err:?}");
    }

    /// A store that fails to open reports its own error, not the timeout's.
    /// `NoBackend` is what tells the caller to use the fallback store (§9.2), so
    /// flattening it into `Locked` would hide the one case that has a remedy.
    #[test]
    fn an_open_that_fails_reports_its_own_error() {
        let opened = TimeoutStore::spawn(Duration::from_secs(5), || {
            Err(SecretError::NoBackend("no store registered".into()))
        });
        let Err(err) = opened else { panic!("the open should have failed") };
        assert!(
            matches!(err, SecretError::NoBackend(_)),
            "the real cause must survive the wrapper; got {err:?}"
        );
    }
}
