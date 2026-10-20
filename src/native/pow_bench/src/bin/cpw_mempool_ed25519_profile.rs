use ai_native_l1_pow_bench::private_testnet_mempool_candidate::{BoundedMempool, MempoolLimits};
use ai_native_l1_pow_bench::state_machine::{
    AccountId, LedgerState, Transaction, TransactionAuthenticator,
};
use ai_native_l1_pow_bench::transaction_auth::{
    AccountPublicKey, Ed25519TransactionAuthenticator, Ed25519TransactionSigner,
    TransactionAuthenticatorKind,
};
use std::cell::Cell;
use std::time::Instant;

struct CountingEd25519<'a> {
    inner: &'a Ed25519TransactionAuthenticator,
    calls: Cell<usize>,
    cache_enabled: bool,
}

impl TransactionAuthenticator for CountingEd25519<'_> {
    fn verify(
        &self,
        sender: &AccountId,
        signing_digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), ()> {
        self.calls.set(self.calls.get() + 1);
        self.inner.verify(sender, signing_digest, signature)
    }

    fn verification_cache_scope(&self) -> Option<[u8; 32]> {
        if self.cache_enabled {
            self.inner.verification_cache_scope()
        } else {
            None
        }
    }
}

fn profile(count: usize, cache_enabled: bool) {
    let network_id = [0xA1; 32];
    // Disposable profiling-only seed. Never printed and never used for any network.
    let signer = Ed25519TransactionSigner::from_seed([0x5A; 32]);
    let sender = signer.account_id();
    let recipient: AccountId = [0x22; 32];
    assert_ne!(sender, recipient, "profiling accounts must be distinct");

    let auth_config = Ed25519TransactionAuthenticator::select_by_id(
        TransactionAuthenticatorKind::Ed25519V1 as u16,
        [AccountPublicKey {
            account_id: sender,
            public_key: signer.public_key(),
        }],
    )
    .expect("single-account Ed25519 test registry");
    let auth = CountingEd25519 {
        inner: &auth_config,
        calls: Cell::new(0),
        cache_enabled,
    };
    let state = LedgerState::genesis(network_id, vec![(sender, 1_000_000), (recipient, 0)])
        .expect("profile Genesis");
    let mut pool = BoundedMempool::new(MempoolLimits {
        max_transactions: 256,
        max_bytes: 1024 * 1024,
    })
    .expect("bounded pool");

    // Sign fixtures before starting timing: admission timings include real verification,
    // not key generation or client-side transaction signing.
    let mut signed_transactions = Vec::with_capacity(count);
    for nonce in 1..=count {
        let mut tx = Transaction {
            network_id,
            sender,
            recipient,
            nonce: nonce as u64,
            amount: 1,
            fee: 1,
            expires_at: 100_000,
            signature: Vec::new(),
        };
        signer
            .sign_transaction(&mut tx)
            .expect("sign disposable profile transaction");
        signed_transactions.push(tx);
    }

    let start = Instant::now();
    for tx in &signed_transactions {
        pool.submit(tx.clone(), &state, &auth, 1)
            .expect("admit Ed25519-signed profiling fixture");
    }
    let admission = start.elapsed();
    let admission_verify_calls = auth.calls.get();
    assert_eq!(pool.len(), count);

    auth.calls.set(0);
    let reconcile_start = Instant::now();
    let summary = pool.reconcile_after_reorg(&state, &auth, 2, &[], &[]);
    let reconciliation = reconcile_start.elapsed();
    let reconcile_verify_calls = auth.calls.get();
    assert_eq!(pool.len(), count);
    assert_eq!(summary.kept, count);
    assert_eq!(summary.readmitted, 0);
    assert_eq!(summary.dropped_invalid, 0);
    assert_eq!(summary.dropped_expired, 0);
    assert_eq!(summary.skipped_confirmed, 0);

    println!(
        "CP-0083-E ED25519 count={} cache={} pool_bytes={} admission_ms={:.3} admission_verify_calls={} reconcile_ms={:.3} reconcile_verify_calls={} authenticator=ED25519_STRICT disposable_key=true",
        count,
        cache_enabled,
        pool.total_bytes(),
        admission.as_secs_f64() * 1_000.0,
        admission_verify_calls,
        reconciliation.as_secs_f64() * 1_000.0,
        reconcile_verify_calls,
    );
}

fn main() {
    println!(
        "CP-0083-E ED25519_BEGIN max_pool_transactions=256 max_pool_bytes=1048576 mode=release candidate_only=true node_wired=false"
    );
    for count in [32usize, 64, 128, 256] {
        profile(count, false);
        profile(count, true);
    }
    println!(
        "CP-0083-E ED25519_PASS counts=32,64,128,256 cache_modes=off,on transactions_retained=true"
    );
}
