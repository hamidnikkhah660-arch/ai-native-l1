use ai_native_l1_pow_bench::private_testnet_mempool_candidate::{
    BoundedMempool, MempoolError, MempoolLimits,
};
use ai_native_l1_pow_bench::state_machine::{
    AccountId, LedgerState, StateError, Transaction, TransactionAuthenticator,
};
use ai_native_l1_pow_bench::transaction_auth::{
    AccountPublicKey, Ed25519TransactionAuthenticator, Ed25519TransactionSigner,
    TransactionAuthenticatorKind,
};
use std::cell::Cell;
use std::time::Instant;

const ATTEMPTS: usize = 32;

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
    assert_ne!(sender, recipient);
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
            .expect("sign valid pool fixture");
        pool.submit(tx, &state, &auth, 1)
            .expect("admit valid pool fixture");
    }
    assert_eq!(pool.len(), count);
    let before_bytes = pool.total_bytes();
    let before_ids = pool.ordered_transactions();

    // Sign once, then corrupt one signature bit. The transaction remains canonically encoded
    // and has the next expected nonce, so non-full pools exercise real Ed25519 rejection after
    // prior pending transfers have been previewed. At a full pool, the count quota should reject
    // before performing any new verification.
    let mut bad = Transaction {
        network_id,
        sender,
        recipient,
        nonce: count as u64 + 1,
        amount: 1,
        fee: 1,
        expires_at: 100_000,
        signature: Vec::new(),
    };
    signer
        .sign_transaction(&mut bad)
        .expect("sign invalid fixture before mutation");
    bad.signature[0] ^= 1;

    auth.calls.set(0);
    let started = Instant::now();
    for _ in 0..ATTEMPTS {
        let result = pool.submit(bad.clone(), &state, &auth, 1);
        if count == 256 {
            assert_eq!(result, Err(MempoolError::TransactionLimit));
        } else {
            assert_eq!(result, Err(MempoolError::State(StateError::Unauthorized)));
        }
    }
    let elapsed = started.elapsed();
    let verify_calls = auth.calls.get();
    let expected_calls = if count == 256 {
        0
    } else if cache_enabled {
        ATTEMPTS
    } else {
        ATTEMPTS * (count + 1)
    };
    assert_eq!(verify_calls, expected_calls, "exact verifier-call budget");
    assert_eq!(
        pool.len(),
        count,
        "rejected input must not mutate membership"
    );
    assert_eq!(
        pool.total_bytes(),
        before_bytes,
        "rejected input must not mutate bytes"
    );
    assert_eq!(
        pool.ordered_transactions(),
        before_ids,
        "rejected input must not mutate order"
    );

    println!(
        "CP-0085-G INVALID_INGRESS count={} cache={} attempts={} pool_bytes={} rejection={} elapsed_ms={:.3} verify_calls={} expected_verify_calls={} pool_unchanged=true node_wired=false",
        count,
        cache_enabled,
        ATTEMPTS,
        pool.total_bytes(),
        if count == 256 { "transaction_limit" } else { "invalid_signature" },
        elapsed.as_secs_f64() * 1_000.0,
        verify_calls,
        expected_calls,
    );
}

fn main() {
    println!(
        "CP-0085-G BEGIN mode=release candidate_only=true node_wired=false attempts_per_case={} max_pool_transactions=256 max_pool_bytes=1048576",
        ATTEMPTS,
    );
    for count in [32usize, 64, 128, 256] {
        profile(count, false);
        profile(count, true);
    }
    println!("CP-0085-G PASS counts=32,64,128,256 cache_modes=off,on rejected_inputs_leave_pool_unchanged=true");
}
