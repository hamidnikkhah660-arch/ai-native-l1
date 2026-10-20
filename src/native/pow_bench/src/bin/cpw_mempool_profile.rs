use ai_native_l1_pow_bench::private_testnet_mempool_candidate::{BoundedMempool, MempoolLimits};
use ai_native_l1_pow_bench::state_machine::{
    AccountId, LedgerState, Transaction, TransactionAuthenticator,
};
use std::cell::Cell;
use std::time::Instant;

struct ProfileOnlyAuthenticator {
    verify_calls: Cell<usize>,
}

impl TransactionAuthenticator for ProfileOnlyAuthenticator {
    fn verify(
        &self,
        sender: &AccountId,
        _signing_digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), ()> {
        self.verify_calls.set(self.verify_calls.get() + 1);
        // Intentionally not cryptographic. This benchmark isolates pool/ledger overhead.
        if signature == [sender[0]] {
            Ok(())
        } else {
            Err(())
        }
    }
}

fn profile(count: usize) {
    let network_id = [0xA1; 32];
    let sender = [1; 32];
    let recipient = [2; 32];
    let state = LedgerState::genesis(network_id, vec![(sender, 1_000_000), (recipient, 0)])
        .expect("profile Genesis");
    let auth = ProfileOnlyAuthenticator {
        verify_calls: Cell::new(0),
    };
    let mut pool = BoundedMempool::new(MempoolLimits {
        max_transactions: 256,
        max_bytes: 1024 * 1024,
    })
    .expect("bounded pool");

    let start = Instant::now();
    for nonce in 1..=count {
        let tx = Transaction {
            network_id,
            sender,
            recipient,
            nonce: nonce as u64,
            amount: 1,
            fee: 1,
            expires_at: 100_000,
            signature: vec![sender[0]],
        };
        pool.submit(tx, &state, &auth, 1)
            .expect("admit profiling fixture");
    }
    let admission = start.elapsed();
    let admission_verify_calls = auth.verify_calls.get();
    assert_eq!(pool.len(), count);

    auth.verify_calls.set(0);
    let reconcile_start = Instant::now();
    let summary = pool.reconcile_after_reorg(&state, &auth, 2, &[], &[]);
    let reconcile = reconcile_start.elapsed();
    let reconcile_verify_calls = auth.verify_calls.get();
    assert_eq!(pool.len(), count);
    assert_eq!(summary.kept, count);
    assert_eq!(summary.readmitted, 0);
    assert_eq!(summary.dropped_invalid, 0);
    assert_eq!(summary.dropped_expired, 0);
    assert_eq!(summary.skipped_confirmed, 0);

    println!(
        "CP-0082-D PROFILE count={} pool_bytes={} admission_ms={:.3} admission_us_per_tx={:.2} admission_verify_calls={} reconcile_ms={:.3} reconcile_us_per_tx={:.2} reconcile_verify_calls={} auth=NONCRYPTOGRAPHIC_FIXTURE",
        count,
        pool.total_bytes(),
        admission.as_secs_f64() * 1_000.0,
        admission.as_secs_f64() * 1_000_000.0 / count as f64,
        admission_verify_calls,
        reconcile.as_secs_f64() * 1_000.0,
        reconcile.as_secs_f64() * 1_000_000.0 / count as f64,
        reconcile_verify_calls,
    );
}

fn main() {
    println!(
        "CP-0082-D BEGIN max_pool_transactions=256 max_pool_bytes=1048576 mode=release candidate_only=true node_wired=false"
    );
    for count in [32usize, 64, 128, 256] {
        profile(count);
    }
    println!("CP-0082-D PASS counts=32,64,128,256 transactions_retained=true");
}
