//! Research chain-view recovery model under transport faults.
//! Research-only: not a production network or consensus implementation.

use crate::chain_view::{client_a_best, ChainView, Header};
use crate::transport::{FaultConfig, FaultInjector};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAdvertisement {
    pub peer_id: u64,
    pub tip: u64,
    pub headers: Vec<Header>,
}

pub fn reconcile(advertisements: &[PeerAdvertisement]) -> Option<ChainView> {
    let mut headers = Vec::new();
    let mut tips = Vec::new();

    for advertisement in advertisements {
        tips.push(advertisement.tip);
        headers.extend(advertisement.headers.clone());
    }

    client_a_best(&headers, &tips)
}

pub fn deliver(
    advertisements: &[PeerAdvertisement],
    cfg: FaultConfig,
    seed: u64,
) -> Vec<PeerAdvertisement> {
    let mut injector = FaultInjector::new(cfg, seed);
    let sequences: Vec<u64> = (0..advertisements.len() as u64).collect();
    let scheduled = injector.inject_batch(&sequences, 0);

    scheduled
        .into_iter()
        .filter_map(|message| advertisements.get(message.sequence as usize).cloned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_view::Header;

    fn honest_advertisement() -> PeerAdvertisement {
        let headers = vec![
            Header {
                id: 0,
                prev: None,
                work: 1,
                claimed_valid: true,
            },
            Header {
                id: 1,
                prev: Some(0),
                work: 5,
                claimed_valid: true,
            },
            Header {
                id: 2,
                prev: Some(1),
                work: 5,
                claimed_valid: true,
            },
        ];

        PeerAdvertisement {
            peer_id: 1,
            tip: 2,
            headers,
        }
    }

    fn invalid_attacker_advertisement() -> PeerAdvertisement {
        PeerAdvertisement {
            peer_id: 999,
            tip: 1000,
            headers: vec![Header {
                id: 1000,
                prev: Some(2),
                work: 1_000_000,
                claimed_valid: false,
            }],
        }
    }

    #[test]
    fn honest_view_reconciles() {
        let view = reconcile(&[honest_advertisement()]).unwrap();
        assert_eq!(view.tip, 2);
        assert_eq!(view.total_work, 11);
    }

    #[test]
    fn invalid_longer_attacker_view_is_rejected() {
        let view = reconcile(&[honest_advertisement(), invalid_attacker_advertisement()]).unwrap();
        assert_eq!(view.tip, 2);
        assert_eq!(view.total_work, 11);
    }

    #[test]
    fn no_delivered_valid_path_means_no_decision() {
        let delivered = deliver(
            &[invalid_attacker_advertisement()],
            FaultConfig {
                drop_per_mille: 0,
                base_delay_ms: 0,
                jitter_ms: 0,
                reorder_per_mille: 0,
            },
            7,
        );
        assert!(reconcile(&delivered).is_none());
    }

    #[test]
    fn repeated_faults_never_select_invalid_branch() {
        let advertisements = vec![honest_advertisement(), invalid_attacker_advertisement()];

        let cfgs = [
            FaultConfig {
                drop_per_mille: 0,
                base_delay_ms: 0,
                jitter_ms: 0,
                reorder_per_mille: 1000,
            },
            FaultConfig {
                drop_per_mille: 100,
                base_delay_ms: 50,
                jitter_ms: 10,
                reorder_per_mille: 500,
            },
            FaultConfig {
                drop_per_mille: 300,
                base_delay_ms: 200,
                jitter_ms: 100,
                reorder_per_mille: 700,
            },
            FaultConfig {
                drop_per_mille: 600,
                base_delay_ms: 1000,
                jitter_ms: 400,
                reorder_per_mille: 1000,
            },
        ];

        for (index, cfg) in cfgs.into_iter().enumerate() {
            for seed in 0..100u64 {
                let delivered = deliver(&advertisements, cfg, seed + index as u64 * 1000);
                if delivered.iter().any(|p| p.peer_id == 1) {
                    let view = reconcile(&delivered).expect("honest path implies a decision");
                    assert_eq!(view.tip, 2);
                } else {
                    assert!(
                        reconcile(&delivered).is_none(),
                        "no honest path must never yield attacker-only canonical choice"
                    );
                }
            }
        }
    }

    #[test]
    fn delivery_order_does_not_change_reconciliation() {
        let mut advertisements = vec![honest_advertisement(), invalid_attacker_advertisement()];

        let forward = reconcile(&advertisements);
        advertisements.reverse();
        let reverse = reconcile(&advertisements);

        assert_eq!(forward, reverse);
    }
}
