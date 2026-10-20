//! Research peer-selection policy with learned-peer and tenure protection.
//! This is routing policy, never a consensus trust mechanism.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    pub peer_id: u64,
    pub prefix: u32,
    pub source: u32,
    pub established_since_ms: Option<u64>,
    pub successful_sessions: u32,
    pub failures: u32,
    pub last_success_ms: u64,
}

impl PeerRecord {
    pub fn tenure_ms(&self, now_ms: u64) -> u64 {
        self.established_since_ms
            .map(|start| now_ms.saturating_sub(start))
            .unwrap_or(0)
    }

    pub fn is_established(&self, now_ms: u64, minimum_tenure_ms: u64) -> bool {
        self.established_since_ms.is_some()
            && self.tenure_ms(now_ms) >= minimum_tenure_ms
            && self.successful_sessions >= 2
            && self.failures == 0
    }

    pub fn routing_score(&self, now_ms: u64) -> i64 {
        let tenure_bonus = (self.tenure_ms(now_ms) / 60_000).min(120) as i64;
        let success_bonus = (self.successful_sessions.min(20) * 4) as i64;
        let failure_penalty = (self.failures.min(20) * 12) as i64;
        (100 + tenure_bonus + success_bonus - failure_penalty).clamp(0, 200)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub slots: usize,
    pub protected_established: usize,
    pub minimum_tenure_ms: u64,
    pub max_per_prefix: usize,
    pub max_per_source: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            slots: 8,
            protected_established: 4,
            minimum_tenure_ms: 3_600_000,
            max_per_prefix: 1,
            max_per_source: 1,
        }
    }
}

pub fn select_peers(peers: &[PeerRecord], policy: Policy, now_ms: u64) -> Vec<PeerRecord> {
    let mut pool = peers.to_vec();
    let mut selected = Vec::new();
    let mut prefixes = std::collections::HashSet::new();
    let mut sources = std::collections::HashSet::new();

    let mut established: Vec<PeerRecord> = pool
        .iter()
        .filter(|p| p.is_established(now_ms, policy.minimum_tenure_ms))
        .cloned()
        .collect();

    established.sort_by_key(|p| std::cmp::Reverse(p.routing_score(now_ms)));

    for peer in established {
        if selected.len() >= policy.protected_established.min(policy.slots) {
            break;
        }
        if prefixes.contains(&peer.prefix) || sources.contains(&peer.source) {
            continue;
        }
        prefixes.insert(peer.prefix);
        sources.insert(peer.source);
        selected.push(peer.clone());
        pool.retain(|p| p.peer_id != peer.peer_id);
    }

    pool.sort_by_key(|p| {
        (
            std::cmp::Reverse(p.routing_score(now_ms)),
            p.failures,
            p.peer_id,
        )
    });

    for peer in pool {
        if selected.len() >= policy.slots {
            break;
        }
        if prefixes.contains(&peer.prefix) || sources.contains(&peer.source) {
            continue;
        }
        prefixes.insert(peer.prefix);
        sources.insert(peer.source);
        selected.push(peer);
    }

    selected
}
#[cfg(test)]
mod tests {
    use super::*;

    fn honest(peer_id: u64, prefix: u32, source: u32) -> PeerRecord {
        PeerRecord {
            peer_id,
            prefix,
            source,
            established_since_ms: Some(1_000),
            successful_sessions: 8,
            failures: 0,
            last_success_ms: 10_000,
        }
    }

    fn fresh_attacker(peer_id: u64) -> PeerRecord {
        PeerRecord {
            peer_id,
            prefix: 10_000 + peer_id as u32,
            source: 20_000 + peer_id as u32,
            established_since_ms: None,
            successful_sessions: 0,
            failures: 0,
            last_success_ms: 0,
        }
    }

    fn long_lived_attacker(peer_id: u64) -> PeerRecord {
        PeerRecord {
            peer_id,
            prefix: 30_000 + peer_id as u32,
            source: 40_000 + peer_id as u32,
            established_since_ms: Some(1_000),
            successful_sessions: 8,
            failures: 0,
            last_success_ms: 10_000,
        }
    }

    #[test]
    fn tenure_and_success_make_a_peer_established() {
        let p = honest(1, 1, 1);
        assert!(p.is_established(3_600_000 + 1_000, 3_600_000));
        assert!(p.routing_score(3_600_000 + 1_000) > 100);
    }

    #[test]
    fn fresh_flood_cannot_evict_protected_established_peers() {
        let mut peers = vec![
            honest(1, 1, 1),
            honest(2, 2, 2),
            honest(3, 3, 3),
            honest(4, 4, 4),
            honest(5, 5, 5),
            honest(6, 6, 6),
        ];
        peers.extend((100..300).map(fresh_attacker));

        let selected = select_peers(&peers, Policy::default(), 3_600_000 + 1_000);
        let established_count = selected
            .iter()
            .filter(|p| p.successful_sessions >= 2)
            .count();

        assert!(established_count >= 4);
        assert_eq!(selected.len(), 8);
    }

    #[test]
    fn long_lived_attackers_are_not_misclassified_as_honest() {
        let mut peers = vec![
            honest(1, 1, 1),
            honest(2, 2, 2),
            honest(3, 3, 3),
            honest(4, 4, 4),
        ];
        peers.extend((100..120).map(long_lived_attacker));

        let selected = select_peers(&peers, Policy::default(), 3_600_000 + 1_000);
        assert!(selected.len() <= 8);
        assert_eq!(selected.iter().filter(|p| p.peer_id < 10).count(), 4);
    }
}
