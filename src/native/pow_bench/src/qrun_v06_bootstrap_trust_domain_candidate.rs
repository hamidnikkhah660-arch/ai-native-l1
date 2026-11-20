//! CP-0639/CP-0640B: operator-provisioned bootstrap trust-domain quotas.
//!
//! Trust domains are local policy metadata. A relay cannot self-assert its domain in Q6AR.
//! The registry is provisioned out-of-band by the node operator from independently verified
//! administrative ownership information and is enforced by the permissionless runtime.
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub type RelayStaticKey = [u8; 32];
pub type TrustDomainId = [u8; 32];

pub const MAX_TRUST_DOMAIN_CANDIDATES: usize = 256;
pub const MAX_TRUST_DOMAIN_RELAYS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustDomainPolicyError {
    InvalidLimits,
    ZeroRelayKey,
    ZeroDomainId,
    DuplicateRelayKey,
    UnknownRelay,
    UnknownExistingRelay,
    DomainCandidateCapacity,
    DomainRelayCapacity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapTrustDomainPolicy {
    relay_domains: BTreeMap<RelayStaticKey, TrustDomainId>,
    max_candidates_per_domain: usize,
    max_relays_per_domain: usize,
}

impl BootstrapTrustDomainPolicy {
    /// Construct a local trust registry. Each relay key must be pinned and assigned by the
    /// operator; no value is accepted from a remote advertisement or peer-supplied label.
    pub fn new(
        assignments: impl IntoIterator<Item = (RelayStaticKey, TrustDomainId)>,
        max_candidates_per_domain: usize,
        max_relays_per_domain: usize,
    ) -> Result<Self, TrustDomainPolicyError> {
        if !(1..=MAX_TRUST_DOMAIN_CANDIDATES).contains(&max_candidates_per_domain)
            || !(1..=MAX_TRUST_DOMAIN_RELAYS).contains(&max_relays_per_domain)
        {
            return Err(TrustDomainPolicyError::InvalidLimits);
        }
        let mut relay_domains = BTreeMap::new();
        for (relay_key, domain_id) in assignments {
            if relay_key == [0; 32] {
                return Err(TrustDomainPolicyError::ZeroRelayKey);
            }
            if domain_id == [0; 32] {
                return Err(TrustDomainPolicyError::ZeroDomainId);
            }
            if relay_domains.insert(relay_key, domain_id).is_some() {
                return Err(TrustDomainPolicyError::DuplicateRelayKey);
            }
        }
        Ok(Self {
            relay_domains,
            max_candidates_per_domain,
            max_relays_per_domain,
        })
    }

    pub fn domain_for(
        &self,
        relay_key: &RelayStaticKey,
    ) -> Result<TrustDomainId, TrustDomainPolicyError> {
        self.relay_domains
            .get(relay_key)
            .copied()
            .ok_or(TrustDomainPolicyError::UnknownRelay)
    }

    /// Order operator-pinned relays in round-robin trust-domain order.
    ///
    /// With a bounded attempt budget, one relay from each configured domain is considered
    /// before a second relay from any domain. Domain IDs remain local operator metadata.
    pub fn order_relays_by_domain<T: Clone>(
        &self,
        relays: &[(RelayStaticKey, T)],
    ) -> Result<Vec<T>, TrustDomainPolicyError> {
        let mut grouped: BTreeMap<TrustDomainId, Vec<T>> = BTreeMap::new();
        let mut seen_relays = BTreeSet::new();
        for (relay_key, value) in relays {
            if !seen_relays.insert(*relay_key) {
                return Err(TrustDomainPolicyError::DuplicateRelayKey);
            }
            let domain_id = self.domain_for(relay_key)?;
            grouped.entry(domain_id).or_default().push(value.clone());
        }

        let max_domain_width = grouped.values().map(Vec::len).max().unwrap_or(0);
        let mut ordered = Vec::with_capacity(relays.len());
        for index in 0..max_domain_width {
            for domain_relays in grouped.values() {
                if let Some(value) = domain_relays.get(index) {
                    ordered.push(value.clone());
                }
            }
        }
        Ok(ordered)
    }

    /// Check admission of one additional candidate record from a pinned relay.
    ///
    /// existing_relay_keys contains one entry per existing candidate record (not a set).
    /// Unknown historical keys fail closed because their ownership cannot be attributed.
    /// The caller must separately enforce the existing per-relay and global book limits.
    pub fn check_candidate_admission(
        &self,
        relay_key: &RelayStaticKey,
        existing_relay_keys: &[RelayStaticKey],
    ) -> Result<TrustDomainId, TrustDomainPolicyError> {
        let domain_id = self.domain_for(relay_key)?;
        let mut domain_candidate_count = 0usize;
        let mut domain_relays = BTreeSet::new();

        for existing_key in existing_relay_keys {
            let existing_domain = self
                .relay_domains
                .get(existing_key)
                .copied()
                .ok_or(TrustDomainPolicyError::UnknownExistingRelay)?;
            if existing_domain == domain_id {
                domain_candidate_count = domain_candidate_count.saturating_add(1);
                domain_relays.insert(*existing_key);
            }
        }

        if domain_candidate_count >= self.max_candidates_per_domain {
            return Err(TrustDomainPolicyError::DomainCandidateCapacity);
        }
        if !domain_relays.contains(relay_key) && domain_relays.len() >= self.max_relays_per_domain {
            return Err(TrustDomainPolicyError::DomainRelayCapacity);
        }
        Ok(domain_id)
    }

    /// Stable identity for the complete operator-provisioned registry and its limits.
    /// BTreeMap iteration makes the digest independent of JSON row ordering.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"QFP6-BOOTSTRAP-TRUST-DOMAIN-REGISTRY-V1\\0");
        hash.update((self.max_candidates_per_domain as u64).to_be_bytes());
        hash.update((self.max_relays_per_domain as u64).to_be_bytes());
        hash.update((self.relay_domains.len() as u64).to_be_bytes());
        for (relay_key, domain_id) in &self.relay_domains {
            hash.update(relay_key);
            hash.update(domain_id);
        }
        hash.finalize().into()
    }

    /// Validate the complete set of already-persisted candidate records before binding a
    /// registry to an address book. The input has one relay key per candidate record.
    pub fn validate_existing_candidate_records(
        &self,
        existing_relay_keys: &[RelayStaticKey],
    ) -> Result<(), TrustDomainPolicyError> {
        let mut domain_candidates: BTreeMap<TrustDomainId, usize> = BTreeMap::new();
        let mut domain_relays: BTreeMap<TrustDomainId, BTreeSet<RelayStaticKey>> = BTreeMap::new();
        for relay_key in existing_relay_keys {
            let domain_id = self
                .relay_domains
                .get(relay_key)
                .copied()
                .ok_or(TrustDomainPolicyError::UnknownExistingRelay)?;
            let count = domain_candidates.entry(domain_id).or_default();
            *count = count.saturating_add(1);
            domain_relays
                .entry(domain_id)
                .or_default()
                .insert(*relay_key);
        }
        if domain_candidates
            .values()
            .any(|count| *count > self.max_candidates_per_domain)
        {
            return Err(TrustDomainPolicyError::DomainCandidateCapacity);
        }
        if domain_relays
            .values()
            .any(|relays| relays.len() > self.max_relays_per_domain)
        {
            return Err(TrustDomainPolicyError::DomainRelayCapacity);
        }
        Ok(())
    }

    pub fn relay_count(&self) -> usize {
        self.relay_domains.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> BootstrapTrustDomainPolicy {
        BootstrapTrustDomainPolicy::new(
            [
                ([1; 32], [10; 32]),
                ([2; 32], [10; 32]),
                ([3; 32], [20; 32]),
            ],
            4,
            2,
        )
        .unwrap()
    }

    #[test]
    fn multiple_relay_keys_share_one_domain_candidate_budget() {
        let policy = policy();
        let existing = vec![[1; 32], [1; 32], [2; 32], [2; 32]];
        assert_eq!(
            policy.check_candidate_admission(&[1; 32], &existing),
            Err(TrustDomainPolicyError::DomainCandidateCapacity)
        );
    }

    #[test]
    fn multiple_keys_cannot_exceed_domain_relay_count() {
        let policy = BootstrapTrustDomainPolicy::new(
            [
                ([1; 32], [10; 32]),
                ([2; 32], [10; 32]),
                ([4; 32], [10; 32]),
            ],
            8,
            2,
        )
        .unwrap();
        assert_eq!(
            policy.check_candidate_admission(&[4; 32], &[[1; 32], [2; 32]]),
            Err(TrustDomainPolicyError::DomainRelayCapacity)
        );
    }

    #[test]
    fn independently_assigned_domain_has_an_independent_budget() {
        let policy = policy();
        let existing = vec![[1; 32], [1; 32], [2; 32], [2; 32]];
        assert_eq!(
            policy.check_candidate_admission(&[3; 32], &existing),
            Ok([20; 32])
        );
    }

    #[test]
    fn bootstrap_peer_order_interleaves_trust_domains_before_reusing_one() {
        let policy = BootstrapTrustDomainPolicy::new(
            [
                ([1; 32], [10; 32]),
                ([2; 32], [10; 32]),
                ([3; 32], [20; 32]),
                ([4; 32], [20; 32]),
                ([5; 32], [30; 32]),
            ],
            8,
            4,
        )
        .unwrap();

        let ordered = policy
            .order_relays_by_domain(&[
                ([1; 32], "domain-10-first"),
                ([2; 32], "domain-10-second"),
                ([3; 32], "domain-20-first"),
                ([4; 32], "domain-20-second"),
                ([5; 32], "domain-30-first"),
            ])
            .unwrap();

        assert_eq!(
            ordered,
            vec![
                "domain-10-first",
                "domain-20-first",
                "domain-30-first",
                "domain-10-second",
                "domain-20-second",
            ]
        );
    }

    #[test]
    fn bootstrap_peer_order_rejects_unknown_or_duplicate_relay_keys() {
        let policy = policy();
        assert_eq!(
            policy.order_relays_by_domain(&[([99; 32], 1)]),
            Err(TrustDomainPolicyError::UnknownRelay)
        );
        assert_eq!(
            policy.order_relays_by_domain(&[([1; 32], 1), ([1; 32], 2)]),
            Err(TrustDomainPolicyError::DuplicateRelayKey)
        );
    }

    #[test]
    fn unknown_or_unattributable_relays_fail_closed() {
        let policy = policy();
        assert_eq!(
            policy.check_candidate_admission(&[9; 32], &[]),
            Err(TrustDomainPolicyError::UnknownRelay)
        );
        assert_eq!(
            policy.check_candidate_admission(&[3; 32], &[[9; 32]]),
            Err(TrustDomainPolicyError::UnknownExistingRelay)
        );
    }

    #[test]
    fn registry_fingerprint_is_order_independent_and_changes_with_policy() {
        let first =
            BootstrapTrustDomainPolicy::new([([1; 32], [10; 32]), ([2; 32], [10; 32])], 4, 2)
                .unwrap();
        let reordered =
            BootstrapTrustDomainPolicy::new([([2; 32], [10; 32]), ([1; 32], [10; 32])], 4, 2)
                .unwrap();
        let changed_limit =
            BootstrapTrustDomainPolicy::new([([1; 32], [10; 32]), ([2; 32], [10; 32])], 3, 2)
                .unwrap();

        assert_eq!(first.fingerprint(), reordered.fingerprint());
        assert_ne!(first.fingerprint(), changed_limit.fingerprint());
    }

    #[test]
    fn existing_candidate_book_is_validated_as_a_complete_domain_set() {
        let policy = policy();
        assert_eq!(
            policy.validate_existing_candidate_records(&[[1; 32], [2; 32], [1; 32], [2; 32]]),
            Ok(())
        );
        assert_eq!(
            policy.validate_existing_candidate_records(&[
                [1; 32], [1; 32], [1; 32], [1; 32], [1; 32]
            ]),
            Err(TrustDomainPolicyError::DomainCandidateCapacity)
        );
        assert_eq!(
            policy.validate_existing_candidate_records(&[[1; 32], [2; 32], [9; 32]]),
            Err(TrustDomainPolicyError::UnknownExistingRelay)
        );
    }

    #[test]
    fn invalid_or_ambiguous_operator_registry_is_rejected() {
        assert_eq!(
            BootstrapTrustDomainPolicy::new([([0; 32], [10; 32])], 4, 2),
            Err(TrustDomainPolicyError::ZeroRelayKey)
        );
        assert_eq!(
            BootstrapTrustDomainPolicy::new([([1; 32], [0; 32])], 4, 2),
            Err(TrustDomainPolicyError::ZeroDomainId)
        );
        assert_eq!(
            BootstrapTrustDomainPolicy::new([([1; 32], [10; 32]), ([1; 32], [20; 32])], 4, 2),
            Err(TrustDomainPolicyError::DuplicateRelayKey)
        );
        assert_eq!(
            BootstrapTrustDomainPolicy::new([([1; 32], [10; 32])], 0, 2),
            Err(TrustDomainPolicyError::InvalidLimits)
        );
    }
}
