//! CP-0225-OSB: isolated Rust encoder and validator for the STV4 boundary state.
//!
//! Candidate-only: not connected to migration execution, Genesis, state storage,
//! transaction authentication, block admission, or consensus. The fixed fixtures are
//! synthetic. An account ID preserved across migration is not proof of spend authority.
use sha2::{Digest, Sha256};
use std::fmt;

pub const STATE_VERSION: u16 = 4;
pub const BOUNDARY_KIND_HARD_FORK: u8 = 1;
pub const MIGRATION_DESCRIPTOR_BYTES: usize = 234;
pub const ACCOUNT_RECORD_BYTES: usize = 48;
pub const MAX_ACCOUNTS: usize = 100_000;
pub const MAX_STV4_BOUNDARY_BYTES: usize = 8_388_608;

pub const ATOM_LIMIT: u64 = 1_000_000_000_000_000_000;
pub const MINER_LIMIT: u64 = 300_000_000_000_000_000;
/// 4,000,000,000 whole coins at 8 decimals, inside the 10B lifetime cap.
pub const FOUNDER_LIMIT: u64 = 400_000_000_000_000_000;
pub const PUBLIC_GOODS_LIMITS: [u64; 6] = [
    30_000_000_000_000_000,
    90_000_000_000_000_000,
    60_000_000_000_000_000,
    30_000_000_000_000_000,
    30_000_000_000_000_000,
    60_000_000_000_000_000,
];

const STATE_PREFIX: &[u8] = b"AIN1-STATE-V4\0";
const STATE_ROOT_DOMAIN: &[u8] = b"AIN1-STATE-ROOT-V4\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundaryStateError {
    ZeroIdentity(&'static str),
    InvalidEpoch,
    InvalidHeightTimestamp,
    WrongNonceCardinality,
    NonzeroGovernanceNonce,
    PendingGovernanceAtBoundary,
    IssuanceCounterMismatch,
    IssuanceCapExceeded,
    BurnExceedsIssuance,
    BalanceConservationMismatch,
    ZeroAccountId,
    AccountsNotCanonical,
    AccountLimitExceeded,
    StateTooLarge,
}

impl fmt::Display for BoundaryStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for BoundaryStateError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryAccount {
    pub account_id: [u8; 32],
    pub balance_atoms: u64,
    pub nonce: u64,
}

impl BoundaryAccount {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.account_id);
        out.extend_from_slice(&self.balance_atoms.to_be_bytes());
        out.extend_from_slice(&self.nonce.to_be_bytes());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryStateV4 {
    pub network_id: [u8; 32],
    pub manifest_id: [u8; 32],
    pub height: u64,
    pub last_timestamp: u64,
    pub governance_config_hash: [u8; 32],
    pub roster_epoch: u64,
    pub recovery_policy_hash: [u8; 32],
    pub recovery_policy_epoch: u64,
    pub migration_descriptor: [u8; MIGRATION_DESCRIPTOR_BYTES],
    pub legacy_founder_beneficiary_id: [u8; 32],
    pub total_issued_atoms: u64,
    pub miner_issued_atoms: u64,
    pub founder_issued_atoms: u64,
    pub public_goods_issued_atoms: [u64; 6],
    pub total_burned_atoms: u64,
    pub proposer_nonce_highwater: [u64; 7],
    pub accounts: Vec<BoundaryAccount>,
    pub pending_treasury_actions_count: u16,
    pub pending_roster_transitions_count: u16,
}

impl BoundaryStateV4 {
    pub fn validate(&self) -> Result<(), BoundaryStateError> {
        for (field, value) in [
            ("network_id", &self.network_id),
            ("manifest_id", &self.manifest_id),
            ("governance_config_hash", &self.governance_config_hash),
            ("recovery_policy_hash", &self.recovery_policy_hash),
            (
                "legacy_founder_beneficiary_id",
                &self.legacy_founder_beneficiary_id,
            ),
        ] {
            if value.iter().all(|byte| *byte == 0) {
                return Err(BoundaryStateError::ZeroIdentity(field));
            }
        }

        if self.height == 0 && self.last_timestamp != 0
            || self.height > 0 && self.last_timestamp == 0
        {
            return Err(BoundaryStateError::InvalidHeightTimestamp);
        }
        if self.roster_epoch == 0 || self.recovery_policy_epoch == 0 {
            return Err(BoundaryStateError::InvalidEpoch);
        }
        if self.proposer_nonce_highwater.len() != 7 {
            return Err(BoundaryStateError::WrongNonceCardinality);
        }
        if self
            .proposer_nonce_highwater
            .iter()
            .any(|nonce| *nonce != 0)
        {
            return Err(BoundaryStateError::NonzeroGovernanceNonce);
        }
        if self.pending_treasury_actions_count != 0 || self.pending_roster_transitions_count != 0 {
            return Err(BoundaryStateError::PendingGovernanceAtBoundary);
        }

        let issuance_sum = self.miner_issued_atoms as u128
            + self.founder_issued_atoms as u128
            + self
                .public_goods_issued_atoms
                .iter()
                .map(|value| *value as u128)
                .sum::<u128>();
        if issuance_sum != self.total_issued_atoms as u128 {
            return Err(BoundaryStateError::IssuanceCounterMismatch);
        }
        if self.total_issued_atoms > ATOM_LIMIT
            || self.miner_issued_atoms > MINER_LIMIT
            || self.founder_issued_atoms > FOUNDER_LIMIT
            || self
                .public_goods_issued_atoms
                .iter()
                .zip(PUBLIC_GOODS_LIMITS)
                .any(|(value, limit)| *value > limit)
        {
            return Err(BoundaryStateError::IssuanceCapExceeded);
        }
        if self.total_burned_atoms > self.total_issued_atoms {
            return Err(BoundaryStateError::BurnExceedsIssuance);
        }

        if self.accounts.len() > MAX_ACCOUNTS {
            return Err(BoundaryStateError::AccountLimitExceeded);
        }
        let mut balance_sum = 0u128;
        let mut encoded_size = fixed_preimage_size();
        for account in &self.accounts {
            if account.account_id.iter().all(|byte| *byte == 0) {
                return Err(BoundaryStateError::ZeroAccountId);
            }
            balance_sum += account.balance_atoms as u128;
            encoded_size = encoded_size.saturating_add(ACCOUNT_RECORD_BYTES);
        }
        if self
            .accounts
            .windows(2)
            .any(|pair| pair[0].account_id >= pair[1].account_id)
        {
            return Err(BoundaryStateError::AccountsNotCanonical);
        }
        if balance_sum != (self.total_issued_atoms - self.total_burned_atoms) as u128 {
            return Err(BoundaryStateError::BalanceConservationMismatch);
        }
        if encoded_size > MAX_STV4_BOUNDARY_BYTES {
            return Err(BoundaryStateError::StateTooLarge);
        }
        Ok(())
    }

    /// Byte-exact canonical STV4 boundary preimage. FAT1 is intentionally external.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BoundaryStateError> {
        self.validate()?;
        let mut out =
            Vec::with_capacity(fixed_preimage_size() + self.accounts.len() * ACCOUNT_RECORD_BYTES);
        out.extend_from_slice(STATE_PREFIX);
        out.extend_from_slice(&STATE_VERSION.to_be_bytes());
        out.push(BOUNDARY_KIND_HARD_FORK);
        out.extend_from_slice(&self.network_id);
        out.extend_from_slice(&self.manifest_id);
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.last_timestamp.to_be_bytes());
        out.extend_from_slice(&self.governance_config_hash);
        out.extend_from_slice(&self.roster_epoch.to_be_bytes());
        out.extend_from_slice(&self.recovery_policy_hash);
        out.extend_from_slice(&self.recovery_policy_epoch.to_be_bytes());
        out.extend_from_slice(&self.migration_descriptor);
        out.extend_from_slice(&self.legacy_founder_beneficiary_id);
        out.extend_from_slice(&self.total_issued_atoms.to_be_bytes());
        out.extend_from_slice(&self.miner_issued_atoms.to_be_bytes());
        out.extend_from_slice(&self.founder_issued_atoms.to_be_bytes());
        for value in self.public_goods_issued_atoms {
            out.extend_from_slice(&value.to_be_bytes());
        }
        out.extend_from_slice(&self.total_burned_atoms.to_be_bytes());
        for nonce in self.proposer_nonce_highwater {
            out.extend_from_slice(&nonce.to_be_bytes());
        }
        out.extend_from_slice(&(self.accounts.len() as u32).to_be_bytes());
        for account in &self.accounts {
            account.encode_into(&mut out);
        }
        out.extend_from_slice(&self.pending_treasury_actions_count.to_be_bytes());
        out.extend_from_slice(&self.pending_roster_transitions_count.to_be_bytes());
        if out.len() > MAX_STV4_BOUNDARY_BYTES {
            return Err(BoundaryStateError::StateTooLarge);
        }
        Ok(out)
    }

    /// Root domain is SHA-256("AIN1-STATE-ROOT-V4\\0" || canonical_preimage).
    pub fn state_root(&self) -> Result<[u8; 32], BoundaryStateError> {
        let preimage = self.canonical_bytes()?;
        let mut hasher = Sha256::new();
        hasher.update(STATE_ROOT_DOMAIN);
        hasher.update(preimage);
        Ok(hasher.finalize().into())
    }
}

const fn fixed_preimage_size() -> usize {
    STATE_PREFIX.len()
        + 2
        + 1
        + 32
        + 32
        + 8
        + 8
        + 32
        + 8
        + 32
        + 8
        + MIGRATION_DESCRIPTOR_BYTES
        + 32
        + 8
        + 8
        + 8
        + 6 * 8
        + 8
        + 7 * 8
        + 4
        + 2
        + 2
}

#[cfg(test)]
mod tests {
    use super::*;
    const VECTOR_FILE: &str =
        include_str!("../../../../simulations/cp0224_stv4_migration_boundary_vectors.tsv");
    const CP0237_MUTATION_VECTORS: &str =
        include_str!("../../../../simulations/cp0237_stv4_root_mutation_vectors.tsv");
    const CP0238_PROPERTY_VECTORS: &str =
        include_str!("../../../../simulations/cp0238_stv4_property_vectors.tsv");
    const BOUNDARY_FIXTURE: &[u8] =
        include_bytes!("../../../../simulations/cp0224_stv4_boundary_preimage.bin");

    struct Reader<'a> {
        bytes: &'a [u8],
        offset: usize,
    }

    impl<'a> Reader<'a> {
        fn take<const N: usize>(&mut self) -> [u8; N] {
            let end = self.offset + N;
            let value: [u8; N] = self.bytes[self.offset..end]
                .try_into()
                .expect("fixture truncated");
            self.offset = end;
            value
        }
        fn u8(&mut self) -> u8 {
            self.take::<1>()[0]
        }
        fn u16(&mut self) -> u16 {
            u16::from_be_bytes(self.take())
        }
        fn u32(&mut self) -> u32 {
            u32::from_be_bytes(self.take())
        }
        fn u64(&mut self) -> u64 {
            u64::from_be_bytes(self.take())
        }
    }

    fn decode_fixture(bytes: &[u8]) -> BoundaryStateV4 {
        assert!(bytes.starts_with(STATE_PREFIX));
        let mut reader = Reader {
            bytes,
            offset: STATE_PREFIX.len(),
        };
        assert_eq!(reader.u16(), STATE_VERSION);
        assert_eq!(reader.u8(), BOUNDARY_KIND_HARD_FORK);
        let network_id = reader.take();
        let manifest_id = reader.take();
        let height = reader.u64();
        let last_timestamp = reader.u64();
        let governance_config_hash = reader.take();
        let roster_epoch = reader.u64();
        let recovery_policy_hash = reader.take();
        let recovery_policy_epoch = reader.u64();
        let migration_descriptor = reader.take();
        let legacy_founder_beneficiary_id = reader.take();
        let total_issued_atoms = reader.u64();
        let miner_issued_atoms = reader.u64();
        let founder_issued_atoms = reader.u64();
        let mut public_goods_issued_atoms = [0u64; 6];
        for value in &mut public_goods_issued_atoms {
            *value = reader.u64();
        }
        let total_burned_atoms = reader.u64();
        let mut proposer_nonce_highwater = [0u64; 7];
        for nonce in &mut proposer_nonce_highwater {
            *nonce = reader.u64();
        }
        let account_count = reader.u32() as usize;
        let mut accounts = Vec::with_capacity(account_count);
        for _ in 0..account_count {
            accounts.push(BoundaryAccount {
                account_id: reader.take(),
                balance_atoms: reader.u64(),
                nonce: reader.u64(),
            });
        }
        let pending_treasury_actions_count = reader.u16();
        let pending_roster_transitions_count = reader.u16();
        assert_eq!(reader.offset, bytes.len(), "fixture has trailing bytes");
        BoundaryStateV4 {
            network_id,
            manifest_id,
            height,
            last_timestamp,
            governance_config_hash,
            roster_epoch,
            recovery_policy_hash,
            recovery_policy_epoch,
            migration_descriptor,
            legacy_founder_beneficiary_id,
            total_issued_atoms,
            miner_issued_atoms,
            founder_issued_atoms,
            public_goods_issued_atoms,
            total_burned_atoms,
            proposer_nonce_highwater,
            accounts,
            pending_treasury_actions_count,
            pending_roster_transitions_count,
        }
    }

    fn vector_value(key: &str) -> &str {
        VECTOR_FILE
            .lines()
            .filter(|line| !line.starts_with('#'))
            .find_map(|line| {
                let (name, value) = line.split_once('\t')?;
                (name == key).then_some(value)
            })
            .expect("required CP-0224 golden vector")
    }
    fn from_hex_32(hex: &str) -> [u8; 32] {
        assert_eq!(hex.len(), 64);
        let mut result = [0u8; 32];
        for (index, value) in result.iter_mut().enumerate() {
            *value = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
        }
        result
    }

    #[test]
    fn cp0224_golden_preimage_and_root_match() {
        let state = decode_fixture(BOUNDARY_FIXTURE);
        assert_eq!(BOUNDARY_FIXTURE.len(), 683);
        assert_eq!(
            state.canonical_bytes().unwrap().as_slice(),
            BOUNDARY_FIXTURE
        );
        assert_eq!(Sha256::digest(BOUNDARY_FIXTURE).as_slice().len(), 32);
        let expected_preimage_sha = from_hex_32(vector_value("boundary.preimage_sha256"));
        assert_eq!(
            Sha256::digest(BOUNDARY_FIXTURE).as_slice(),
            expected_preimage_sha
        );
        assert_eq!(
            state.state_root().unwrap(),
            from_hex_32(vector_value("boundary.state_root"))
        );
    }

    #[test]
    fn root_binds_manifest_governance_accounts_and_economic_counters() {
        let state = decode_fixture(BOUNDARY_FIXTURE);
        let expected = state.state_root().unwrap();

        let mut changed = state.clone();
        changed.manifest_id[0] ^= 1;
        assert_ne!(changed.state_root().unwrap(), expected);

        let mut changed = state.clone();
        changed.governance_config_hash[0] ^= 1;
        assert_ne!(changed.state_root().unwrap(), expected);

        let mut changed = state.clone();
        changed.accounts[0].nonce += 1;
        assert_ne!(changed.canonical_bytes().unwrap(), BOUNDARY_FIXTURE);

        let mut changed = state.clone();
        changed.total_burned_atoms += 1;
        assert!(changed.canonical_bytes().is_err());
    }

    #[test]
    fn rejects_unsorted_accounts_nonzero_governance_nonces_and_pending_sets() {
        let state = decode_fixture(BOUNDARY_FIXTURE);
        let mut unsorted = state.clone();
        unsorted.accounts.reverse();
        assert_eq!(
            unsorted.validate(),
            Err(BoundaryStateError::AccountsNotCanonical)
        );

        let mut nonce = state.clone();
        nonce.proposer_nonce_highwater[3] = 1;
        assert_eq!(
            nonce.validate(),
            Err(BoundaryStateError::NonzeroGovernanceNonce)
        );

        let mut treasury = state.clone();
        treasury.pending_treasury_actions_count = 1;
        assert_eq!(
            treasury.validate(),
            Err(BoundaryStateError::PendingGovernanceAtBoundary)
        );
    }

    #[test]
    fn rejects_counter_cap_and_balance_violations() {
        let state = decode_fixture(BOUNDARY_FIXTURE);

        let mut bad_sum = state.clone();
        bad_sum.miner_issued_atoms += 1;
        assert_eq!(
            bad_sum.validate(),
            Err(BoundaryStateError::IssuanceCounterMismatch)
        );

        let mut over_cap = state.clone();
        over_cap.total_issued_atoms = ATOM_LIMIT + 1;
        over_cap.miner_issued_atoms =
            ATOM_LIMIT + 1 - over_cap.public_goods_issued_atoms.iter().sum::<u64>();
        assert_eq!(
            over_cap.validate(),
            Err(BoundaryStateError::IssuanceCapExceeded)
        );

        let mut owner_credit = state.clone();
        owner_credit.founder_issued_atoms = FOUNDER_LIMIT;
        owner_credit.total_issued_atoms += FOUNDER_LIMIT;
        owner_credit.accounts[0].balance_atoms += FOUNDER_LIMIT;
        assert!(
            owner_credit.validate().is_ok(),
            "owner allocation must not have protocol-time vesting"
        );

        let mut bad_balance = state.clone();
        bad_balance.accounts[0].balance_atoms += 1;
        assert_eq!(
            bad_balance.validate(),
            Err(BoundaryStateError::BalanceConservationMismatch)
        );

        let mut invalid_burn = state.clone();
        invalid_burn.total_burned_atoms = invalid_burn.total_issued_atoms + 1;
        assert_eq!(
            invalid_burn.validate(),
            Err(BoundaryStateError::BurnExceedsIssuance)
        );
    }

    #[test]
    fn rejects_zero_ids_bad_epochs_and_height_timestamp_mismatch() {
        let state = decode_fixture(BOUNDARY_FIXTURE);

        let mut zero_id = state.clone();
        zero_id.accounts[0].account_id = [0; 32];
        assert_eq!(zero_id.validate(), Err(BoundaryStateError::ZeroAccountId));

        let mut zero_manifest = state.clone();
        zero_manifest.manifest_id = [0; 32];
        assert_eq!(
            zero_manifest.validate(),
            Err(BoundaryStateError::ZeroIdentity("manifest_id"))
        );

        let mut epoch = state.clone();
        epoch.roster_epoch = 0;
        assert_eq!(epoch.validate(), Err(BoundaryStateError::InvalidEpoch));

        let mut timestamp = state.clone();
        timestamp.last_timestamp = 0;
        assert_eq!(
            timestamp.validate(),
            Err(BoundaryStateError::InvalidHeightTimestamp)
        );
    }

    #[test]
    fn owner_allocation_limit_is_inside_the_lifetime_supply_cap() {
        assert_eq!(ATOM_LIMIT, 1_000_000_000_000_000_000);
        assert_eq!(FOUNDER_LIMIT, 400_000_000_000_000_000);
        assert_eq!(FOUNDER_LIMIT as u128 * 100 / ATOM_LIMIT as u128, 40);
        assert_eq!(ATOM_LIMIT / 100_000_000, 10_000_000_000);
        assert_eq!(FOUNDER_LIMIT / 100_000_000, 4_000_000_000);
    }

    fn cp0237_mutate(name: &str, state: &mut BoundaryStateV4) {
        match name {
            "network_id_byte" => state.network_id[0] ^= 1,
            "manifest_id_byte" => state.manifest_id[0] ^= 1,
            "height_increment" => state.height += 1,
            "timestamp_increment" => state.last_timestamp += 1,
            "governance_config_hash_byte" => state.governance_config_hash[0] ^= 1,
            "roster_epoch_increment" => state.roster_epoch += 1,
            "recovery_policy_hash_byte" => state.recovery_policy_hash[0] ^= 1,
            "recovery_policy_epoch_increment" => state.recovery_policy_epoch += 1,
            "migration_descriptor_byte" => state.migration_descriptor[233] ^= 1,
            "founder_beneficiary_byte" => state.legacy_founder_beneficiary_id[0] ^= 1,
            "miner_issuance_bundle" => {
                state.total_issued_atoms += 1;
                state.miner_issued_atoms += 1;
                state.accounts[0].balance_atoms += 1;
            }
            "founder_issuance_bundle" => {
                state.total_issued_atoms += 1;
                state.founder_issued_atoms += 1;
                state.accounts[0].balance_atoms += 1;
            }
            "public_goods_issuance_bundle" => {
                state.total_issued_atoms += 1;
                state.public_goods_issued_atoms[0] += 1;
                state.accounts[0].balance_atoms += 1;
            }
            "burn_and_balance_bundle" => {
                state.total_burned_atoms += 1;
                state.accounts[0].balance_atoms -= 1;
            }
            "account_id_byte" => state.accounts[0].account_id[0] ^= 1,
            "account_nonce_increment" => state.accounts[0].nonce += 1,
            "account_balance_redistribution" => {
                state.accounts[0].balance_atoms += 1;
                state.accounts[1].balance_atoms -= 1;
            }
            "account_count_split" => {
                state.accounts[0].balance_atoms -= 1;
                state.accounts.insert(
                    1,
                    BoundaryAccount {
                        account_id: [0x28; 32],
                        balance_atoms: 1,
                        nonce: 0,
                    },
                );
            }
            _ => panic!("unknown CP-0237 mutation case: {name}"),
        }
    }

    fn cp0237_apply_raw_patches(base: &[u8], encoded: &str) -> Vec<u8> {
        let mut bytes = base.to_vec();
        let mut patches = Vec::<(usize, usize, Vec<u8>)>::new();
        for patch in encoded.split(';') {
            let mut parts = patch.splitn(3, ':');
            let offset = parts
                .next()
                .expect("patch offset")
                .parse::<usize>()
                .unwrap();
            let delete_len = parts
                .next()
                .expect("patch delete length")
                .parse::<usize>()
                .unwrap();
            let hex = parts.next().expect("patch inserted bytes");
            assert_eq!(hex.len() % 2, 0, "hex length must be even");
            let payload = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect::<Vec<_>>();
            assert!(offset + delete_len <= bytes.len(), "patch is out of bounds");
            patches.push((offset, delete_len, payload));
        }
        patches.sort_by(|a, b| b.0.cmp(&a.0));
        for (offset, delete_len, payload) in patches {
            drop(bytes.splice(offset..offset + delete_len, payload));
        }
        bytes
    }

    #[test]
    fn cp0237_independent_stv4_root_mutation_vectors_match_rust() {
        let baseline = decode_fixture(BOUNDARY_FIXTURE);
        let baseline_root = baseline.state_root().unwrap();
        let mut seen = 0usize;
        for line in CP0237_MUTATION_VECTORS.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let columns = line.split('\t').collect::<Vec<_>>();
            assert_eq!(columns.len(), 4, "malformed CP-0237 vector: {line}");
            let (name, patch_text, preimage_hash, root_hex) =
                (columns[0], columns[1], columns[2], columns[3]);
            let patched_raw = cp0237_apply_raw_patches(BOUNDARY_FIXTURE, patch_text);
            let patched_preimage_hash: [u8; 32] = Sha256::digest(&patched_raw).into();
            assert_eq!(
                patched_preimage_hash,
                from_hex_32(preimage_hash),
                "{name}: preimage hash"
            );
            let raw_root: [u8; 32] = {
                let mut h = Sha256::new();
                h.update(STATE_ROOT_DOMAIN);
                h.update(&patched_raw);
                h.finalize().into()
            };
            assert_eq!(
                raw_root,
                from_hex_32(root_hex),
                "{name}: independent raw root"
            );

            let mut changed = baseline.clone();
            cp0237_mutate(name, &mut changed);
            let canonical = changed.canonical_bytes().unwrap();
            assert_eq!(
                canonical, patched_raw,
                "{name}: Rust serialization vs fixed patch"
            );
            assert_ne!(
                changed.state_root().unwrap(),
                baseline_root,
                "{name}: root unchanged"
            );
            assert_eq!(
                changed.state_root().unwrap(),
                raw_root,
                "{name}: Rust state root"
            );
            seen += 1;
        }
        assert_eq!(seen, 18, "CP-0237 mutation vector count changed");
        eprintln!(
            "CP-0237_RUST_ROOT_MUTATIONS=PASS rows={seen} baseline_bytes={}",
            BOUNDARY_FIXTURE.len()
        );
    }

    const CP0238_VALID_SEED: u64 = 0xA1B2_C3D4_E5F6_0718;
    const CP0238_INVALID_SEED: u64 = 0xC0DE_C0FF_EE12_3457;

    fn cp0238_next_u64(state: &mut u64) -> u64 {
        let mut value = *state;
        value ^= value.wrapping_shl(13);
        value ^= value >> 7;
        value ^= value.wrapping_shl(17);
        *state = value;
        value
    }

    fn cp0238_case_name(kind: usize) -> &'static str {
        match kind {
            0 => "network_id_byte",
            1 => "manifest_id_byte",
            2 => "height_timestamp_pair",
            3 => "governance_config_byte",
            4 => "roster_epoch",
            5 => "recovery_policy_byte",
            6 => "recovery_policy_epoch",
            7 => "migration_descriptor_byte",
            8 => "founder_beneficiary_byte",
            9 => "miner_issuance_bundle",
            10 => "founder_issuance_bundle",
            11 => "public_goods_issuance_bundle",
            12 => "burn_and_balance_bundle",
            13 => "balance_redistribution",
            14 => "account_nonce",
            15 => "account_id_last_byte",
            16 => "account_count_split",
            _ => panic!("unknown CP-0238 valid case {kind}"),
        }
    }

    fn cp0238_mutate_valid(
        state: &mut BoundaryStateV4,
        kind: usize,
        delta: u64,
        byte: u8,
        offset: usize,
    ) {
        match kind {
            0 => state.network_id[offset] ^= byte,
            1 => state.manifest_id[offset] ^= byte,
            2 => {
                state.height += delta;
                state.last_timestamp += delta;
            }
            3 => state.governance_config_hash[offset] ^= byte,
            4 => state.roster_epoch += delta,
            5 => state.recovery_policy_hash[offset] ^= byte,
            6 => state.recovery_policy_epoch += delta,
            7 => state.migration_descriptor[offset] ^= byte,
            8 => state.legacy_founder_beneficiary_id[offset] ^= byte,
            9 => {
                state.total_issued_atoms += delta;
                state.miner_issued_atoms += delta;
                state.accounts[0].balance_atoms += delta;
            }
            10 => {
                state.total_issued_atoms += delta;
                state.founder_issued_atoms += delta;
                state.accounts[0].balance_atoms += delta;
            }
            11 => {
                state.total_issued_atoms += delta;
                state.public_goods_issued_atoms[0] += delta;
                state.accounts[0].balance_atoms += delta;
            }
            12 => {
                state.total_burned_atoms += delta;
                state.accounts[0].balance_atoms -= delta;
            }
            13 => {
                state.accounts[0].balance_atoms += delta;
                state.accounts[1].balance_atoms -= delta;
            }
            14 => state.accounts[0].nonce += delta,
            15 => state.accounts[0].account_id[31] ^= byte,
            16 => {
                state.accounts[0].balance_atoms -= 1;
                state.accounts.insert(
                    1,
                    BoundaryAccount {
                        account_id: [0x28; 32],
                        balance_atoms: 1,
                        nonce: 0,
                    },
                );
            }
            _ => panic!("unknown CP-0238 mutation kind {kind}"),
        }
    }

    fn cp0238_hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write as _;
            write!(&mut out, "{byte:02x}").unwrap();
        }
        out
    }

    #[test]
    fn cp0238_2048_valid_property_cases_match_python_fixture() {
        let baseline = decode_fixture(BOUNDARY_FIXTURE);
        let baseline_root = baseline.state_root().unwrap();
        assert_eq!(baseline.canonical_bytes().unwrap(), BOUNDARY_FIXTURE);
        let mut rng = CP0238_VALID_SEED;
        let mut seen = 0usize;

        for line in CP0238_PROPERTY_VECTORS.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let columns = line.split('\t').collect::<Vec<_>>();
            assert_eq!(columns.len(), 7, "malformed CP-0238 vector: {line}");
            let index = columns[0].parse::<usize>().unwrap();
            let kind = index % 17;
            let delta = cp0238_next_u64(&mut rng) % 1000 + 1;
            let random_word = cp0238_next_u64(&mut rng);
            let byte = (random_word % 255 + 1) as u8;
            let descriptor_word = cp0238_next_u64(&mut rng);
            let short_offset = (random_word % 32) as usize;
            let descriptor_offset = (descriptor_word % MIGRATION_DESCRIPTOR_BYTES as u64) as usize;
            let offset = match kind {
                0 | 1 | 3 | 5 | 8 => short_offset,
                7 => descriptor_offset,
                15 => 31,
                16 => 1,
                _ => 0,
            };

            assert_eq!(index, seen, "CP-0238 index is not contiguous");
            assert_eq!(columns[1], cp0238_case_name(kind), "case {index} name");
            assert_eq!(
                columns[2].parse::<u64>().unwrap(),
                delta,
                "case {index} delta"
            );
            assert_eq!(columns[3].parse::<u8>().unwrap(), byte, "case {index} byte");
            assert_eq!(
                columns[4].parse::<usize>().unwrap(),
                offset,
                "case {index} offset"
            );

            let mut changed = baseline.clone();
            cp0238_mutate_valid(&mut changed, kind, delta, byte, offset);
            changed
                .validate()
                .unwrap_or_else(|error| panic!("case {index}: {error}"));
            let raw = changed.canonical_bytes().unwrap();
            assert_eq!(
                raw,
                changed.canonical_bytes().unwrap(),
                "case {index}: nondeterministic encoding"
            );
            assert_ne!(raw, BOUNDARY_FIXTURE, "case {index}: no byte mutation");
            assert_ne!(
                changed.state_root().unwrap(),
                baseline_root,
                "case {index}: root unchanged"
            );

            let preimage_hash: [u8; 32] = Sha256::digest(&raw).into();
            assert_eq!(
                columns[5],
                cp0238_hex(&preimage_hash),
                "case {index}: preimage hash"
            );
            assert_eq!(
                columns[6],
                cp0238_hex(&changed.state_root().unwrap()),
                "case {index}: state root"
            );
            seen += 1;
        }
        assert_eq!(seen, 2048, "CP-0238 vector count changed");
        eprintln!("CP-0238_VALID_PROPERTY=PASS cases={seen} deterministic_seed=0x{CP0238_VALID_SEED:016X}");
    }

    fn cp0238_mutate_invalid(state: &mut BoundaryStateV4, kind: usize, salt: u64, delta: u64) {
        match kind {
            0 => state.network_id = [0; 32],
            1 => state.manifest_id = [0; 32],
            2 => state.governance_config_hash = [0; 32],
            3 => state.recovery_policy_hash = [0; 32],
            4 => state.legacy_founder_beneficiary_id = [0; 32],
            5 => state.last_timestamp = 0,
            6 => {
                state.height = 0;
                state.last_timestamp = 1;
            }
            7 => state.roster_epoch = 0,
            8 => state.recovery_policy_epoch = 0,
            9 => state.proposer_nonce_highwater[(salt % 7) as usize] = 1,
            10 => state.pending_treasury_actions_count = 1,
            11 => state.pending_roster_transitions_count = 1,
            12 => state.miner_issued_atoms += 1,
            13 => {
                state.total_issued_atoms = ATOM_LIMIT + 1;
                state.miner_issued_atoms = state.total_issued_atoms
                    - state.founder_issued_atoms
                    - state.public_goods_issued_atoms.iter().sum::<u64>();
            }
            14 => state.total_burned_atoms = state.total_issued_atoms + 1,
            15 => state.accounts[0].balance_atoms += delta,
            16 => state.accounts.reverse(),
            17 => state.accounts[0].account_id = [0; 32],
            18 => {
                state.accounts.pop();
            }
            19 => state.accounts.push(state.accounts[0].clone()),
            20 => state.public_goods_issued_atoms[0] += 1,
            _ => panic!("unknown CP-0238 invalid case {kind}"),
        }
    }

    #[test]
    fn cp0238_1024_invalid_semantic_mutations_fail_closed() {
        let baseline = decode_fixture(BOUNDARY_FIXTURE);
        let mut rng = CP0238_INVALID_SEED;
        for index in 0..1024usize {
            let salt = cp0238_next_u64(&mut rng);
            let delta = salt % 1000 + 1;
            let kind = index % 21;
            let mut changed = baseline.clone();
            cp0238_mutate_invalid(&mut changed, kind, salt, delta);
            assert!(
                changed.validate().is_err(),
                "CP-0238 invalid mutation was accepted: index={index} kind={kind}"
            );
        }
        eprintln!("CP-0238_INVALID_MUTATIONS=PASS cases=1024 deterministic_seed=0x{CP0238_INVALID_SEED:016X}");
    }
}
