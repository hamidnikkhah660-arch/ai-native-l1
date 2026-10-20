//! CP-0218-S3T isolated, staged V3 transfer/issuance/treasury transition candidate.
//! No production hybrid-signature or Argon2id implementation is supplied here.
//! Callers must provide audited verifiers; this module is not wired into consensus.
use crate::v3_state_candidate::{AccountRecordV3, PendingProposalV3, StateLimits, StateV3};
use crate::v3_wire_candidate::{Ptb3, Txn3};
use sha2::{Digest, Sha256};

const GOV_SIGN: &[u8] = b"AIN1-GOV-SIGN-V3\0";
const GOV_PROPOSAL_ID: &[u8] = b"AIN1-GOV-PROPOSAL-ID-V3\0";
const GOV_APPROVAL: &[u8] = b"AIN1-GOV-APPROVAL-V3\0";
const GOV_SIGNER_ID: &[u8] = b"AIN1-GOV-SIGNER-ID-V3\0";
const INITIAL_MINER_SUBSIDY_ATOMS: u64 = 35_673_515_981;
const BLOCKS_PER_HALVING: u64 = 4_204_800;
const FOUNDER_CLIFF_BLOCKS: u64 = 1_051_200;
const FOUNDER_EPOCH_BLOCKS: u64 = 87_600;
const FOUNDER_EPOCHS: u64 = 48;
const TIMELOCK_BLOCKS: u64 = 20_160;
const EXECUTION_WINDOW_BLOCKS: u64 = 86_400;
const AUTH_SUITE_HYBRID: u16 = 3;
const HYBRID_SIGNATURE_BYTES: usize = 3_373;
const ED25519_SIGNATURE_BYTES: usize = 64;
const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1_952;
const MAX_TRANSACTIONS: usize = 1_024;
const MAX_ACTIONS: usize = 64;
const GOVERNANCE_SIGNERS: usize = 7;
const GOVERNANCE_THRESHOLD: u32 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionError {
    InvalidConfiguration,
    StateInvariant,
    InvalidBlock,
    WrongNetwork,
    WrongParent,
    WrongHeight,
    TimestampOrder,
    WrongTarget,
    InvalidProofOfWork,
    InvalidSignature(&'static str),
    InvalidTransaction(&'static str),
    InvalidGovernance(&'static str),
    Arithmetic,
    MissingSender,
    InsufficientBalance,
    AccountLimit,
    StateRootMismatch,
}

/// Cryptographic boundary for this candidate.
///
/// Production must implement both methods with reviewed ML-DSA-65 + Ed25519
/// verification and the exact manifest-pinned Argon2id profile. Tests use a
/// deterministic mock only; it is not cryptographic evidence.
pub trait V3TransitionVerifier {
    fn verify_hybrid_signature(
        &self,
        digest: &[u8; 32],
        ed25519_public_key: &[u8; 32],
        mldsa65_public_key: &[u8],
        ed25519_signature: &[u8],
        mldsa65_signature: &[u8],
    ) -> bool;

    fn argon2id_digest(&self, pow_preimage: &[u8]) -> Result<[u8; 32], TransitionError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceSignerV3 {
    pub signer_id: [u8; 32],
    pub ed25519_public_key: [u8; 32],
    pub mldsa65_public_key: Vec<u8>,
}

/// Candidate configuration copied from an already validated GNV3 manifest.
/// This type does not parse or authenticate GNV3 itself.
#[derive(Debug, Clone)]
pub struct TransitionConfigV3 {
    pub network_id: [u8; 32],
    pub manifest_id: [u8; 32],
    pub governance_config_hash: [u8; 32],
    pub founder_account_id: [u8; 32],
    pub limits: StateLimits,
    /// Must contain the seven manifest-bound entries in ascending signer_id order.
    pub governance_roster: Vec<GovernanceSignerV3>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedTransitionV3 {
    pub state: StateV3,
    pub body_tip_id: [u8; 32],
    pub consensus_tip_digest: [u8; 32],
    pub collected_fees_atoms: u64,
    pub miner_subsidy_atoms: u64,
    pub founder_vesting_delta_atoms: u64,
}

fn zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| *b == 0)
}

fn hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    h.finalize().into()
}

fn derive_governance_signer_id(ed: &[u8; 32], pq: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(GOV_SIGNER_ID);
    h.update(ed);
    h.update(pq);
    h.finalize().into()
}

fn fixed32(bytes: &[u8], start: usize) -> Result<[u8; 32], TransitionError> {
    let end = start.checked_add(32).ok_or(TransitionError::Arithmetic)?;
    let slice = bytes
        .get(start..end)
        .ok_or(TransitionError::InvalidGovernance("truncated field"))?;
    slice
        .try_into()
        .map_err(|_| TransitionError::InvalidGovernance("32-byte field"))
}

fn read_u64(bytes: &[u8], start: usize) -> Result<u64, TransitionError> {
    let end = start.checked_add(8).ok_or(TransitionError::Arithmetic)?;
    let slice = bytes
        .get(start..end)
        .ok_or(TransitionError::InvalidGovernance("truncated integer"))?;
    Ok(u64::from_be_bytes(slice.try_into().map_err(|_| {
        TransitionError::InvalidGovernance("u64 field")
    })?))
}

fn validate_config(cfg: &TransitionConfigV3) -> Result<(), TransitionError> {
    let expected = StateLimits::default();
    if zero(&cfg.network_id)
        || zero(&cfg.manifest_id)
        || zero(&cfg.governance_config_hash)
        || zero(&cfg.founder_account_id)
        || cfg.limits.total_supply_atoms != expected.total_supply_atoms
        || cfg.limits.miner_budget_atoms != expected.miner_budget_atoms
        || cfg.limits.founder_budget_atoms != expected.founder_budget_atoms
        || cfg.limits.public_goods_budgets_atoms != expected.public_goods_budgets_atoms
        || cfg.limits.max_accounts != expected.max_accounts
        || cfg.limits.max_pending_proposals != expected.max_pending_proposals
        || cfg.limits.max_snapshot_bytes != expected.max_snapshot_bytes
        || cfg.governance_roster.len() != GOVERNANCE_SIGNERS
    {
        return Err(TransitionError::InvalidConfiguration);
    }
    let mut previous: Option<[u8; 32]> = None;
    for signer in &cfg.governance_roster {
        if zero(&signer.signer_id)
            || zero(&signer.ed25519_public_key)
            || signer.mldsa65_public_key.len() != ML_DSA_65_PUBLIC_KEY_BYTES
            || zero(&signer.mldsa65_public_key)
            || derive_governance_signer_id(&signer.ed25519_public_key, &signer.mldsa65_public_key)
                != signer.signer_id
            || previous.is_some_and(|p| p >= signer.signer_id)
        {
            return Err(TransitionError::InvalidConfiguration);
        }
        previous = Some(signer.signer_id);
    }
    Ok(())
}

fn credit(
    state: &mut StateV3,
    account_id: [u8; 32],
    amount: u64,
    limits: &StateLimits,
) -> Result<(), TransitionError> {
    if zero(&account_id) {
        return Err(TransitionError::InvalidBlock);
    }
    if amount == 0 {
        return Ok(());
    }
    match state
        .accounts
        .binary_search_by(|a| a.account_id.cmp(&account_id))
    {
        Ok(i) => {
            state.accounts[i].balance_atoms = state.accounts[i]
                .balance_atoms
                .checked_add(amount)
                .ok_or(TransitionError::Arithmetic)?;
        }
        Err(i) => {
            if state.accounts.len() >= limits.max_accounts {
                return Err(TransitionError::AccountLimit);
            }
            state.accounts.insert(
                i,
                AccountRecordV3 {
                    account_id,
                    balance_atoms: amount,
                    nonce: 0,
                },
            );
        }
    }
    Ok(())
}

fn execute_transaction<V: V3TransitionVerifier>(
    state: &mut StateV3,
    tx: &Txn3,
    block_timestamp: u64,
    limits: &StateLimits,
    verifier: &V,
) -> Result<u128, TransitionError> {
    tx.encode()
        .map_err(|_| TransitionError::InvalidTransaction("non-canonical TXN3"))?;
    if tx.network_id != state.network_id {
        return Err(TransitionError::WrongNetwork);
    }
    if tx.expires_at <= block_timestamp {
        return Err(TransitionError::InvalidTransaction("exclusive expiry"));
    }
    let digest = tx
        .signing_digest()
        .map_err(|_| TransitionError::InvalidTransaction("signing digest"))?;
    if !verifier.verify_hybrid_signature(&digest, &tx.ed_pk, &tx.pq_pk, &tx.ed_sig, &tx.pq_sig) {
        return Err(TransitionError::InvalidSignature("TXN3"));
    }
    let i = state
        .accounts
        .binary_search_by(|a| a.account_id.cmp(&tx.sender_id))
        .map_err(|_| TransitionError::MissingSender)?;
    let expected_nonce = state.accounts[i]
        .nonce
        .checked_add(1)
        .ok_or(TransitionError::Arithmetic)?;
    if tx.nonce != expected_nonce {
        return Err(TransitionError::InvalidTransaction("nonce"));
    }
    let debit = u128::from(tx.amount_atoms)
        .checked_add(u128::from(tx.fee_atoms))
        .ok_or(TransitionError::Arithmetic)?;
    if u128::from(state.accounts[i].balance_atoms) < debit {
        return Err(TransitionError::InsufficientBalance);
    }
    state.accounts[i].balance_atoms =
        u64::try_from(u128::from(state.accounts[i].balance_atoms) - debit)
            .map_err(|_| TransitionError::Arithmetic)?;
    state.accounts[i].nonce = tx.nonce;
    credit(state, tx.recipient_id, tx.amount_atoms, limits)?;
    Ok(u128::from(tx.fee_atoms))
}

fn miner_subsidy(
    height: u64,
    state: &StateV3,
    limits: &StateLimits,
) -> Result<u64, TransitionError> {
    let index = height.checked_sub(1).ok_or(TransitionError::WrongHeight)?;
    let era = index / BLOCKS_PER_HALVING;
    let nominal = if era >= 64 {
        0
    } else {
        INITIAL_MINER_SUBSIDY_ATOMS >> era
    };
    let miner_remaining = limits
        .miner_budget_atoms
        .checked_sub(state.miner_issued_atoms)
        .ok_or(TransitionError::StateInvariant)?;
    let global_remaining = limits
        .total_supply_atoms
        .checked_sub(state.total_issued_atoms)
        .ok_or(TransitionError::StateInvariant)?;
    Ok(nominal.min(miner_remaining).min(global_remaining))
}

fn founder_due(height: u64, limits: &StateLimits) -> Result<u64, TransitionError> {
    let index = height.checked_sub(1).ok_or(TransitionError::WrongHeight)?;
    let periods = if index < FOUNDER_CLIFF_BLOCKS {
        0
    } else {
        ((index - FOUNDER_CLIFF_BLOCKS) / FOUNDER_EPOCH_BLOCKS).min(FOUNDER_EPOCHS)
    };
    let due = u128::from(limits.founder_budget_atoms)
        .checked_mul(u128::from(periods))
        .ok_or(TransitionError::Arithmetic)?
        / u128::from(FOUNDER_EPOCHS);
    u64::try_from(due).map_err(|_| TransitionError::Arithmetic)
}

fn roster_index(cfg: &TransitionConfigV3, id: &[u8; 32]) -> Result<usize, TransitionError> {
    cfg.governance_roster
        .binary_search_by(|s| s.signer_id.cmp(id))
        .map_err(|_| TransitionError::InvalidGovernance("signer not in manifest roster"))
}

fn verify_action_signature<V: V3TransitionVerifier>(
    verifier: &V,
    signer: &GovernanceSignerV3,
    digest: [u8; 32],
    action: &[u8],
    signature_start: usize,
) -> Result<(), TransitionError> {
    let ed_end = signature_start
        .checked_add(ED25519_SIGNATURE_BYTES)
        .ok_or(TransitionError::Arithmetic)?;
    let sig_end = signature_start
        .checked_add(HYBRID_SIGNATURE_BYTES)
        .ok_or(TransitionError::Arithmetic)?;
    let ed_sig = action
        .get(signature_start..ed_end)
        .ok_or(TransitionError::InvalidGovernance(
            "truncated Ed25519 signature",
        ))?;
    let pq_sig = action
        .get(ed_end..sig_end)
        .ok_or(TransitionError::InvalidGovernance(
            "truncated ML-DSA-65 signature",
        ))?;
    if !verifier.verify_hybrid_signature(
        &digest,
        &signer.ed25519_public_key,
        &signer.mldsa65_public_key,
        ed_sig,
        pq_sig,
    ) {
        return Err(TransitionError::InvalidSignature("governance action"));
    }
    Ok(())
}

fn execute_gpr<V: V3TransitionVerifier>(
    state: &mut StateV3,
    cfg: &TransitionConfigV3,
    action: &[u8],
    height: u64,
    verifier: &V,
) -> Result<(), TransitionError> {
    if action.len() != 3_528
        || &action[..4] != b"GPR3"
        || u16::from_be_bytes([action[151], action[152]]) != AUTH_SUITE_HYBRID
        || u16::from_be_bytes([action[153], action[154]]) as usize != HYBRID_SIGNATURE_BYTES
    {
        return Err(TransitionError::InvalidGovernance("GPR3 framing"));
    }
    if fixed32(action, 6)? != cfg.governance_config_hash {
        return Err(TransitionError::InvalidGovernance("GPR3 governance config"));
    }
    let signer_id = fixed32(action, 38)?;
    let signer_i = roster_index(cfg, &signer_id)?;
    let nonce = read_u64(action, 70)?;
    let expected_nonce = state.proposer_nonce_highwater[signer_i]
        .checked_add(1)
        .ok_or(TransitionError::Arithmetic)?;
    if nonce != expected_nonce {
        return Err(TransitionError::InvalidGovernance("GPR3 proposer nonce"));
    }
    let digest = hash(GOV_SIGN, &action[..153]);
    verify_action_signature(
        verifier,
        &cfg.governance_roster[signer_i],
        digest,
        action,
        155,
    )?;

    let bucket_id = action[78];
    let recipient_id = fixed32(action, 79)?;
    let amount_atoms = read_u64(action, 111)?;
    let rationale_hash = fixed32(action, 119)?;
    if !(1..=6).contains(&bucket_id) || zero(&recipient_id) || amount_atoms == 0 {
        return Err(TransitionError::InvalidGovernance("GPR3 fields"));
    }
    let mut proposal_preimage = action[..153].to_vec();
    proposal_preimage.extend_from_slice(&height.to_be_bytes());
    let proposal_id = hash(GOV_PROPOSAL_ID, &proposal_preimage);
    if state.pending_proposals.len() >= cfg.limits.max_pending_proposals
        || state
            .pending_proposals
            .binary_search_by(|p| p.proposal_id.cmp(&proposal_id))
            .is_ok()
    {
        return Err(TransitionError::InvalidGovernance(
            "GPR3 proposal limit/duplicate",
        ));
    }
    let not_before_height = height
        .checked_add(TIMELOCK_BLOCKS)
        .ok_or(TransitionError::Arithmetic)?;
    let expires_height = not_before_height
        .checked_add(EXECUTION_WINDOW_BLOCKS)
        .ok_or(TransitionError::Arithmetic)?;
    let proposal = PendingProposalV3 {
        proposal_id,
        proposer_signer_id: signer_id,
        proposer_nonce: nonce,
        bucket_id,
        recipient_id,
        amount_atoms,
        rationale_hash,
        submitted_height: height,
        not_before_height,
        expires_height,
        approval_bitmap: 1u8
            .checked_shl(signer_i as u32)
            .ok_or(TransitionError::Arithmetic)?,
    };
    proposal
        .validate()
        .map_err(|_| TransitionError::InvalidGovernance("GPR3 proposal invariant"))?;
    state.proposer_nonce_highwater[signer_i] = nonce;
    let insertion = state
        .pending_proposals
        .binary_search_by(|p| p.proposal_id.cmp(&proposal_id))
        .unwrap_err();
    state.pending_proposals.insert(insertion, proposal);
    Ok(())
}

fn execute_gap<V: V3TransitionVerifier>(
    state: &mut StateV3,
    cfg: &TransitionConfigV3,
    action: &[u8],
    height: u64,
    verifier: &V,
) -> Result<(), TransitionError> {
    if action.len() != 3_479
        || &action[..4] != b"GAP3"
        || u16::from_be_bytes([action[102], action[103]]) != AUTH_SUITE_HYBRID
        || u16::from_be_bytes([action[104], action[105]]) as usize != HYBRID_SIGNATURE_BYTES
    {
        return Err(TransitionError::InvalidGovernance("GAP3 framing"));
    }
    if fixed32(action, 6)? != cfg.governance_config_hash {
        return Err(TransitionError::InvalidGovernance("GAP3 governance config"));
    }
    let proposal_id = fixed32(action, 38)?;
    let signer_id = fixed32(action, 70)?;
    let signer_i = roster_index(cfg, &signer_id)?;
    let digest = hash(GOV_APPROVAL, &action[..104]);
    verify_action_signature(
        verifier,
        &cfg.governance_roster[signer_i],
        digest,
        action,
        106,
    )?;
    let proposal_i = state
        .pending_proposals
        .binary_search_by(|p| p.proposal_id.cmp(&proposal_id))
        .map_err(|_| TransitionError::InvalidGovernance("GAP3 proposal absent"))?;
    let proposal = &mut state.pending_proposals[proposal_i];
    if proposal.expires_height < height {
        return Err(TransitionError::InvalidGovernance("GAP3 expired proposal"));
    }
    let bit = 1u8
        .checked_shl(signer_i as u32)
        .ok_or(TransitionError::Arithmetic)?;
    if proposal.approval_bitmap & bit != 0 {
        return Err(TransitionError::InvalidGovernance(
            "GAP3 duplicate approval",
        ));
    }
    proposal.approval_bitmap |= bit;
    Ok(())
}

fn execute_gex(
    state: &mut StateV3,
    cfg: &TransitionConfigV3,
    action: &[u8],
    height: u64,
) -> Result<(), TransitionError> {
    if action.len() != 70 || &action[..4] != b"GEX3" {
        return Err(TransitionError::InvalidGovernance("GEX3 framing"));
    }
    if fixed32(action, 6)? != cfg.governance_config_hash {
        return Err(TransitionError::InvalidGovernance("GEX3 governance config"));
    }
    let proposal_id = fixed32(action, 38)?;
    let i = state
        .pending_proposals
        .binary_search_by(|p| p.proposal_id.cmp(&proposal_id))
        .map_err(|_| TransitionError::InvalidGovernance("GEX3 proposal absent/already executed"))?;
    let proposal = state.pending_proposals[i].clone();
    if proposal.approval_bitmap.count_ones() < GOVERNANCE_THRESHOLD
        || height < proposal.not_before_height
        || height > proposal.expires_height
        || zero(&proposal.recipient_id)
        || proposal.amount_atoms == 0
    {
        return Err(TransitionError::InvalidGovernance(
            "GEX3 threshold/timelock/window",
        ));
    }
    let bucket_i = usize::from(
        proposal
            .bucket_id
            .checked_sub(1)
            .ok_or(TransitionError::InvalidGovernance("GEX3 bucket"))?,
    );
    if bucket_i >= 6 {
        return Err(TransitionError::InvalidGovernance("GEX3 bucket"));
    }
    let bucket_total = state.public_goods_issued_atoms[bucket_i]
        .checked_add(proposal.amount_atoms)
        .ok_or(TransitionError::Arithmetic)?;
    if bucket_total > cfg.limits.public_goods_budgets_atoms[bucket_i]
        || state
            .total_issued_atoms
            .checked_add(proposal.amount_atoms)
            .ok_or(TransitionError::Arithmetic)?
            > cfg.limits.total_supply_atoms
    {
        return Err(TransitionError::InvalidGovernance("GEX3 budget exceeded"));
    }
    state.public_goods_issued_atoms[bucket_i] = bucket_total;
    state.total_issued_atoms = state
        .total_issued_atoms
        .checked_add(proposal.amount_atoms)
        .ok_or(TransitionError::Arithmetic)?;
    credit(
        state,
        proposal.recipient_id,
        proposal.amount_atoms,
        &cfg.limits,
    )?;
    state.pending_proposals.remove(i);
    Ok(())
}

/// Apply a candidate PTB3 as an all-or-nothing staged state transition.
///
/// This verifies encoding, branch linkage, a caller-supplied expected target,
/// verifier-supplied hybrid signatures and verifier-supplied Argon2id output.
/// It does not validate the full branch difficulty history or production time
/// policy, parse/authenticate GNV3, persist state, or perform reorg recovery.
pub fn apply_block<V: V3TransitionVerifier>(
    parent: &StateV3,
    parent_body_tip_id: [u8; 32],
    parent_consensus_tip_digest: [u8; 32],
    block: &Ptb3,
    expected_target: [u8; 32],
    cfg: &TransitionConfigV3,
    verifier: &V,
) -> Result<AppliedTransitionV3, TransitionError> {
    validate_config(cfg)?;
    parent
        .validate(&cfg.limits)
        .map_err(|_| TransitionError::StateInvariant)?;
    if parent.network_id != cfg.network_id
        || parent.manifest_id != cfg.manifest_id
        || parent.governance_config_hash != cfg.governance_config_hash
    {
        return Err(TransitionError::WrongNetwork);
    }
    if block.network_id != cfg.network_id || block.body.network_id != cfg.network_id {
        return Err(TransitionError::WrongNetwork);
    }
    if block.height
        != parent
            .height
            .checked_add(1)
            .ok_or(TransitionError::Arithmetic)?
    {
        return Err(TransitionError::WrongHeight);
    }
    if block.timestamp <= parent.last_timestamp {
        return Err(TransitionError::TimestampOrder);
    }
    if block.parent_body_id != parent_body_tip_id
        || block.body.parent_body_id != parent_body_tip_id
        || block.previous_consensus_hash != parent_consensus_tip_digest
    {
        return Err(TransitionError::WrongParent);
    }
    if zero(&block.reward_beneficiary_id)
        || zero(&expected_target)
        || block.target != expected_target
    {
        return Err(TransitionError::WrongTarget);
    }
    if block.body.transactions.len() > MAX_TRANSACTIONS || block.body.actions.len() > MAX_ACTIONS {
        return Err(TransitionError::InvalidBlock);
    }
    // Codec validation includes count/length ceilings and canonical GPR3/GAP3/GEX3 ordering.
    block.encode().map_err(|_| TransitionError::InvalidBlock)?;
    let pow_preimage = block
        .pow_preimage()
        .map_err(|_| TransitionError::InvalidBlock)?;
    let pow_digest = verifier.argon2id_digest(&pow_preimage)?;
    if pow_digest > block.target {
        return Err(TransitionError::InvalidProofOfWork);
    }

    let height = block.height;
    let mut staged = parent.clone();
    staged.height = height;
    staged.last_timestamp = block.timestamp;
    staged
        .pending_proposals
        .retain(|p| p.expires_height >= height);

    let mut fee_sum: u128 = 0;
    for tx in &block.body.transactions {
        fee_sum = fee_sum
            .checked_add(execute_transaction(
                &mut staged,
                tx,
                block.timestamp,
                &cfg.limits,
                verifier,
            )?)
            .ok_or(TransitionError::Arithmetic)?;
    }
    let collected_fees_atoms = u64::try_from(fee_sum).map_err(|_| TransitionError::Arithmetic)?;
    credit(
        &mut staged,
        block.reward_beneficiary_id,
        collected_fees_atoms,
        &cfg.limits,
    )?;

    let miner_subsidy_atoms = miner_subsidy(height, &staged, &cfg.limits)?;
    staged.miner_issued_atoms = staged
        .miner_issued_atoms
        .checked_add(miner_subsidy_atoms)
        .ok_or(TransitionError::Arithmetic)?;
    staged.total_issued_atoms = staged
        .total_issued_atoms
        .checked_add(miner_subsidy_atoms)
        .ok_or(TransitionError::Arithmetic)?;
    credit(
        &mut staged,
        block.reward_beneficiary_id,
        miner_subsidy_atoms,
        &cfg.limits,
    )?;

    let due = founder_due(height, &cfg.limits)?;
    if staged.founder_issued_atoms > due {
        return Err(TransitionError::StateInvariant);
    }
    let founder_vesting_delta_atoms = due - staged.founder_issued_atoms;
    let remaining_global = cfg
        .limits
        .total_supply_atoms
        .checked_sub(staged.total_issued_atoms)
        .ok_or(TransitionError::StateInvariant)?;
    let remaining_founder = cfg
        .limits
        .founder_budget_atoms
        .checked_sub(staged.founder_issued_atoms)
        .ok_or(TransitionError::StateInvariant)?;
    if founder_vesting_delta_atoms > remaining_global
        || founder_vesting_delta_atoms > remaining_founder
    {
        return Err(TransitionError::StateInvariant);
    }
    staged.founder_issued_atoms = staged
        .founder_issued_atoms
        .checked_add(founder_vesting_delta_atoms)
        .ok_or(TransitionError::Arithmetic)?;
    staged.total_issued_atoms = staged
        .total_issued_atoms
        .checked_add(founder_vesting_delta_atoms)
        .ok_or(TransitionError::Arithmetic)?;
    credit(
        &mut staged,
        cfg.founder_account_id,
        founder_vesting_delta_atoms,
        &cfg.limits,
    )?;

    for action in block.body.actions.iter().filter(|a| a.starts_with(b"GPR3")) {
        execute_gpr(&mut staged, cfg, action, height, verifier)?;
    }
    for action in block.body.actions.iter().filter(|a| a.starts_with(b"GAP3")) {
        execute_gap(&mut staged, cfg, action, height, verifier)?;
    }
    for action in block.body.actions.iter().filter(|a| a.starts_with(b"GEX3")) {
        execute_gex(&mut staged, cfg, action, height)?;
    }

    staged
        .validate(&cfg.limits)
        .map_err(|_| TransitionError::StateInvariant)?;
    let calculated_root = staged
        .state_root(&cfg.limits)
        .map_err(|_| TransitionError::StateInvariant)?;
    if calculated_root != block.body.post_state_root || calculated_root != block.post_state_root {
        return Err(TransitionError::StateRootMismatch);
    }
    let body_tip_id = block
        .body
        .body_id()
        .map_err(|_| TransitionError::InvalidBlock)?;
    Ok(AppliedTransitionV3 {
        state: staged,
        body_tip_id,
        consensus_tip_digest: pow_digest,
        collected_fees_atoms,
        miner_subsidy_atoms,
        founder_vesting_delta_atoms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v3_wire_candidate::{derive_account_id, Block3, Ptb3, Txn3};

    struct MockVerifier {
        signatures_valid: bool,
        pow_digest: [u8; 32],
    }
    impl V3TransitionVerifier for MockVerifier {
        fn verify_hybrid_signature(
            &self,
            _digest: &[u8; 32],
            _ed_pk: &[u8; 32],
            pq_pk: &[u8],
            ed_sig: &[u8],
            pq_sig: &[u8],
        ) -> bool {
            self.signatures_valid
                && pq_pk.len() == ML_DSA_65_PUBLIC_KEY_BYTES
                && ed_sig == vec![0xA5; ED25519_SIGNATURE_BYTES]
                && pq_sig == vec![0x5A; HYBRID_SIGNATURE_BYTES - ED25519_SIGNATURE_BYTES]
        }
        fn argon2id_digest(&self, _preimage: &[u8]) -> Result<[u8; 32], TransitionError> {
            Ok(self.pow_digest)
        }
    }

    fn roster() -> Vec<GovernanceSignerV3> {
        let mut entries = (1u8..=7)
            .map(|n| {
                let ed = [n; 32];
                let pq = vec![n.wrapping_add(16); ML_DSA_65_PUBLIC_KEY_BYTES];
                GovernanceSignerV3 {
                    signer_id: derive_governance_signer_id(&ed, &pq),
                    ed25519_public_key: ed,
                    mldsa65_public_key: pq,
                }
            })
            .collect::<Vec<_>>();
        entries.sort_by_key(|s| s.signer_id);
        entries
    }

    fn config() -> TransitionConfigV3 {
        TransitionConfigV3 {
            network_id: [1; 32],
            manifest_id: [2; 32],
            governance_config_hash: [3; 32],
            founder_account_id: [0x66; 32],
            limits: StateLimits::default(),
            governance_roster: roster(),
        }
    }

    fn parent(height: u64, timestamp: u64) -> StateV3 {
        let ed = [0x11; 32];
        let pq = vec![0x22; ML_DSA_65_PUBLIC_KEY_BYTES];
        let sender = derive_account_id(&ed, &pq).unwrap();
        StateV3 {
            network_id: [1; 32],
            height,
            last_timestamp: timestamp,
            manifest_id: [2; 32],
            governance_config_hash: [3; 32],
            total_issued_atoms: 1_000,
            miner_issued_atoms: 1_000,
            founder_issued_atoms: 0,
            public_goods_issued_atoms: [0; 6],
            total_burned_atoms: 0,
            proposer_nonce_highwater: [0; 7],
            accounts: vec![AccountRecordV3 {
                account_id: sender,
                balance_atoms: 1_000,
                nonce: 0,
            }],
            pending_proposals: vec![],
        }
    }

    fn txn(cfg: &TransitionConfigV3) -> Txn3 {
        let ed_pk = [0x11; 32];
        let pq_pk = vec![0x22; ML_DSA_65_PUBLIC_KEY_BYTES];
        Txn3 {
            network_id: cfg.network_id,
            sender_id: derive_account_id(&ed_pk, &pq_pk).unwrap(),
            recipient_id: [0x22; 32],
            nonce: 1,
            amount_atoms: 100,
            fee_atoms: 10,
            expires_at: 500,
            ed_pk,
            pq_pk,
            ed_sig: vec![0xA5; ED25519_SIGNATURE_BYTES],
            pq_sig: vec![0x5A; HYBRID_SIGNATURE_BYTES - ED25519_SIGNATURE_BYTES],
        }
    }

    fn block(
        cfg: &TransitionConfigV3,
        height: u64,
        timestamp: u64,
        root: [u8; 32],
        transactions: Vec<Txn3>,
        actions: Vec<Vec<u8>>,
    ) -> Ptb3 {
        let body = Block3 {
            network_id: cfg.network_id,
            height,
            timestamp,
            parent_body_id: [0x44; 32],
            post_state_root: root,
            transactions,
            actions,
        };
        Ptb3 {
            network_id: cfg.network_id,
            height,
            timestamp,
            parent_body_id: [0x44; 32],
            previous_consensus_hash: [0x55; 32],
            post_state_root: root,
            target: [0xFF; 32],
            nonce: 7,
            reward_beneficiary_id: [0x33; 32],
            body,
        }
    }

    fn oracle_root() -> [u8; 32] {
        let line = include_str!("../../../../simulations/cp0218_v3_transition_vectors.tsv")
            .lines()
            .find(|l| l.starts_with("post_state_root_hex\t"))
            .expect("root fixture");
        let hex = line.split_once('\t').unwrap().1.trim();
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>();
        bytes.try_into().unwrap()
    }

    #[test]
    fn transfer_fees_and_miner_issuance_match_independent_python_root() {
        let cfg = config();
        let parent = parent(1, 100);
        let tx = txn(&cfg);
        let b = block(&cfg, 2, 120, oracle_root(), vec![tx], vec![]);
        let result = apply_block(
            &parent,
            [0x44; 32],
            [0x55; 32],
            &b,
            [0xFF; 32],
            &cfg,
            &MockVerifier {
                signatures_valid: true,
                pow_digest: [0; 32],
            },
        )
        .unwrap();
        let sender =
            derive_account_id(&[0x11; 32], &vec![0x22; ML_DSA_65_PUBLIC_KEY_BYTES]).unwrap();
        assert_eq!(result.collected_fees_atoms, 10);
        assert_eq!(result.miner_subsidy_atoms, INITIAL_MINER_SUBSIDY_ATOMS);
        assert_eq!(result.founder_vesting_delta_atoms, 0);
        assert_eq!(result.state.total_issued_atoms, 35_673_516_981);
        assert_eq!(result.state.miner_issued_atoms, 35_673_516_981);
        assert_eq!(
            result
                .state
                .accounts
                .iter()
                .find(|a| a.account_id == sender)
                .unwrap()
                .balance_atoms,
            890
        );
        assert_eq!(
            result
                .state
                .accounts
                .iter()
                .find(|a| a.account_id == [0x22; 32])
                .unwrap()
                .balance_atoms,
            100
        );
        assert_eq!(
            result
                .state
                .accounts
                .iter()
                .find(|a| a.account_id == [0x33; 32])
                .unwrap()
                .balance_atoms,
            35_673_515_991
        );
        assert_eq!(result.state.state_root(&cfg.limits).unwrap(), oracle_root());
        assert_eq!(result.consensus_tip_digest, [0; 32]);
    }

    #[test]
    fn invalid_signature_and_over_target_pow_fail_without_mutating_parent() {
        let cfg = config();
        let parent = parent(1, 100);
        let original = parent.clone();
        let good_root = oracle_root();
        let b = block(&cfg, 2, 120, good_root, vec![txn(&cfg)], vec![]);
        assert_eq!(
            apply_block(
                &parent,
                [0x44; 32],
                [0x55; 32],
                &b,
                [0xFF; 32],
                &cfg,
                &MockVerifier {
                    signatures_valid: false,
                    pow_digest: [0; 32]
                }
            ),
            Err(TransitionError::InvalidSignature("TXN3")),
        );
        assert_eq!(parent, original);
        let mut bad_pow_block = b.clone();
        bad_pow_block.target = [0x7F; 32];
        assert_eq!(
            apply_block(
                &parent,
                [0x44; 32],
                [0x55; 32],
                &bad_pow_block,
                [0x7F; 32],
                &cfg,
                &MockVerifier {
                    signatures_valid: true,
                    pow_digest: [0x80; 32]
                }
            ),
            Err(TransitionError::InvalidProofOfWork),
        );
        assert_eq!(parent, original);
    }

    fn signed_gpr(
        cfg: &TransitionConfigV3,
        signer_i: usize,
        nonce: u64,
        bucket: u8,
        recipient: [u8; 32],
        amount: u64,
    ) -> Vec<u8> {
        let s = &cfg.governance_roster[signer_i];
        let mut a = Vec::new();
        a.extend_from_slice(b"GPR3");
        a.extend_from_slice(&3u16.to_be_bytes());
        a.extend_from_slice(&cfg.governance_config_hash);
        a.extend_from_slice(&s.signer_id);
        a.extend_from_slice(&nonce.to_be_bytes());
        a.push(bucket);
        a.extend_from_slice(&recipient);
        a.extend_from_slice(&amount.to_be_bytes());
        a.extend_from_slice(&[0x77; 32]);
        a.extend_from_slice(&AUTH_SUITE_HYBRID.to_be_bytes());
        assert_eq!(a.len(), 153);
        a.extend_from_slice(&(HYBRID_SIGNATURE_BYTES as u16).to_be_bytes());
        a.extend_from_slice(&vec![0xA5; ED25519_SIGNATURE_BYTES]);
        a.extend_from_slice(&vec![
            0x5A;
            HYBRID_SIGNATURE_BYTES - ED25519_SIGNATURE_BYTES
        ]);
        a
    }

    fn signed_gap(cfg: &TransitionConfigV3, proposal_id: [u8; 32], signer_i: usize) -> Vec<u8> {
        let s = &cfg.governance_roster[signer_i];
        let mut a = Vec::new();
        a.extend_from_slice(b"GAP3");
        a.extend_from_slice(&3u16.to_be_bytes());
        a.extend_from_slice(&cfg.governance_config_hash);
        a.extend_from_slice(&proposal_id);
        a.extend_from_slice(&s.signer_id);
        a.extend_from_slice(&AUTH_SUITE_HYBRID.to_be_bytes());
        assert_eq!(a.len(), 104);
        a.extend_from_slice(&(HYBRID_SIGNATURE_BYTES as u16).to_be_bytes());
        a.extend_from_slice(&vec![0xA5; ED25519_SIGNATURE_BYTES]);
        a.extend_from_slice(&vec![
            0x5A;
            HYBRID_SIGNATURE_BYTES - ED25519_SIGNATURE_BYTES
        ]);
        a
    }

    fn gex(proposal_id: [u8; 32], cfg: &TransitionConfigV3) -> Vec<u8> {
        let mut a = Vec::new();
        a.extend_from_slice(b"GEX3");
        a.extend_from_slice(&3u16.to_be_bytes());
        a.extend_from_slice(&cfg.governance_config_hash);
        a.extend_from_slice(&proposal_id);
        a
    }

    #[test]
    fn proposal_and_approval_phase_updates_nonce_and_bitmap() {
        let cfg = config();
        let parent = parent(1, 100);
        let gpr = signed_gpr(&cfg, 0, 1, 2, [0x77; 32], 100);
        let mut id_preimage = gpr[..153].to_vec();
        id_preimage.extend_from_slice(&2u64.to_be_bytes());
        let proposal_id = hash(GOV_PROPOSAL_ID, &id_preimage);
        let gap = signed_gap(&cfg, proposal_id, 1);
        let mut expected = parent.clone();
        expected.height = 2;
        expected.last_timestamp = 120;
        expected.total_issued_atoms += INITIAL_MINER_SUBSIDY_ATOMS;
        expected.miner_issued_atoms += INITIAL_MINER_SUBSIDY_ATOMS;
        credit(
            &mut expected,
            [0x33; 32],
            INITIAL_MINER_SUBSIDY_ATOMS,
            &cfg.limits,
        )
        .unwrap();
        let not_before = 2 + TIMELOCK_BLOCKS;
        let expires = not_before + EXECUTION_WINDOW_BLOCKS;
        expected.proposer_nonce_highwater[cfg
            .governance_roster
            .binary_search_by(|s| s.signer_id.cmp(&cfg.governance_roster[0].signer_id))
            .unwrap()] = 1;
        let proposer_index = roster_index(&cfg, &cfg.governance_roster[0].signer_id).unwrap();
        let approver_index = roster_index(&cfg, &cfg.governance_roster[1].signer_id).unwrap();
        expected.pending_proposals.push(PendingProposalV3 {
            proposal_id,
            proposer_signer_id: cfg.governance_roster[0].signer_id,
            proposer_nonce: 1,
            bucket_id: 2,
            recipient_id: [0x77; 32],
            amount_atoms: 100,
            rationale_hash: [0x77; 32],
            submitted_height: 2,
            not_before_height: not_before,
            expires_height: expires,
            approval_bitmap: (1 << proposer_index) | (1 << approver_index),
        });
        expected.pending_proposals.sort_by_key(|p| p.proposal_id);
        let root = expected.state_root(&cfg.limits).unwrap();
        let b = block(&cfg, 2, 120, root, vec![], vec![gpr, gap]);
        let out = apply_block(
            &parent,
            [0x44; 32],
            [0x55; 32],
            &b,
            [0xFF; 32],
            &cfg,
            &MockVerifier {
                signatures_valid: true,
                pow_digest: [0; 32],
            },
        )
        .unwrap();
        assert_eq!(out.state, expected);
        assert_eq!(
            out.state.pending_proposals[0].approval_bitmap.count_ones(),
            2
        );
        assert_eq!(out.state.proposer_nonce_highwater[proposer_index], 1);
    }

    #[test]
    fn treasury_execution_requires_four_approvals_and_timelock_then_credits_recipient() {
        let cfg = config();
        let mut p = parent(TIMELOCK_BLOCKS, 200);
        let recipient = [0x77; 32];
        let proposal = PendingProposalV3 {
            proposal_id: [0x88; 32],
            proposer_signer_id: cfg.governance_roster[0].signer_id,
            proposer_nonce: 1,
            bucket_id: 2,
            recipient_id: recipient,
            amount_atoms: 100,
            rationale_hash: [0x99; 32],
            submitted_height: 1,
            not_before_height: 1 + TIMELOCK_BLOCKS,
            expires_height: 1 + TIMELOCK_BLOCKS + EXECUTION_WINDOW_BLOCKS,
            approval_bitmap: 0x0F,
        };
        p.pending_proposals = vec![proposal.clone()];
        let mut expected = p.clone();
        expected.height += 1;
        expected.last_timestamp += 1;
        expected.total_issued_atoms += INITIAL_MINER_SUBSIDY_ATOMS + 100;
        expected.miner_issued_atoms += INITIAL_MINER_SUBSIDY_ATOMS;
        expected.public_goods_issued_atoms[1] += 100;
        credit(
            &mut expected,
            [0x33; 32],
            INITIAL_MINER_SUBSIDY_ATOMS,
            &cfg.limits,
        )
        .unwrap();
        credit(&mut expected, recipient, 100, &cfg.limits).unwrap();
        expected.pending_proposals.clear();
        let root = expected.state_root(&cfg.limits).unwrap();
        let b = block(
            &cfg,
            p.height + 1,
            p.last_timestamp + 1,
            root,
            vec![],
            vec![gex(proposal.proposal_id, &cfg)],
        );
        let out = apply_block(
            &p,
            [0x44; 32],
            [0x55; 32],
            &b,
            [0xFF; 32],
            &cfg,
            &MockVerifier {
                signatures_valid: true,
                pow_digest: [0; 32],
            },
        )
        .unwrap();
        assert_eq!(out.state, expected);
        assert_eq!(out.state.public_goods_issued_atoms[1], 100);
        assert_eq!(
            out.state
                .accounts
                .iter()
                .find(|a| a.account_id == recipient)
                .unwrap()
                .balance_atoms,
            100
        );

        p.pending_proposals[0].approval_bitmap = 0x07;
        let invalid = block(
            &cfg,
            p.height + 1,
            p.last_timestamp + 1,
            [0; 32],
            vec![],
            vec![gex(proposal.proposal_id, &cfg)],
        );
        let before = p.clone();
        assert_eq!(
            apply_block(
                &p,
                [0x44; 32],
                [0x55; 32],
                &invalid,
                [0xFF; 32],
                &cfg,
                &MockVerifier {
                    signatures_valid: true,
                    pow_digest: [0; 32]
                }
            ),
            Err(TransitionError::InvalidGovernance(
                "GEX3 threshold/timelock/window"
            )),
        );
        assert_eq!(p, before);
    }

    #[test]
    fn transaction_expiry_is_exclusive_and_nonce_replay_rejects() {
        let cfg = config();
        let parent = parent(1, 100);
        let original = parent.clone();
        let mut expired_tx = txn(&cfg);
        expired_tx.expires_at = 120;
        let expired_block = block(&cfg, 2, 120, [0; 32], vec![expired_tx], vec![]);
        assert_eq!(
            apply_block(
                &parent,
                [0x44; 32],
                [0x55; 32],
                &expired_block,
                [0xFF; 32],
                &cfg,
                &MockVerifier {
                    signatures_valid: true,
                    pow_digest: [0; 32],
                },
            ),
            Err(TransitionError::InvalidTransaction("exclusive expiry")),
        );

        let mut replay_tx = txn(&cfg);
        replay_tx.nonce = 2;
        let replay_block = block(&cfg, 2, 120, [0; 32], vec![replay_tx], vec![]);
        assert_eq!(
            apply_block(
                &parent,
                [0x44; 32],
                [0x55; 32],
                &replay_block,
                [0xFF; 32],
                &cfg,
                &MockVerifier {
                    signatures_valid: true,
                    pow_digest: [0; 32],
                },
            ),
            Err(TransitionError::InvalidTransaction("nonce")),
        );
        assert_eq!(parent, original);
    }

    #[test]
    fn bad_post_state_root_rejects_the_whole_staged_transition() {
        let cfg = config();
        let parent = parent(1, 100);
        let original = parent.clone();
        let bad_root = [0xAB; 32];
        let b = block(&cfg, 2, 120, bad_root, vec![txn(&cfg)], vec![]);
        assert_eq!(
            apply_block(
                &parent,
                [0x44; 32],
                [0x55; 32],
                &b,
                [0xFF; 32],
                &cfg,
                &MockVerifier {
                    signatures_valid: true,
                    pow_digest: [0; 32],
                },
            ),
            Err(TransitionError::StateRootMismatch),
        );
        assert_eq!(parent, original);
    }

    #[test]
    fn expired_pending_treasury_proposal_is_pruned_before_actions() {
        let cfg = config();
        let expires_height = 1 + TIMELOCK_BLOCKS + EXECUTION_WINDOW_BLOCKS;
        let mut parent = parent(expires_height, 200);
        parent.pending_proposals = vec![PendingProposalV3 {
            proposal_id: [0x88; 32],
            proposer_signer_id: cfg.governance_roster[0].signer_id,
            proposer_nonce: 1,
            bucket_id: 2,
            recipient_id: [0x77; 32],
            amount_atoms: 100,
            rationale_hash: [0x99; 32],
            submitted_height: 1,
            not_before_height: 1 + TIMELOCK_BLOCKS,
            expires_height,
            approval_bitmap: 1,
        }];
        parent.validate(&cfg.limits).unwrap();
        let mut expected = parent.clone();
        expected.height += 1;
        expected.last_timestamp += 1;
        expected.pending_proposals.clear();
        expected.total_issued_atoms += INITIAL_MINER_SUBSIDY_ATOMS;
        expected.miner_issued_atoms += INITIAL_MINER_SUBSIDY_ATOMS;
        credit(
            &mut expected,
            [0x33; 32],
            INITIAL_MINER_SUBSIDY_ATOMS,
            &cfg.limits,
        )
        .unwrap();
        let root = expected.state_root(&cfg.limits).unwrap();
        let b = block(
            &cfg,
            parent.height + 1,
            parent.last_timestamp + 1,
            root,
            vec![],
            vec![],
        );
        let out = apply_block(
            &parent,
            [0x44; 32],
            [0x55; 32],
            &b,
            [0xFF; 32],
            &cfg,
            &MockVerifier {
                signatures_valid: true,
                pow_digest: [0; 32],
            },
        )
        .unwrap();
        assert_eq!(out.state, expected);
        assert!(out.state.pending_proposals.is_empty());
    }
}
