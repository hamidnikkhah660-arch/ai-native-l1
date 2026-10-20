//! Test-only model for anti-rollback recovery decisions.
//!
//! This deliberately does not implement a trust anchor or storage protocol. It classifies
//! observations so future designs can test fail-closed behavior without wiring research
//! snapshot state into production or canonical consensus.

#[derive(Debug, Clone, PartialEq, Eq)]
struct SnapshotObservation {
    domain: [u8; 32],
    schema: u16,
    generation: u64,
    digest: [u8; 32],
    semantic_valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AnchorObservation {
    Unavailable,
    Uninitialized,
    Current {
        domain: [u8; 32],
        schema: u16,
        generation: u64,
        digest: [u8; 32],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryDecision {
    AcceptAnchoredCurrent,
    RejectNoLocalSnapshot,
    RejectSemanticInvalidity,
    RejectDomainMismatch,
    RejectUnsupportedSchema,
    FailClosedAnchorUnavailable,
    BootstrapRequiresOutOfBandApproval,
    RejectStaleSnapshot,
    QuarantineLocalAheadOfAnchor,
    QuarantineSameGenerationDigestConflict,
}

/// Classify a local snapshot against a separately trusted anchor observation.
///
/// The caller must already have bounded and decoded the bytes and compute digest using a
/// cryptographic hash over an explicitly domain-separated canonical representation. This
/// model does not select that encoding/hash, perform I/O, authenticate anchor responses, or
/// decide how a pending commit is recovered. It is test-only and never called by runtime code.
fn classify(
    local: Option<&SnapshotObservation>,
    anchor: &AnchorObservation,
    expected_domain: &[u8; 32],
    expected_schema: u16,
) -> RecoveryDecision {
    let Some(local) = local else {
        return RecoveryDecision::RejectNoLocalSnapshot;
    };
    if !local.semantic_valid {
        return RecoveryDecision::RejectSemanticInvalidity;
    }
    if &local.domain != expected_domain {
        return RecoveryDecision::RejectDomainMismatch;
    }
    if local.schema != expected_schema {
        return RecoveryDecision::RejectUnsupportedSchema;
    }

    let (anchor_domain, anchor_schema, anchor_generation, anchor_digest) = match anchor {
        AnchorObservation::Unavailable => {
            return RecoveryDecision::FailClosedAnchorUnavailable;
        }
        AnchorObservation::Uninitialized => {
            return RecoveryDecision::BootstrapRequiresOutOfBandApproval;
        }
        AnchorObservation::Current {
            domain,
            schema,
            generation,
            digest,
        } => (domain, schema, generation, digest),
    };

    if anchor_domain != expected_domain {
        return RecoveryDecision::RejectDomainMismatch;
    }
    if *anchor_schema != expected_schema {
        return RecoveryDecision::RejectUnsupportedSchema;
    }
    if local.generation < *anchor_generation {
        return RecoveryDecision::RejectStaleSnapshot;
    }
    if local.generation > *anchor_generation {
        return RecoveryDecision::QuarantineLocalAheadOfAnchor;
    }
    if &local.digest != anchor_digest {
        return RecoveryDecision::QuarantineSameGenerationDigestConflict;
    }
    RecoveryDecision::AcceptAnchoredCurrent
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconciliationDecision {
    AcceptAnchoredCurrent,
    RecoverByInstallingAnchoredPreparedPayload,
    RejectSemanticInvalidity,
    RejectDomainMismatch,
    RejectUnsupportedSchema,
    FailClosedAnchorUnavailable,
    BootstrapRequiresOutOfBandApproval,
    QuarantineLocalAheadOfAnchor,
    QuarantineAnchorAheadWithoutMatchingPayload,
    QuarantineSameGenerationDigestConflict,
}

/// Reconcile the final local snapshot and an optional prepared payload after an ambiguous
/// local/anchor commit. The prepared payload must have been independently reopened and fully
/// validated, not merely inferred from a temp filename. This is a classifier only; callers
/// must not treat it as a storage protocol or act without a reviewed commit/recovery design.
fn reconcile(
    local: Option<&SnapshotObservation>,
    prepared: Option<&SnapshotObservation>,
    anchor: &AnchorObservation,
    expected_domain: &[u8; 32],
    expected_schema: u16,
) -> ReconciliationDecision {
    let (anchor_domain, anchor_schema, anchor_generation, anchor_digest) = match anchor {
        AnchorObservation::Unavailable => {
            return ReconciliationDecision::FailClosedAnchorUnavailable;
        }
        AnchorObservation::Uninitialized => {
            return ReconciliationDecision::BootstrapRequiresOutOfBandApproval;
        }
        AnchorObservation::Current {
            domain,
            schema,
            generation,
            digest,
        } => (domain, schema, generation, digest),
    };

    if anchor_domain != expected_domain {
        return ReconciliationDecision::RejectDomainMismatch;
    }
    if *anchor_schema != expected_schema {
        return ReconciliationDecision::RejectUnsupportedSchema;
    }

    if let Some(local) = local {
        if !local.semantic_valid {
            return ReconciliationDecision::RejectSemanticInvalidity;
        }
        if &local.domain != expected_domain {
            return ReconciliationDecision::RejectDomainMismatch;
        }
        if local.schema != expected_schema {
            return ReconciliationDecision::RejectUnsupportedSchema;
        }
        if local.generation == *anchor_generation && &local.digest == anchor_digest {
            return ReconciliationDecision::AcceptAnchoredCurrent;
        }
        if local.generation > *anchor_generation {
            return ReconciliationDecision::QuarantineLocalAheadOfAnchor;
        }
        if local.generation == *anchor_generation {
            return ReconciliationDecision::QuarantineSameGenerationDigestConflict;
        }
    }

    // Local is missing/older than the anchor, or absent. Only a complete, independently
    // validated prepared payload matching the anchor can close this gap.
    if let Some(prepared) = prepared {
        if !prepared.semantic_valid {
            return ReconciliationDecision::RejectSemanticInvalidity;
        }
        if &prepared.domain != expected_domain {
            return ReconciliationDecision::RejectDomainMismatch;
        }
        if prepared.schema != expected_schema {
            return ReconciliationDecision::RejectUnsupportedSchema;
        }
        if prepared.generation == *anchor_generation && &prepared.digest == anchor_digest {
            return ReconciliationDecision::RecoverByInstallingAnchoredPreparedPayload;
        }
    }

    ReconciliationDecision::QuarantineAnchorAheadWithoutMatchingPayload
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingAnchorCommit {
    from_generation: u64,
    from_digest: [u8; 32],
    to_generation: u64,
    to_digest: [u8; 32],
    semantically_valid: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnchorLifecycleDecision {
    AcceptCurrent,
    AcceptCurrentAndClearCommittedIntent,
    KeepAnchoredOldAndDiscardUncommittedIntent,
    InstallPreparedPayloadMatchingAdvancedAnchor,
    FailClosedAnchorUnavailable,
    BootstrapRequiresOutOfBandApproval,
    RejectDomainMismatch,
    RejectUnsupportedSchema,
    RejectSemanticInvalidity,
    QuarantineLocalAheadOfAnchor,
    QuarantineAnchorAheadWithoutPreparedPayload,
    QuarantineSameGenerationDigestConflict,
    QuarantineInvalidOrMismatchedIntent,
}

/// Candidate crash-window classifier for a two-domain anchor protocol.
///
/// Intended order: sync branch envelopes and a prepared full catalog; sync a pending intent
/// linking the prior and next (generation,digest); compare-and-swap the external monotonic
/// anchor from prior to next; atomically publish the prepared catalog; clear the intent.
/// The external anchor service must itself provide durable monotonic CAS semantics.
/// This classifier performs no I/O and is deliberately test-only.
fn classify_anchor_lifecycle(
    local: Option<&SnapshotObservation>,
    prepared: Option<&SnapshotObservation>,
    pending: Option<&PendingAnchorCommit>,
    anchor: &AnchorObservation,
    expected_domain: &[u8; 32],
    expected_schema: u16,
) -> AnchorLifecycleDecision {
    let (anchor_domain, anchor_schema, anchor_generation, anchor_digest) = match anchor {
        AnchorObservation::Unavailable => {
            return AnchorLifecycleDecision::FailClosedAnchorUnavailable;
        }
        AnchorObservation::Uninitialized => {
            return AnchorLifecycleDecision::BootstrapRequiresOutOfBandApproval;
        }
        AnchorObservation::Current {
            domain,
            schema,
            generation,
            digest,
        } => (domain, schema, generation, digest),
    };
    if anchor_domain != expected_domain {
        return AnchorLifecycleDecision::RejectDomainMismatch;
    }
    if *anchor_schema != expected_schema {
        return AnchorLifecycleDecision::RejectUnsupportedSchema;
    }

    for item in [local, prepared].into_iter().flatten() {
        if !item.semantic_valid {
            return AnchorLifecycleDecision::RejectSemanticInvalidity;
        }
        if &item.domain != expected_domain {
            return AnchorLifecycleDecision::RejectDomainMismatch;
        }
        if item.schema != expected_schema {
            return AnchorLifecycleDecision::RejectUnsupportedSchema;
        }
    }

    let local_matches_anchor = local
        .is_some_and(|item| item.generation == *anchor_generation && &item.digest == anchor_digest);
    let local_ahead_of_anchor = local.is_some_and(|item| item.generation > *anchor_generation);
    let local_same_generation_conflict = local
        .is_some_and(|item| item.generation == *anchor_generation && &item.digest != anchor_digest);

    if let Some(intent) = pending {
        let expected_next = intent.from_generation.checked_add(1);
        let intent_shape_valid = intent.semantically_valid
            && expected_next == Some(intent.to_generation)
            && intent.from_generation < intent.to_generation
            && intent.from_digest != intent.to_digest;
        if !intent_shape_valid {
            return AnchorLifecycleDecision::QuarantineInvalidOrMismatchedIntent;
        }
        let local_is_from = local.is_some_and(|item| {
            item.generation == intent.from_generation && item.digest == intent.from_digest
        });
        let local_is_to = local.is_some_and(|item| {
            item.generation == intent.to_generation && item.digest == intent.to_digest
        });
        let prepared_is_to = prepared.is_some_and(|item| {
            item.generation == intent.to_generation && item.digest == intent.to_digest
        });
        let anchor_is_from =
            *anchor_generation == intent.from_generation && *anchor_digest == intent.from_digest;
        let anchor_is_to =
            *anchor_generation == intent.to_generation && *anchor_digest == intent.to_digest;

        if (!local_is_from && !local_is_to && local.is_some())
            || prepared.is_some_and(|item| {
                item.generation != intent.to_generation || item.digest != intent.to_digest
            })
        {
            return AnchorLifecycleDecision::QuarantineInvalidOrMismatchedIntent;
        }
        if local_is_to && anchor_is_to {
            return AnchorLifecycleDecision::AcceptCurrentAndClearCommittedIntent;
        }
        if local_is_from && anchor_is_from {
            return AnchorLifecycleDecision::KeepAnchoredOldAndDiscardUncommittedIntent;
        }
        if anchor_is_to && prepared_is_to && (local_is_from || local.is_none()) {
            return AnchorLifecycleDecision::InstallPreparedPayloadMatchingAdvancedAnchor;
        }
        return AnchorLifecycleDecision::QuarantineInvalidOrMismatchedIntent;
    }

    if local_matches_anchor {
        return AnchorLifecycleDecision::AcceptCurrent;
    }
    if local_ahead_of_anchor {
        return AnchorLifecycleDecision::QuarantineLocalAheadOfAnchor;
    }
    if local_same_generation_conflict {
        return AnchorLifecycleDecision::QuarantineSameGenerationDigestConflict;
    }
    // A prepared file without a durable matching intent is never a commit record.
    AnchorLifecycleDecision::QuarantineAnchorAheadWithoutPreparedPayload
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN: [u8; 32] = [0x65; 32];
    const OTHER_DOMAIN: [u8; 32] = [0x66; 32];
    const SCHEMA: u16 = 1;

    fn local(generation: u64, digest: [u8; 32]) -> SnapshotObservation {
        SnapshotObservation {
            domain: DOMAIN,
            schema: SCHEMA,
            generation,
            digest,
            semantic_valid: true,
        }
    }

    fn anchor(generation: u64, digest: [u8; 32]) -> AnchorObservation {
        AnchorObservation::Current {
            domain: DOMAIN,
            schema: SCHEMA,
            generation,
            digest,
        }
    }

    #[test]
    fn recovery_decision_table_is_fail_closed() {
        let current = local(7, [0xA7; 32]);
        let mut invalid = current.clone();
        invalid.semantic_valid = false;
        let mut wrong_domain = current.clone();
        wrong_domain.domain = OTHER_DOMAIN;
        let mut wrong_schema = current.clone();
        wrong_schema.schema = SCHEMA + 1;
        let wrong_anchor_domain = AnchorObservation::Current {
            domain: OTHER_DOMAIN,
            schema: SCHEMA,
            generation: 7,
            digest: [0xA7; 32],
        };
        let wrong_anchor_schema = AnchorObservation::Current {
            domain: DOMAIN,
            schema: SCHEMA + 1,
            generation: 7,
            digest: [0xA7; 32],
        };

        let cases: Vec<(
            &str,
            Option<SnapshotObservation>,
            AnchorObservation,
            RecoveryDecision,
        )> = vec![
            (
                "missing local snapshot",
                None,
                anchor(7, [0xA7; 32]),
                RecoveryDecision::RejectNoLocalSnapshot,
            ),
            (
                "invalid semantics",
                Some(invalid),
                anchor(7, [0xA7; 32]),
                RecoveryDecision::RejectSemanticInvalidity,
            ),
            (
                "wrong local domain",
                Some(wrong_domain),
                anchor(7, [0xA7; 32]),
                RecoveryDecision::RejectDomainMismatch,
            ),
            (
                "unsupported local schema",
                Some(wrong_schema),
                anchor(7, [0xA7; 32]),
                RecoveryDecision::RejectUnsupportedSchema,
            ),
            (
                "anchor unavailable",
                Some(current.clone()),
                AnchorObservation::Unavailable,
                RecoveryDecision::FailClosedAnchorUnavailable,
            ),
            (
                "anchor uninitialized",
                Some(current.clone()),
                AnchorObservation::Uninitialized,
                RecoveryDecision::BootstrapRequiresOutOfBandApproval,
            ),
            (
                "wrong anchor domain",
                Some(current.clone()),
                wrong_anchor_domain,
                RecoveryDecision::RejectDomainMismatch,
            ),
            (
                "unsupported anchor schema",
                Some(current.clone()),
                wrong_anchor_schema,
                RecoveryDecision::RejectUnsupportedSchema,
            ),
            (
                "local snapshot older than anchor",
                Some(local(6, [0xA6; 32])),
                anchor(7, [0xA7; 32]),
                RecoveryDecision::RejectStaleSnapshot,
            ),
            (
                "local snapshot ahead of anchor",
                Some(local(8, [0xA8; 32])),
                anchor(7, [0xA7; 32]),
                RecoveryDecision::QuarantineLocalAheadOfAnchor,
            ),
            (
                "same generation and digest",
                Some(current.clone()),
                anchor(7, [0xA7; 32]),
                RecoveryDecision::AcceptAnchoredCurrent,
            ),
            (
                "same generation with conflicting digest",
                Some(local(7, [0xB7; 32])),
                anchor(7, [0xA7; 32]),
                RecoveryDecision::QuarantineSameGenerationDigestConflict,
            ),
        ];

        for (label, snapshot, anchor, expected) in cases {
            assert_eq!(
                classify(snapshot.as_ref(), &anchor, &DOMAIN, SCHEMA),
                expected,
                "case={label}"
            );
        }
    }

    #[test]
    fn only_exact_anchored_generation_and_digest_can_be_accepted() {
        let digest = [0x37; 32];
        let anchor = anchor(37, digest);
        assert_eq!(
            classify(Some(&local(37, digest)), &anchor, &DOMAIN, SCHEMA),
            RecoveryDecision::AcceptAnchoredCurrent
        );

        for generation in [0, 36, 38, u64::MAX] {
            let decision = classify(Some(&local(generation, digest)), &anchor, &DOMAIN, SCHEMA);
            assert_ne!(decision, RecoveryDecision::AcceptAnchoredCurrent);
        }
        assert_ne!(
            classify(Some(&local(37, [0x38; 32])), &anchor, &DOMAIN, SCHEMA),
            RecoveryDecision::AcceptAnchoredCurrent
        );
    }

    #[test]
    fn ambiguous_commit_reconciliation_requires_exact_anchored_payload() {
        let anchored = anchor(7, [0xA7; 32]);
        let exact_local = local(7, [0xA7; 32]);
        let old_local = local(6, [0xA6; 32]);
        let exact_prepared = local(7, [0xA7; 32]);
        let wrong_prepared = local(7, [0xB7; 32]);
        let invalid_prepared = SnapshotObservation {
            semantic_valid: false,
            ..exact_prepared.clone()
        };
        let newer_local = local(8, [0xA8; 32]);
        let conflicting_local = local(7, [0xB7; 32]);

        let cases: Vec<(
            &str,
            Option<SnapshotObservation>,
            Option<SnapshotObservation>,
            AnchorObservation,
            ReconciliationDecision,
        )> = vec![
            (
                "exact current local state",
                Some(exact_local.clone()),
                None,
                anchored.clone(),
                ReconciliationDecision::AcceptAnchoredCurrent,
            ),
            (
                "anchor committed and durable prepared payload matches",
                Some(old_local.clone()),
                Some(exact_prepared.clone()),
                anchored.clone(),
                ReconciliationDecision::RecoverByInstallingAnchoredPreparedPayload,
            ),
            (
                "anchor committed but final local snapshot missing",
                None,
                Some(exact_prepared.clone()),
                anchored.clone(),
                ReconciliationDecision::RecoverByInstallingAnchoredPreparedPayload,
            ),
            (
                "anchor advanced but recoverable payload missing",
                Some(old_local.clone()),
                None,
                anchored.clone(),
                ReconciliationDecision::QuarantineAnchorAheadWithoutMatchingPayload,
            ),
            (
                "prepared payload does not match anchored digest",
                Some(old_local.clone()),
                Some(wrong_prepared),
                anchored.clone(),
                ReconciliationDecision::QuarantineAnchorAheadWithoutMatchingPayload,
            ),
            (
                "prepared payload fails semantic validation",
                Some(old_local),
                Some(invalid_prepared),
                anchored.clone(),
                ReconciliationDecision::RejectSemanticInvalidity,
            ),
            (
                "local file ahead but anchor not advanced",
                Some(newer_local),
                None,
                anchored.clone(),
                ReconciliationDecision::QuarantineLocalAheadOfAnchor,
            ),
            (
                "same generation with conflicting local digest",
                Some(conflicting_local),
                None,
                anchored.clone(),
                ReconciliationDecision::QuarantineSameGenerationDigestConflict,
            ),
            (
                "anchor unavailable after ambiguous commit",
                None,
                Some(exact_prepared.clone()),
                AnchorObservation::Unavailable,
                ReconciliationDecision::FailClosedAnchorUnavailable,
            ),
            (
                "anchor uninitialized is not implicit bootstrap",
                None,
                Some(exact_prepared),
                AnchorObservation::Uninitialized,
                ReconciliationDecision::BootstrapRequiresOutOfBandApproval,
            ),
        ];

        for (label, local, prepared, anchor, expected) in cases {
            assert_eq!(
                reconcile(local.as_ref(), prepared.as_ref(), &anchor, &DOMAIN, SCHEMA),
                expected,
                "case={label}"
            );
        }
    }

    fn pending(
        from_generation: u64,
        from_digest: [u8; 32],
        to_generation: u64,
        to_digest: [u8; 32],
    ) -> PendingAnchorCommit {
        PendingAnchorCommit {
            from_generation,
            from_digest,
            to_generation,
            to_digest,
            semantically_valid: true,
        }
    }

    #[test]
    fn external_anchor_lifecycle_crash_windows_choose_only_old_or_new_committed_state() {
        let old = local(6, [0xA6; 32]);
        let new = local(7, [0xA7; 32]);
        let intent = pending(6, [0xA6; 32], 7, [0xA7; 32]);

        // 0: before prepared data exists; 1: prepared catalog exists but intent is not durable.
        assert_eq!(
            classify_anchor_lifecycle(
                Some(&old),
                None,
                None,
                &anchor(6, [0xA6; 32]),
                &DOMAIN,
                SCHEMA
            ),
            AnchorLifecycleDecision::AcceptCurrent
        );
        assert_eq!(
            classify_anchor_lifecycle(Some(&old), Some(&new), None, &anchor(6, [0xA6; 32]), &DOMAIN, SCHEMA),
            AnchorLifecycleDecision::AcceptCurrent,
            "prepared files are not a commit record without a durable intent and matching advanced anchor"
        );

        // 2: intent durable, external compare-and-swap has not advanced: discard uncommitted intent.
        assert_eq!(
            classify_anchor_lifecycle(
                Some(&old),
                Some(&new),
                Some(&intent),
                &anchor(6, [0xA6; 32]),
                &DOMAIN,
                SCHEMA
            ),
            AnchorLifecycleDecision::KeepAnchoredOldAndDiscardUncommittedIntent
        );

        // 3: external anchor advanced, but the committed manifest still points at old state.
        assert_eq!(
            classify_anchor_lifecycle(
                Some(&old),
                Some(&new),
                Some(&intent),
                &anchor(7, [0xA7; 32]),
                &DOMAIN,
                SCHEMA
            ),
            AnchorLifecycleDecision::InstallPreparedPayloadMatchingAdvancedAnchor
        );

        assert_eq!(
            classify_anchor_lifecycle(None, Some(&new), Some(&intent), &anchor(7, [0xA7; 32]), &DOMAIN, SCHEMA),
            AnchorLifecycleDecision::InstallPreparedPayloadMatchingAdvancedAnchor,
            "a missing previous manifest may be restored only from the exact prepared payload matching the advanced anchor"
        );

        // 4: manifest atomically published, while the durable intent has not yet been cleared.
        assert_eq!(
            classify_anchor_lifecycle(
                Some(&new),
                Some(&new),
                Some(&intent),
                &anchor(7, [0xA7; 32]),
                &DOMAIN,
                SCHEMA
            ),
            AnchorLifecycleDecision::AcceptCurrentAndClearCommittedIntent
        );

        // 5: stable state after the intent cleanup.
        assert_eq!(
            classify_anchor_lifecycle(
                Some(&new),
                None,
                None,
                &anchor(7, [0xA7; 32]),
                &DOMAIN,
                SCHEMA
            ),
            AnchorLifecycleDecision::AcceptCurrent
        );
    }

    #[test]
    fn external_anchor_lifecycle_never_guesses_when_recovery_evidence_is_missing_or_conflicts() {
        let old = local(6, [0xA6; 32]);
        let new = local(7, [0xA7; 32]);
        let intent = pending(6, [0xA6; 32], 7, [0xA7; 32]);

        assert_eq!(
            classify_anchor_lifecycle(
                Some(&old),
                None,
                None,
                &anchor(7, [0xA7; 32]),
                &DOMAIN,
                SCHEMA
            ),
            AnchorLifecycleDecision::QuarantineAnchorAheadWithoutPreparedPayload
        );
        assert_eq!(
            classify_anchor_lifecycle(
                Some(&new),
                None,
                None,
                &anchor(6, [0xA6; 32]),
                &DOMAIN,
                SCHEMA
            ),
            AnchorLifecycleDecision::QuarantineLocalAheadOfAnchor
        );
        assert_eq!(
            classify_anchor_lifecycle(Some(&old), None, Some(&intent), &anchor(7, [0xA7; 32]), &DOMAIN, SCHEMA),
            AnchorLifecycleDecision::QuarantineInvalidOrMismatchedIntent,
            "an advanced anchor without the exact prepared payload must not be reconstructed from an assumption"
        );
        assert_eq!(
            classify_anchor_lifecycle(
                Some(&local(7, [0xB7; 32])),
                None,
                None,
                &anchor(7, [0xA7; 32]),
                &DOMAIN,
                SCHEMA
            ),
            AnchorLifecycleDecision::QuarantineSameGenerationDigestConflict
        );
    }

    #[test]
    fn external_anchor_lifecycle_rejects_bad_intents_domains_schemas_and_unknown_anchor_state() {
        let old = local(6, [0xA6; 32]);
        let new = local(7, [0xA7; 32]);
        let mut bad_intent = pending(6, [0xA6; 32], 8, [0xA7; 32]);
        bad_intent.semantically_valid = true;

        assert_eq!(
            classify_anchor_lifecycle(
                Some(&old),
                Some(&new),
                Some(&bad_intent),
                &anchor(6, [0xA6; 32]),
                &DOMAIN,
                SCHEMA
            ),
            AnchorLifecycleDecision::QuarantineInvalidOrMismatchedIntent
        );
        assert_eq!(
            classify_anchor_lifecycle(
                Some(&old),
                None,
                None,
                &AnchorObservation::Unavailable,
                &DOMAIN,
                SCHEMA
            ),
            AnchorLifecycleDecision::FailClosedAnchorUnavailable
        );
        assert_eq!(
            classify_anchor_lifecycle(
                Some(&old),
                None,
                None,
                &AnchorObservation::Uninitialized,
                &DOMAIN,
                SCHEMA
            ),
            AnchorLifecycleDecision::BootstrapRequiresOutOfBandApproval
        );
        assert_eq!(
            classify_anchor_lifecycle(
                Some(&old),
                None,
                None,
                &anchor(6, [0xA6; 32]),
                &OTHER_DOMAIN,
                SCHEMA
            ),
            AnchorLifecycleDecision::RejectDomainMismatch
        );
        assert_eq!(
            classify_anchor_lifecycle(
                Some(&old),
                None,
                None,
                &anchor(6, [0xA6; 32]),
                &DOMAIN,
                SCHEMA + 1
            ),
            AnchorLifecycleDecision::RejectUnsupportedSchema
        );
    }

    #[test]
    fn unavailable_or_uninitialized_anchor_never_fails_open() {
        let snapshot = local(100, [0x99; 32]);
        for anchor in [
            AnchorObservation::Unavailable,
            AnchorObservation::Uninitialized,
        ] {
            assert_ne!(
                classify(Some(&snapshot), &anchor, &DOMAIN, SCHEMA),
                RecoveryDecision::AcceptAnchoredCurrent
            );
        }
    }
}
