//! Core-facing verifier interface: policy first, primitive provider second.
//! No private-key material is accepted or serialized here.
use crate::identity_policy::{KeyRecord, KeyState};
use crate::signature_policy::{SigPolicy, SignatureEnvelope};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    KeyStateInvalid,
    KeyIdMismatch,
    GenerationMismatch,
    PurposeMismatch,
    DomainMismatch,
    Policy(crate::signature_policy::SigPolicyError),
    Provider(String),
}

pub trait SignatureProvider {
    fn verify(
        &self,
        suite: crate::signature_policy::SignatureSuite,
        public_key: &[u8],
        preimage: &[u8],
        signature: &[u8],
    ) -> Result<(), String>;
}

pub struct VerificationRequest<'a> {
    pub key: &'a KeyRecord,
    pub signature: &'a SignatureEnvelope,
    pub message: &'a [u8],
    pub expected_domain: u16,
    pub epoch: u64,
    pub policy: SigPolicy,
}

pub fn signing_preimage(domain: u16, message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + message.len());
    out.extend_from_slice(b"AIN1-SIG\0");
    out.extend_from_slice(&domain.to_be_bytes());
    out.extend_from_slice(message);
    out
}

pub fn verify<P: SignatureProvider>(
    provider: &P,
    req: VerificationRequest<'_>,
) -> Result<(), VerifyError> {
    if req.key.state != KeyState::Active || !req.key.is_valid_at(req.epoch) {
        return Err(VerifyError::KeyStateInvalid);
    }
    if req.signature.key_id != req.key.key_id {
        return Err(VerifyError::KeyIdMismatch);
    }
    if req.signature.generation != req.key.generation {
        return Err(VerifyError::GenerationMismatch);
    }
    if req.signature.purpose != req.key.purpose {
        return Err(VerifyError::PurposeMismatch);
    }
    if req.signature.domain != req.expected_domain {
        return Err(VerifyError::DomainMismatch);
    }
    req.signature
        .validate(req.key.algorithm, req.key.purpose, req.epoch, req.policy)
        .map_err(VerifyError::Policy)?;
    let preimage = signing_preimage(req.expected_domain, req.message);
    provider
        .verify(
            req.signature.suite,
            &req.key.public_key,
            &preimage,
            &req.signature.signature,
        )
        .map_err(VerifyError::Provider)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_policy::{KeyAlgorithm, KeyPurpose, SecurityClass};
    use crate::signature_policy::SignatureSuite;

    struct ExpectedProvider {
        suite: SignatureSuite,
        key: Vec<u8>,
        preimage: Vec<u8>,
        sig: Vec<u8>,
    }
    impl SignatureProvider for ExpectedProvider {
        fn verify(
            &self,
            suite: SignatureSuite,
            public_key: &[u8],
            preimage: &[u8],
            signature: &[u8],
        ) -> Result<(), String> {
            if suite != self.suite
                || public_key != self.key
                || preimage != self.preimage
                || signature != self.sig
            {
                return Err("provider vector mismatch".into());
            }
            Ok(())
        }
    }
    fn key() -> KeyRecord {
        KeyRecord {
            key_id: 42,
            generation: 3,
            algorithm: KeyAlgorithm::Ed25519,
            purpose: KeyPurpose::AccountAuth,
            state: KeyState::Active,
            not_before: 1,
            not_after: 100,
            public_key: vec![9, 8, 7],
        }
    }
    fn sig() -> SignatureEnvelope {
        SignatureEnvelope {
            suite: SignatureSuite::Ed25519,
            key_id: 42,
            generation: 3,
            purpose: KeyPurpose::AccountAuth,
            domain: 7,
            signature: vec![1, 2, 3],
        }
    }
    fn policy() -> SigPolicy {
        SigPolicy {
            min_class: SecurityClass::Classical,
            pq_activation_epoch: None,
            require_hybrid_until: None,
        }
    }
    #[test]
    fn provider_dispatch_binds_domain_and_key() {
        let k = key();
        let s = sig();
        let msg = b"hello";
        let pre = signing_preimage(7, msg);
        let p = ExpectedProvider {
            suite: SignatureSuite::Ed25519,
            key: k.public_key.clone(),
            preimage: pre,
            sig: s.signature.clone(),
        };
        verify(
            &p,
            VerificationRequest {
                key: &k,
                signature: &s,
                message: msg,
                expected_domain: 7,
                epoch: 10,
                policy: policy(),
            },
        )
        .unwrap();
    }
    #[test]
    fn domain_replay_is_rejected_before_provider() {
        let k = key();
        let s = sig();
        let p = ExpectedProvider {
            suite: SignatureSuite::Ed25519,
            key: k.public_key.clone(),
            preimage: signing_preimage(7, b"hello"),
            sig: s.signature.clone(),
        };
        assert_eq!(
            verify(
                &p,
                VerificationRequest {
                    key: &k,
                    signature: &s,
                    message: b"hello",
                    expected_domain: 8,
                    epoch: 10,
                    policy: policy()
                }
            ),
            Err(VerifyError::DomainMismatch)
        );
    }
    #[test]
    fn revoked_key_is_rejected_before_provider() {
        let k = KeyRecord::revoke(&key()).unwrap();
        let s = sig();
        let p = ExpectedProvider {
            suite: SignatureSuite::Ed25519,
            key: vec![],
            preimage: vec![],
            sig: vec![],
        };
        assert_eq!(
            verify(
                &p,
                VerificationRequest {
                    key: &k,
                    signature: &s,
                    message: b"hello",
                    expected_domain: 7,
                    epoch: 10,
                    policy: policy()
                }
            ),
            Err(VerifyError::KeyStateInvalid)
        );
    }
    #[test]
    fn generation_mismatch_is_rejected() {
        let k = key();
        let mut s = sig();
        s.generation = 2;
        let p = ExpectedProvider {
            suite: SignatureSuite::Ed25519,
            key: k.public_key.clone(),
            preimage: vec![],
            sig: s.signature.clone(),
        };
        assert_eq!(
            verify(
                &p,
                VerificationRequest {
                    key: &k,
                    signature: &s,
                    message: b"hello",
                    expected_domain: 7,
                    epoch: 10,
                    policy: policy()
                }
            ),
            Err(VerifyError::GenerationMismatch)
        );
    }
    #[test]
    fn provider_failure_is_preserved() {
        struct Reject;
        impl SignatureProvider for Reject {
            fn verify(
                &self,
                _: SignatureSuite,
                _: &[u8],
                _: &[u8],
                _: &[u8],
            ) -> Result<(), String> {
                Err("bad signature".into())
            }
        }
        let k = key();
        let s = sig();
        let e = verify(
            &Reject,
            VerificationRequest {
                key: &k,
                signature: &s,
                message: b"hello",
                expected_domain: 7,
                epoch: 10,
                policy: policy(),
            },
        )
        .unwrap_err();
        assert_eq!(e, VerifyError::Provider("bad signature".into()));
    }
}
