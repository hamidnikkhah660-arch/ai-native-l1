//! Research-only generation lease for archive commits racing canonical reorgs.
//!
//! Every page-persistence callback must run while holding this coordinator's read lease.
//! A reorg installs its replacement stamp under the write lock, so either the page commit
//! linearizes before the reorg, or it observes a stale generation and is not persisted.
//! Callers outside this coordinator can bypass the guard; this is not canonical-chain wiring.

use std::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveGenerationStamp {
    pub generation: u64,
    pub snapshot_commitment: [u8; 32],
}

impl ArchiveGenerationStamp {
    pub const fn new(generation: u64, snapshot_commitment: [u8; 32]) -> Self {
        Self {
            generation,
            snapshot_commitment,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveGenerationCoordinatorError {
    LockPoisoned,
    NonMonotonicGeneration {
        current_generation: u64,
        requested_generation: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveGenerationCommitError<E> {
    LockPoisoned,
    StaleGeneration {
        expected: ArchiveGenerationStamp,
        actual: ArchiveGenerationStamp,
    },
    Persist(E),
}

/// In-process generation gate for a single archive/WAL coordinator domain.
pub struct ArchiveGenerationCoordinatorCandidate {
    current: RwLock<ArchiveGenerationStamp>,
}

impl ArchiveGenerationCoordinatorCandidate {
    pub fn new(initial: ArchiveGenerationStamp) -> Self {
        Self {
            current: RwLock::new(initial),
        }
    }

    pub fn current(&self) -> Result<ArchiveGenerationStamp, ArchiveGenerationCoordinatorError> {
        self.current
            .read()
            .map(|stamp| *stamp)
            .map_err(|_| ArchiveGenerationCoordinatorError::LockPoisoned)
    }

    /// Replace the active archive generation. Generations must strictly increase.
    /// This takes an exclusive lock and therefore waits for any in-flight commit callback.
    pub fn transition_to(
        &self,
        next: ArchiveGenerationStamp,
    ) -> Result<ArchiveGenerationStamp, ArchiveGenerationCoordinatorError> {
        let mut current = self
            .current
            .write()
            .map_err(|_| ArchiveGenerationCoordinatorError::LockPoisoned)?;
        if next.generation <= current.generation {
            return Err(ArchiveGenerationCoordinatorError::NonMonotonicGeneration {
                current_generation: current.generation,
                requested_generation: next.generation,
            });
        }
        *current = next;
        Ok(next)
    }

    /// Validate and hold the generation lease throughout persistence.
    ///
    /// The callback must only perform bounded persistence work; it must not call
    /// `transition_to` on this same coordinator, which would self-deadlock.
    pub fn commit_if_current<T, E, F>(
        &self,
        expected: ArchiveGenerationStamp,
        persist: F,
    ) -> Result<T, ArchiveGenerationCommitError<E>>
    where
        F: FnOnce() -> Result<T, E>,
    {
        let lease = self
            .current
            .read()
            .map_err(|_| ArchiveGenerationCommitError::LockPoisoned)?;
        let actual = *lease;
        if actual != expected {
            return Err(ArchiveGenerationCommitError::StaleGeneration { expected, actual });
        }
        // Keep 'lease' alive until the callback completes, serializing reorg publication.
        let result = persist().map_err(ArchiveGenerationCommitError::Persist);
        drop(lease);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_or_same_height_different_commitment_is_rejected_before_callback() {
        let active = ArchiveGenerationStamp::new(9, [0x99; 32]);
        let coordinator = ArchiveGenerationCoordinatorCandidate::new(active);
        let stale = ArchiveGenerationStamp::new(8, [0x88; 32]);
        let mut callback_ran = false;
        assert_eq!(
            coordinator.commit_if_current(stale, || {
                callback_ran = true;
                Ok::<_, ()>(())
            }),
            Err(ArchiveGenerationCommitError::StaleGeneration {
                expected: stale,
                actual: active,
            })
        );
        let equivocating = ArchiveGenerationStamp::new(9, [0x98; 32]);
        assert!(matches!(
            coordinator.commit_if_current(equivocating, || {
                callback_ran = true;
                Ok::<_, ()>(())
            }),
            Err(ArchiveGenerationCommitError::StaleGeneration { .. })
        ));
        assert!(!callback_ran);
    }

    #[test]
    fn reorg_transition_waits_until_inflight_persistence_callback_returns() {
        use std::sync::{mpsc, Arc};
        use std::thread;
        use std::time::Duration;

        let active = ArchiveGenerationStamp::new(20, [0x20; 32]);
        let next = ArchiveGenerationStamp::new(21, [0x21; 32]);
        let coordinator = Arc::new(ArchiveGenerationCoordinatorCandidate::new(active));
        let (callback_entered_tx, callback_entered_rx) = mpsc::channel();
        let (release_callback_tx, release_callback_rx) = mpsc::channel();
        let commit_coordinator = Arc::clone(&coordinator);

        let commit_thread = thread::spawn(move || {
            commit_coordinator.commit_if_current(active, || {
                callback_entered_tx.send(()).unwrap();
                release_callback_rx
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap();
                Ok::<_, ()>(())
            })
        });
        callback_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();

        let (transition_started_tx, transition_started_rx) = mpsc::channel();
        let (transition_done_tx, transition_done_rx) = mpsc::channel();
        let transition_coordinator = Arc::clone(&coordinator);
        let transition_thread = thread::spawn(move || {
            transition_started_tx.send(()).unwrap();
            let result = transition_coordinator.transition_to(next);
            transition_done_tx.send(result).unwrap();
        });
        transition_started_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();

        assert!(matches!(
            transition_done_rx.recv_timeout(Duration::from_millis(30)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        release_callback_tx.send(()).unwrap();
        assert_eq!(commit_thread.join().unwrap(), Ok(()));
        assert_eq!(
            transition_done_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap(),
            Ok(next)
        );
        transition_thread.join().unwrap();
        assert_eq!(coordinator.current(), Ok(next));
    }

    #[test]
    fn reorg_transition_rejects_generation_rollback_and_same_generation_equivocation() {
        let active = ArchiveGenerationStamp::new(30, [0x30; 32]);
        let coordinator = ArchiveGenerationCoordinatorCandidate::new(active);
        assert_eq!(
            coordinator.transition_to(ArchiveGenerationStamp::new(29, [0x29; 32])),
            Err(ArchiveGenerationCoordinatorError::NonMonotonicGeneration {
                current_generation: 30,
                requested_generation: 29,
            })
        );
        assert_eq!(
            coordinator.transition_to(ArchiveGenerationStamp::new(30, [0x31; 32])),
            Err(ArchiveGenerationCoordinatorError::NonMonotonicGeneration {
                current_generation: 30,
                requested_generation: 30,
            })
        );
        assert_eq!(coordinator.current(), Ok(active));
    }
}
