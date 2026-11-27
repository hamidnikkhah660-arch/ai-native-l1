//! CP-0487 candidate owner for an explicitly supplied off-host Anchor daemon task.
//!
//! This type is deliberately disabled by default. It does not parse configuration, bind sockets,
//! provision keys, start a daemon, or restart a failed service. A future runtime initializer may
//! attach a task only after independently constructing and validating the daemon configuration.
//! The owner joins the task on explicit shutdown or when its containing node state is dropped.

use crate::external_cas_offhost_anchor_noise_daemon_candidate::{
    OffhostAnchorNoiseDaemonStats, OffhostAnchorNoiseDaemonTask,
};
use crate::external_cas_offhost_anchor_noise_transport_candidate::OffhostAnchorNoiseError;
use std::fmt;

#[derive(Default)]
pub struct OffhostAnchorNodeServiceOwner {
    task: Option<OffhostAnchorNoiseDaemonTask>,
}

impl fmt::Debug for OffhostAnchorNodeServiceOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OffhostAnchorNodeServiceOwner")
            .field("attached", &self.is_attached())
            .field("stats", &self.stats())
            .finish()
    }
}

impl OffhostAnchorNodeServiceOwner {
    /// Construct a disabled owner. This performs no bind and starts no thread.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Whether a daemon task is currently owned by this node lifecycle.
    pub fn is_attached(&self) -> bool {
        self.task.is_some()
    }

    /// Attach an already spawned task. A second task is returned unchanged to the caller.
    /// This method never binds a listener or starts a daemon itself.
    pub fn try_attach(
        &mut self,
        task: OffhostAnchorNoiseDaemonTask,
    ) -> Result<(), OffhostAnchorNoiseDaemonTask> {
        if self.task.is_some() {
            return Err(task);
        }
        self.task = Some(task);
        Ok(())
    }

    /// Obtain live counters while a task remains attached.
    pub fn stats(&self) -> Option<OffhostAnchorNoiseDaemonStats> {
        self.task.as_ref().map(OffhostAnchorNoiseDaemonTask::stats)
    }

    /// Signal graceful shutdown without detaching the task; `shutdown_and_join` still reports it.
    pub fn request_shutdown(&self) {
        if let Some(task) = self.task.as_ref() {
            task.request_shutdown();
        }
    }

    /// Stop and join the owned daemon. Repeated calls after the first are idempotent.
    pub fn shutdown_and_join(
        &mut self,
    ) -> Result<Option<OffhostAnchorNoiseDaemonStats>, OffhostAnchorNoiseError> {
        self.task
            .take()
            .map(OffhostAnchorNoiseDaemonTask::shutdown_and_join)
            .transpose()
    }
}

impl Drop for OffhostAnchorNodeServiceOwner {
    fn drop(&mut self) {
        // Drop cannot surface the daemon's result; callers that need to inspect it should invoke
        // shutdown_and_join explicitly before their node state is destroyed.
        let _ = self.shutdown_and_join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_owner_is_disabled_and_shutdown_is_idempotent() {
        let mut owner = OffhostAnchorNodeServiceOwner::default();
        assert!(!owner.is_attached());
        assert_eq!(owner.stats(), None);
        assert_eq!(owner.shutdown_and_join().unwrap(), None);
        assert_eq!(owner.shutdown_and_join().unwrap(), None);
        assert!(!owner.is_attached());
    }

    #[test]
    fn explicitly_named_disabled_constructor_does_not_attach_a_task() {
        let owner = OffhostAnchorNodeServiceOwner::disabled();
        assert!(!owner.is_attached());
        assert!(owner.stats().is_none());
    }
}
