//! Deterministic transport fault-injection model for local protocol tests.
//! This does not open sockets or emulate a real network stack.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultConfig {
    pub drop_per_mille: u16,
    pub base_delay_ms: u64,
    pub jitter_ms: u64,
    pub reorder_per_mille: u16,
}

impl FaultConfig {
    pub fn validate(self) -> bool {
        self.drop_per_mille <= 1000 && self.reorder_per_mille <= 1000
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledMessage {
    pub sequence: u64,
    pub deliver_at_ms: u64,
}

#[derive(Debug, Clone)]
pub struct FaultInjector {
    cfg: FaultConfig,
    state: u64,
}

impl FaultInjector {
    pub fn new(cfg: FaultConfig, seed: u64) -> Self {
        assert!(cfg.validate(), "fault configuration out of range");
        Self {
            cfg,
            state: seed.max(1),
        }
    }

    fn next_u32(&mut self) -> u32 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x as u32
    }

    fn roll_per_mille(&mut self) -> u16 {
        (self.next_u32() % 1000) as u16
    }

    fn delay(&mut self) -> u64 {
        if self.cfg.jitter_ms == 0 {
            return self.cfg.base_delay_ms;
        }

        let span = self.cfg.jitter_ms.saturating_mul(2).saturating_add(1);
        let offset = (self.next_u32() as u64) % span;
        let jitter = offset as i64 - self.cfg.jitter_ms as i64;
        if jitter >= 0 {
            self.cfg.base_delay_ms.saturating_add(jitter as u64)
        } else {
            self.cfg.base_delay_ms.saturating_sub((-jitter) as u64)
        }
    }

    pub fn inject(&mut self, sequence: u64, now_ms: u64) -> Option<ScheduledMessage> {
        if self.roll_per_mille() < self.cfg.drop_per_mille {
            return None;
        }

        let mut delay = self.delay();
        if self.roll_per_mille() < self.cfg.reorder_per_mille {
            delay = delay.saturating_add(self.cfg.jitter_ms.max(1));
        }

        Some(ScheduledMessage {
            sequence,
            deliver_at_ms: now_ms.saturating_add(delay),
        })
    }

    pub fn inject_batch(&mut self, sequences: &[u64], now_ms: u64) -> Vec<ScheduledMessage> {
        let mut out = sequences
            .iter()
            .copied()
            .filter_map(|seq| self.inject(seq, now_ms))
            .collect::<Vec<_>>();

        out.sort_by_key(|message| (message.deliver_at_ms, message.sequence));
        out
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_loss_preserves_every_message() {
        let cfg = FaultConfig {
            drop_per_mille: 0,
            base_delay_ms: 10,
            jitter_ms: 0,
            reorder_per_mille: 0,
        };
        let mut fx = FaultInjector::new(cfg, 7);
        let input = [0, 1, 2, 3, 4, 5];
        let output = fx.inject_batch(&input, 100);
        assert_eq!(output.len(), input.len());
        assert!(output.iter().all(|m| m.deliver_at_ms == 110));
    }

    #[test]
    fn full_loss_drops_every_message() {
        let cfg = FaultConfig {
            drop_per_mille: 1000,
            base_delay_ms: 10,
            jitter_ms: 0,
            reorder_per_mille: 0,
        };
        let mut fx = FaultInjector::new(cfg, 7);
        assert!(fx.inject_batch(&[0, 1, 2, 3], 100).is_empty());
    }

    #[test]
    fn jitter_stays_within_configured_bound() {
        let cfg = FaultConfig {
            drop_per_mille: 0,
            base_delay_ms: 100,
            jitter_ms: 20,
            reorder_per_mille: 0,
        };
        let mut fx = FaultInjector::new(cfg, 99);
        for seq in 0..500 {
            let message = fx.inject(seq, 1000).unwrap();
            let delta = message.deliver_at_ms - 1000;
            assert!((80..=120).contains(&delta), "delta={delta}");
        }
    }

    #[test]
    fn reorder_fault_can_change_delivery_time() {
        let cfg = FaultConfig {
            drop_per_mille: 0,
            base_delay_ms: 0,
            jitter_ms: 5,
            reorder_per_mille: 1000,
        };
        let mut fx = FaultInjector::new(cfg, 1234);
        let output = fx.inject_batch(&[0, 1, 2, 3, 4, 5, 6, 7], 0);
        assert_eq!(output.len(), 8);
        assert!(output.iter().any(|m| m.deliver_at_ms > 0));
    }

    #[test]
    fn sequence_is_preserved_even_when_delivery_is_delayed() {
        let cfg = FaultConfig {
            drop_per_mille: 0,
            base_delay_ms: 50,
            jitter_ms: 10,
            reorder_per_mille: 1000,
        };
        let mut fx = FaultInjector::new(cfg, 321);
        let output = fx.inject_batch(&[10, 11, 12], 100);
        let mut ids = output.iter().map(|m| m.sequence).collect::<Vec<_>>();
        ids.sort_unstable();
        assert_eq!(ids, vec![10, 11, 12]);
    }
}
