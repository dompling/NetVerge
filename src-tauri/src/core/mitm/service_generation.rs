//! Identity of a service-owned core process, not just its owner session.
//! The watchdog can replace the process without changing the owner token.
use anyhow::{Result, ensure};
use clash_verge_service_ipc::{ServiceLifecycleState, ServiceStatusSnapshot};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Generation {
    owner: u64,
    pub(crate) pid: u32,
    started_at: u64,
    restarts: u32,
}

impl Generation {
    pub(crate) fn from_status(owner: u64, state: &ServiceStatusSnapshot) -> Result<Option<Self>> {
        ensure!(state.is_active && state.active_generation == Some(owner), "service owner generation changed");
        ensure!(state.service_state != ServiceLifecycleState::Fatal, "service reported Fatal: pid_present={} restart_count={}", state.core_pid.is_some(), state.restart_count);
        if !state.desired_core_should_be_running || state.service_state != ServiceLifecycleState::Running {
            return Ok(None);
        }
        Ok(match (state.core_pid, state.core_started_at) {
            (Some(pid), Some(started_at)) if pid != 0 => Some(Self { owner, pid, started_at, restarts: state.restart_count }),
            _ => None,
        })
    }

    pub(crate) fn is_restart_of(self, previous: Self) -> bool {
        self.owner == previous.owner && self.pid != previous.pid
            && self.restarts > previous.restarts
            && self.started_at >= previous.started_at
    }
}

/// Keep the last trusted identity across unreadable/recovering samples. A
/// missing or contradictory sample revokes current readiness without making
/// an older instance acceptable on the next sample.
#[derive(Clone, Default)]
pub(crate) struct GenerationWatch {
    last: Option<Generation>,
    ready: Option<Generation>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Transition {
    Initial,
    Unchanged,
    Reconfirmed,
    Restarted,
    Unavailable,
    Rejected,
}

impl GenerationWatch {
    pub(crate) const fn current(&self) -> Option<Generation> { self.ready }

    pub(crate) fn observe(&mut self, sample: Option<Generation>) -> Transition {
        let Some(next) = sample else {
            self.ready = None;
            return Transition::Unavailable;
        };
        let transition = match self.last {
            None => Transition::Initial,
            Some(old) if old == next => {
                if self.ready == Some(next) { Transition::Unchanged } else { Transition::Reconfirmed }
            }
            Some(old) if next.is_restart_of(old) => Transition::Restarted,
            Some(_) => {
                self.ready = None;
                return Transition::Rejected;
            }
        };
        self.last = Some(next);
        self.ready = Some(next);
        transition
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generation(owner: u64, pid: u32, started_at: u64, restarts: u32) -> Generation {
        Generation { owner, pid, started_at, restarts }
    }

    #[test]
    fn rejects_stale_owner_and_process_samples_after_watchdog_restart() {
        let first = generation(5, 100, 10, 0);
        let replacement = generation(5, 200, 10, 1);
        let mut watch = GenerationWatch::default();
        assert_eq!(watch.observe(Some(first)), Transition::Initial);
        assert_eq!(watch.observe(Some(first)), Transition::Unchanged);
        assert_eq!(watch.observe(None), Transition::Unavailable);
        assert_eq!(watch.current(), None);
        assert_eq!(watch.observe(Some(first)), Transition::Reconfirmed);
        assert_eq!(watch.observe(Some(replacement)), Transition::Restarted);
        assert_eq!(watch.current(), Some(replacement));
        for invalid in [first, generation(6, 300, 11, 2), generation(5, 300, 11, 1), generation(5, 300, 9, 2)] {
            assert_eq!(watch.observe(Some(invalid)), Transition::Rejected);
            assert_eq!(watch.current(), None);
            assert_eq!(watch.observe(Some(replacement)), Transition::Reconfirmed);
        }
    }

    #[test]
    fn only_authenticated_running_status_with_process_identity_is_ready() -> Result<()> {
        let mut state = ServiceStatusSnapshot {
            is_active: true, active_generation: Some(5),
            service_state: ServiceLifecycleState::Running, core_pid: Some(100),
            core_started_at: Some(10), last_core_exit_reason: None, restart_count: 0,
            last_recovery_at: None, desired_core_should_be_running: true,
            desired_generation: 5, desired_updated_at: 10, desired_persistence_error: None,
        };
        assert_eq!(Generation::from_status(5, &state)?, Some(generation(5, 100, 10, 0)));
        assert!(Generation::from_status(6, &state).is_err());
        state.service_state = ServiceLifecycleState::RecoveringCore;
        assert_eq!(Generation::from_status(5, &state)?, None);
        state.service_state = ServiceLifecycleState::Running;
        state.core_pid = None;
        assert_eq!(Generation::from_status(5, &state)?, None);
        state.service_state = ServiceLifecycleState::Fatal;
        assert!(Generation::from_status(5, &state).is_err());
        Ok(())
    }
}
