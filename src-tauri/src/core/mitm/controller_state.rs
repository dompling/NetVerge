//! Common authenticated controller state and exact-selection verification.
//! A guarded process is not ready until its startup fence is settled.
use anyhow::{Result, ensure};
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Deserialize, Debug, PartialEq, Eq)]
pub(crate) struct CoreState {
    pub(crate) protocol: u32,
    pub(crate) enabled: bool,
    pub(crate) hosts: Vec<String>,
    #[serde(default, rename = "awaitingSelection")]
    pub(crate) awaiting_selection: bool,
}

pub(crate) fn same_hosts(a: &[String], b: &[String]) -> bool {
    let aa = a.iter().collect::<BTreeSet<_>>();
    let bb = b.iter().collect::<BTreeSet<_>>();
    aa.len() == a.len() && bb.len() == b.len() && aa == bb
}

impl CoreState {
    pub(crate) fn verify_protocol(&self) -> Result<()> {
        ensure!(self.protocol == 1, "custom Mihomo controller protocol mismatch");
        Ok(())
    }

    pub(crate) fn verify_pending(&self) -> Result<()> {
        self.verify_protocol()?;
        ensure!(self.awaiting_selection && !self.enabled && self.hosts.is_empty(), "fresh service core did not confirm guarded startup");
        Ok(())
    }

    pub(crate) fn verify_selection(&self, enabled: bool, hosts: &[String]) -> Result<()> {
        self.verify_protocol()?;
        ensure!(!self.awaiting_selection && self.enabled == enabled, "MITM selection is not settled");
        let expected = if enabled { hosts } else { &[] };
        ensure!(same_hosts(&self.hosts, expected), "MITM controller scope differs from committed selection");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_is_never_the_same_as_confirmed_disabled() -> Result<()> {
        let pending: CoreState = serde_json::from_str(r#"{"protocol":1,"enabled":false,"hosts":[],"awaitingSelection":true}"#)?;
        pending.verify_pending()?;
        assert!(pending.verify_selection(false, &[]).is_err());
        let disabled: CoreState = serde_json::from_str(r#"{"protocol":1,"enabled":false,"hosts":[]}"#)?;
        disabled.verify_selection(false, &["saved.test".into()])?;
        assert!(disabled.verify_pending().is_err());
        Ok(())
    }

    #[test]
    fn exact_scope_is_order_independent_but_rejects_duplicates() -> Result<()> {
        let active: CoreState = serde_json::from_str(r#"{"protocol":1,"enabled":true,"hosts":["a.test","b.test"]}"#)?;
        active.verify_selection(true, &["b.test".into(), "a.test".into()])?;
        assert!(active.verify_selection(true, &["a.test".into()]).is_err());
        assert!(active.verify_selection(true, &["a.test".into(), "a.test".into()]).is_err());
        assert!(active.verify_selection(false, &[]).is_err());
        Ok(())
    }
}
