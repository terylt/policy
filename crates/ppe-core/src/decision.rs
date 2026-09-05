// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The DecisionLog: the executor's record of what each plugin did to a
// request and how the pipeline ruled on it.
//
// A plugin observing a request cannot see the pipeline's verdict. Allow,
// deny and modify live in the executor's control flow (`PluginResult` and
// the short-circuit return), not in `Extensions`, so an observation-only
// plugin sees allowed post-hook traffic and nothing else. The DecisionLog
// captures that control flow so an audit sink can serialize it.
//
// It is built by the executor and handed only to audit handlers. It is not
// placed on `PluginContext`: every plugin can read that, and a plugin that
// could read the log could tailor its behaviour to what has already been
// recorded about it.
//
// It records what happened (which plugin, which phase, which action), not
// copies of payloads.

use crate::error::PluginViolation;
use crate::plugin::PluginMode;

/// What a single plugin did to the request, as the executor saw it.
///
/// Derived from the plugin's returned `PluginResult`, never self-reported.
#[derive(Debug, Clone, PartialEq)]
pub enum PluginAction {
    /// Ran and let the request continue unchanged.
    Allowed,
    /// Blocked the request, carrying its own violation.
    ///
    /// The terminal [`Verdict::Deny`] carries the violation the pipeline ruled
    /// on, which is this one in a serial phase. A concurrent phase can have
    /// several branches deny at once and only the first becomes the verdict,
    /// so without a violation here the other objections would be recorded as
    /// bare markers with no reason attached to them.
    Denied(Box<PluginViolation>),
    /// Replaced the payload, and the executor accepted the replacement.
    ModifiedPayload,
    /// Wrote to an extension slot it was capable of writing.
    ModifiedExtensions,
    /// Signalled a block from a phase that cannot block (Transform), so the
    /// deny was suppressed and the pipeline continued.
    ///
    /// Recorded as its own action rather than as [`PluginAction::Allowed`]:
    /// a consumer mapping actions to a disposition must not read a suppressed
    /// block as the plugin having permitted the request.
    ///
    /// Carries the violation the plugin returned. Enforcement did not happen
    /// here, so this record is the only place the objection survives: the
    /// verdict is an allow and names nothing.
    DenyIgnored(Box<PluginViolation>),
    /// Cancelled mid-flight because another concurrent branch short-circuited
    /// the phase. Distinct from [`PluginAction::Error`] so an intentional
    /// abort does not read as a crash.
    Aborted,
    /// Failed, carrying the error as the executor rendered it. Whether this
    /// halts the pipeline is decided by the plugin's `on_error`, so an
    /// `Error` step may be followed by more steps.
    Error(String),
}

/// One entry in the log: a plugin, the phase it ran in, and what it did.
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionStep {
    /// The plugin instance name, from `PluginConfig.name`.
    pub plugin_name: String,
    /// The phase this plugin ran in.
    pub phase: PluginMode,
    /// What it did.
    pub action: PluginAction,
}

/// The pipeline's terminal ruling on a request.
#[derive(Debug, Clone)]
pub enum Verdict {
    /// The request was allowed through. Any modifications along the way are
    /// in [`DecisionLog::steps`].
    Allow,
    /// The request was blocked, carrying the violation the executor stamped
    /// with the deciding plugin's name.
    Deny(PluginViolation),
}

impl Verdict {
    /// True if this verdict blocked the request.
    pub fn is_deny(&self) -> bool {
        matches!(self, Verdict::Deny(_))
    }
}

/// The executor's record of one pipeline invocation: the ordered steps the
/// plugins took and the terminal verdict.
///
/// `verdict` is `None` while the pipeline is still running and is set once,
/// at a return point. An audit sink is only ever handed a finalized log.
#[derive(Debug, Clone, Default)]
pub struct DecisionLog {
    steps: Vec<DecisionStep>,
    verdict: Option<Verdict>,
}

impl DecisionLog {
    /// A fresh log for one pipeline invocation.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append what a plugin did. Called by the executor as each plugin
    /// returns, so the order is execution order.
    pub fn record(
        &mut self,
        plugin_name: impl Into<String>,
        phase: PluginMode,
        action: PluginAction,
    ) {
        self.steps.push(DecisionStep {
            plugin_name: plugin_name.into(),
            phase,
            action,
        });
    }

    /// Set the terminal verdict, once, at the pipeline's return point and
    /// before the log reaches any audit handler.
    pub fn finalize(&mut self, verdict: Verdict) {
        self.verdict = Some(verdict);
    }

    /// The ordered steps taken this invocation.
    pub fn steps(&self) -> &[DecisionStep] {
        &self.steps
    }

    /// The terminal verdict, or `None` if the pipeline has not returned yet.
    pub fn verdict(&self) -> Option<&Verdict> {
        self.verdict.as_ref()
    }

    /// True once finalized with a deny.
    pub fn is_denied(&self) -> bool {
        self.verdict.as_ref().is_some_and(Verdict::is_deny)
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_log_has_no_steps_and_no_verdict() {
        let log = DecisionLog::new();
        assert!(log.steps().is_empty());
        assert!(log.verdict().is_none());
        assert!(!log.is_denied());
    }

    #[test]
    fn steps_are_kept_in_the_order_they_were_recorded() {
        let mut log = DecisionLog::new();
        log.record("first", PluginMode::Sequential, PluginAction::Allowed);
        log.record(
            "second",
            PluginMode::Transform,
            PluginAction::ModifiedPayload,
        );
        log.record(
            "third",
            PluginMode::Concurrent,
            PluginAction::Denied(Box::new(PluginViolation::new("blocked", "no"))),
        );

        let names: Vec<&str> = log.steps().iter().map(|s| s.plugin_name.as_str()).collect();
        assert_eq!(names, ["first", "second", "third"]);
        assert_eq!(log.steps()[1].phase, PluginMode::Transform);
        assert!(matches!(log.steps()[2].action, PluginAction::Denied(_)));
    }

    #[test]
    fn a_finalized_deny_reports_denied_and_carries_the_violation() {
        let mut log = DecisionLog::new();
        log.finalize(Verdict::Deny(PluginViolation::new("blocked", "no")));

        assert!(log.is_denied());
        match log.verdict() {
            Some(Verdict::Deny(v)) => assert_eq!(v.code, "blocked"),
            other => panic!("expected a deny, got {other:?}"),
        }
    }

    #[test]
    fn a_finalized_allow_is_not_a_deny() {
        let mut log = DecisionLog::new();
        log.finalize(Verdict::Allow);

        assert!(!log.is_denied());
        assert!(matches!(log.verdict(), Some(Verdict::Allow)));
    }

    /// A suppressed block must not be read as consent, and it is the only
    /// record of the objection: the verdict is an allow and names nothing, so
    /// losing the violation here loses the reason entirely.
    #[test]
    fn deny_ignored_is_distinct_from_allowed_and_keeps_its_reason() {
        let action = PluginAction::DenyIgnored(Box::new(PluginViolation::new(
            "pii_present",
            "unredactable field",
        )));
        assert_ne!(action, PluginAction::Allowed);
        match &action {
            PluginAction::DenyIgnored(v) => {
                assert_eq!(v.code, "pii_present");
                assert_eq!(v.reason, "unredactable field");
            },
            other => panic!("expected DenyIgnored, got {other:?}"),
        }
        assert_ne!(PluginAction::Aborted, PluginAction::Error(String::new()));
    }
}
