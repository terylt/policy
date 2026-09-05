// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// The audit sink: an observation-only consumer invoked at the pipeline's
// verdict with the decision log.
//
// An `AuditHandler` is not a `HookHandler<H>`. A hook handler returns a
// `PluginResult` and can therefore allow, deny or modify; this returns
// nothing, so a sink sees the verdict and every plugin's action but cannot
// influence either. The type carries that property, which is why sinks are
// their own family rather than a special case inside the engine.
//
// The engine attaches sinks; the executor invokes them once per pipeline
// run, at the verdict, with the final payload, extensions and decision log.

use async_trait::async_trait;

use crate::decision::DecisionLog;
use crate::effect::EffectRecord;
use crate::hooks::payload::{Extensions, PluginPayload};

/// An observation-only consumer of pipeline decisions.
///
/// Implemented by audit plugins. The executor calls [`AuditHandler::handle`]
/// once per pipeline invocation, after the verdict is decided, for allowed
/// and denied requests alike.
#[async_trait]
pub trait AuditHandler: Send + Sync {
    /// Observe one finished pipeline invocation.
    ///
    /// The executor awaits this before returning the pipeline result, so a
    /// verdict that was emitted cannot be lost to a crash and a consumer
    /// needs no drop-detection for the steady state. Changing this to
    /// fire-and-forget would weaken that guarantee without any signal at the
    /// call sites that rely on it.
    ///
    /// The cost is that sink latency sits on the request path, bounded per
    /// sink by the plugin timeout and run sequentially. Keep `handle` cheap:
    /// serialize, hash, append. A sink writing to a network destination
    /// should hand off to its own queue rather than block here.
    ///
    /// * `payload` is the message as it stood at the verdict.
    /// * `extensions` are the final extensions.
    /// * `decisions` is what each plugin did and how the pipeline ruled.
    async fn handle(
        &self,
        payload: &dyn PluginPayload,
        extensions: &Extensions,
        decisions: &DecisionLog,
    );

    /// Observe an irreversible external act a plugin caused, as its own event
    /// separate from the per-invocation decision.
    ///
    /// Fired at each lifecycle transition, so a sink sees the intent before
    /// the act and the outcome after. `extensions` carries the same ambient
    /// context a decision gets, so a sink can correlate the effect with the
    /// request that caused it rather than working from the record alone.
    ///
    /// The default ignores effects, for a sink that only cares about verdicts.
    async fn on_effect(&self, _effect: &EffectRecord, _extensions: &Extensions) {}

    /// A short identifier used in error logs when a sink panics or times out.
    fn name(&self) -> &str {
        "audit"
    }
}
