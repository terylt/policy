// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Irreversible external effects, and the write-ahead log that records them.
//
// A decision record says what the engine ruled. It does not say what a
// plugin *did* to the outside world on the way: a token minted at an IdP,
// an approval granted. Those are irreversible and outlive the request, so
// recording them after the fact is not enough. A process that dies between
// "about to mint" and "minted" leaves no trace either way.
//
// The protocol is two-phase. A plugin durably records its intent before it
// acts, and records the outcome after. If the intent cannot be recorded the
// act does not happen (fail-closed), so a completed act always has a record.
// If the process dies in between, recovery finds the intent with no outcome
// and reconciles it against the participant.
//
// All of it is opt-in. With no log configured a plugin's effects run exactly
// as they would have, recording nothing.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;

use crate::error::PluginError;

/// Where an effect is in its lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectState {
    /// Intent durably recorded; nothing external has happened yet.
    Prepared,
    /// The external act completed.
    Confirmed,
    /// The external act provably did not happen.
    Rejected,
    /// The outcome is not known: the process died after the act, or the call
    /// failed in a way that does not say whether it landed. Resolved by
    /// reconciling against the participant via [`EffectRecord::key`].
    Unknown,
}

/// A record of one irreversible external effect.
///
/// The causing plugin fills the descriptive fields. The framework stamps
/// `plugin_name`, so a record cannot claim to come from a plugin that did not
/// produce it.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EffectRecord {
    /// Machine-readable kind, e.g. `"token_mint"`, `"approval_grant"`.
    pub kind: String,
    /// Human-readable description.
    pub description: String,
    /// Reconciliation key, threaded into the external call so an `Unknown`
    /// outcome can be resolved against the participant later.
    ///
    /// Must be **unique per attempt**. Recovery resolves keys across the whole
    /// log, so a key reused across retries lets an earlier attempt's terminal
    /// record mask a later attempt's orphaned intent, and the later attempt is
    /// then treated as complete when nobody knows whether it happened.
    pub key: String,
    /// Where in its lifecycle this record is.
    pub state: EffectState,
    /// Structured, effect-specific detail (audience, scopes, ttl).
    pub details: HashMap<String, serde_json::Value>,
    /// Which plugin caused the effect. Stamped by the framework, never
    /// self-reported.
    pub plugin_name: Option<String>,
}

impl EffectRecord {
    /// A fresh record of intent, before the act. `key` is the reconciliation
    /// key that rides into the external call.
    pub fn prepared(
        kind: impl Into<String>,
        description: impl Into<String>,
        key: impl Into<String>,
    ) -> Self {
        Self {
            kind: kind.into(),
            description: description.into(),
            key: key.into(),
            state: EffectState::Prepared,
            details: HashMap::new(),
            plugin_name: None,
        }
    }

    /// Attach a structured detail.
    #[must_use]
    pub fn with_detail(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    /// Move to another lifecycle state.
    #[must_use]
    pub fn into_state(mut self, state: EffectState) -> Self {
        self.state = state;
        self
    }
}

/// Resolves an effect left `Unknown` by asking an authoritative ledger whether
/// the act identified by [`EffectRecord::key`] actually happened.
///
/// The record is self-describing, so a reconciler reads its fields and performs
/// a keyed lookup. It needs no knowledge of which plugin caused the effect.
/// Returning [`EffectState::Unknown`] leaves the record for a later sweep.
///
/// Most participants expose no lookup by mint key, which is why
/// [`LogUnknownsReconciler`] is the default.
#[async_trait]
pub trait EffectReconciler: Send + Sync {
    /// Decide the terminal state of one unresolved effect.
    async fn reconcile(&self, effect: &EffectRecord) -> EffectState;
}

/// The default reconciler: there is no ledger to query, so it logs each
/// unresolved effect and leaves it `Unknown` for an operator.
///
/// This is the correct behaviour for a participant with no keyed lookup, which
/// today is all of them. Claiming `Rejected` instead would assert that a mint
/// did not happen when nobody knows.
#[derive(Debug, Default)]
pub struct LogUnknownsReconciler;

#[async_trait]
impl EffectReconciler for LogUnknownsReconciler {
    async fn reconcile(&self, effect: &EffectRecord) -> EffectState {
        tracing::warn!(
            effect_key = %effect.key,
            kind = %effect.kind,
            plugin = effect.plugin_name.as_deref().unwrap_or("?"),
            "effect left unresolved after a restart and no ledger can confirm it; \
             leaving it unknown for investigation"
        );
        EffectState::Unknown
    }
}

/// A durable, append-only sink for effect records: the write-ahead log.
///
/// `append` must not return `Ok` until the record is on stable storage. An
/// `Err` means the caller must not perform the act, which is what makes the
/// write-ahead guarantee real.
///
/// Implemented by a host that wants effects recorded somewhere other than a
/// file. [`FileEffectLog`] is the built-in implementation.
#[async_trait]
pub trait DurableEffectLog: Send + Sync + std::fmt::Debug {
    /// Durably record one effect.
    ///
    /// # Errors
    ///
    /// Returns an error when the record could not be persisted. The caller
    /// treats this as fail-closed and does not act.
    async fn append(&self, effect: &EffectRecord) -> Result<(), Box<PluginError>>;

    /// Recover after a restart: drop completed effects and reconcile the
    /// unresolved ones, recording each resolved outcome durably. Returns the
    /// effects still unresolved, for a later sweep.
    ///
    /// The default is a no-op, for logs with no recoverable on-disk state.
    ///
    /// # Errors
    ///
    /// Returns an error when the log cannot be read or rewritten.
    async fn recover_and_reconcile(
        &self,
        _reconciler: &dyn EffectReconciler,
    ) -> Result<Vec<EffectRecord>, Box<PluginError>> {
        Ok(Vec::new())
    }
}

/// Appends between automatic compactions. Effects are rare, so this bounds the
/// file without paying a rewrite per write.
const DEFAULT_COMPACTION_THRESHOLD: usize = 1024;

/// A file-backed write-ahead log. Each record is one JSON line, `fsync`'d
/// before `append` returns, so an intent is on stable storage before the act.
///
/// The append and `fsync` run on a blocking thread: a synchronous `fsync` must
/// never stall an async worker. The file is opened per append, which is fine
/// because effects are rare.
#[derive(Debug, Clone)]
pub struct FileEffectLog {
    path: Arc<std::path::PathBuf>,
    /// Serializes appends. `O_APPEND` makes each write land at the end of the
    /// file, but `write_all`'s partial-write loop leaves a window where two
    /// writers could interleave one record with another. One writer at a time
    /// closes it and gives recovery a deterministic order to read back.
    /// Cloned handles share the lock, because they share the file.
    write_lock: Arc<tokio::sync::Mutex<()>>,
    /// Appends since the last compaction, shared across cloned handles.
    appends_since_compaction: Arc<AtomicUsize>,
    /// Auto-compaction fires after this many appends. `0` disables it, leaving
    /// compaction to an explicit recovery.
    compaction_threshold: usize,
}

impl FileEffectLog {
    /// A log appending to `path`, creating the file if it does not exist.
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: Arc::new(path.into()),
            write_lock: Arc::new(tokio::sync::Mutex::new(())),
            appends_since_compaction: Arc::new(AtomicUsize::new(0)),
            compaction_threshold: DEFAULT_COMPACTION_THRESHOLD,
        }
    }

    /// Override the append count that triggers automatic compaction. `0`
    /// disables it.
    #[must_use]
    pub fn with_compaction_threshold(mut self, threshold: usize) -> Self {
        self.compaction_threshold = threshold;
        self
    }
}

#[async_trait]
impl DurableEffectLog for FileEffectLog {
    async fn append(&self, effect: &EffectRecord) -> Result<(), Box<PluginError>> {
        let mut line = serde_json::to_vec(effect)
            .map_err(|e| wal_error("serialize effect record", Some(Box::new(e))))?;
        line.push(b'\n');

        let path = Arc::clone(&self.path);
        // The lock is released before any compaction below: `recover` takes
        // the same lock, so holding it across the call would deadlock.
        {
            let _guard = self.write_lock.lock().await;
            tokio::task::spawn_blocking(move || -> Result<(), Box<PluginError>> {
                use std::io::Write as _;
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path.as_ref())
                    .map_err(|e| wal_error("open the log", Some(Box::new(e))))?;
                file.write_all(&line)
                    .map_err(|e| wal_error("write a record", Some(Box::new(e))))?;
                // The durability barrier. The record is on stable storage
                // before this returns, and therefore before the caller acts.
                file.sync_all()
                    .map_err(|e| wal_error("fsync the log", Some(Box::new(e))))?;
                Ok(())
            })
            .await
            .map_err(|e| wal_error("the append task failed", Some(Box::new(e))))??;
        }

        // Bound the file. A compaction failure is logged rather than returned:
        // the record above is already durable, so the append succeeded, and
        // reporting failure here would stop an act that has every right to
        // proceed.
        if self.compaction_threshold != 0 {
            let n = self
                .appends_since_compaction
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            if n >= self.compaction_threshold {
                self.appends_since_compaction.store(0, Ordering::Relaxed);
                if let Err(e) = self.recover().await {
                    tracing::warn!("effect log auto-compaction failed: {e}");
                }
            }
        }

        Ok(())
    }

    async fn recover_and_reconcile(
        &self,
        reconciler: &dyn EffectReconciler,
    ) -> Result<Vec<EffectRecord>, Box<PluginError>> {
        let summary = self.recover().await?;
        let mut resolved_any = false;
        let mut still_unknown = Vec::new();
        for rec in summary.unresolved {
            match reconciler.reconcile(&rec).await {
                state @ (EffectState::Confirmed | EffectState::Rejected) => {
                    self.append(&rec.clone().into_state(state)).await?;
                    resolved_any = true;
                },
                // Still unresolved. Keep it for the next sweep.
                _ => still_unknown.push(rec),
            }
        }
        if resolved_any {
            // A second pass drops the pairs the reconciler just completed.
            self.recover().await?;
        }
        Ok(still_unknown)
    }
}

/// The error a durable-write failure surfaces. `begin_effect` treats any error
/// from the log as fail-closed, so this is what stops an act from proceeding.
fn wal_error(
    what: &str,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
) -> Box<PluginError> {
    PluginError::Execution {
        plugin_name: "effect-log".into(),
        message: format!("effect log: could not {what}"),
        source,
        code: Some("effect_log_failed".into()),
        details: HashMap::new(),
        proto_error_code: None,
    }
    .boxed()
}

/// What one recovery sweep found.
#[derive(Debug, Default)]
pub struct RecoverySummary {
    /// Effects that completed, an intent matched by a terminal record, and
    /// were dropped from the log.
    pub compacted: usize,
    /// Effects with no terminal record: an intent whose act may or may not
    /// have happened, or an explicit unknown. Each needs reconciling against
    /// the participant via its `key`. These are retained in the rewritten log.
    pub unresolved: Vec<EffectRecord>,
}

impl FileEffectLog {
    /// Read the log, drop completed effects, and rewrite the file with only
    /// the unresolved records.
    ///
    /// This is both the crash-recovery entry point and the compaction that
    /// bounds the file. Idempotent, and a missing file is a no-op.
    ///
    /// # Errors
    ///
    /// Returns an error when the log cannot be read, parsed, or rewritten.
    pub async fn recover(&self) -> Result<RecoverySummary, Box<PluginError>> {
        let path = Arc::clone(&self.path);
        // Held across the read and the rewrite so no append lands in between
        // and is lost to the rename.
        let _guard = self.write_lock.lock().await;
        tokio::task::spawn_blocking(move || -> Result<RecoverySummary, Box<PluginError>> {
            let data = match std::fs::read_to_string(path.as_ref()) {
                Ok(d) => d,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(RecoverySummary::default());
                },
                Err(e) => return Err(wal_error("read the log", Some(Box::new(e)))),
            };

            let mut records: Vec<EffectRecord> = Vec::new();
            for (i, line) in data.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let rec = serde_json::from_str(line)
                    .map_err(|e| wal_error(&format!("parse line {}", i + 1), Some(Box::new(e))))?;
                records.push(rec);
            }

            // A key is resolved when some record for it reached a terminal
            // state. Everything else is unresolved.
            //
            // This matches across the whole file, which is why `key` has to be
            // unique per attempt: a plugin reusing one key across retries would
            // let an earlier attempt's terminal record mask a later attempt's
            // orphaned intent, and recovery would skip the one act nobody can
            // account for.
            let resolved: std::collections::HashSet<&str> = records
                .iter()
                .filter(|r| matches!(r.state, EffectState::Confirmed | EffectState::Rejected))
                .map(|r| r.key.as_str())
                .collect();

            // Keep the latest record per unresolved key, in first-seen order.
            let mut unresolved: Vec<EffectRecord> = Vec::new();
            let mut pos: HashMap<String, usize> = HashMap::new();
            for r in &records {
                if resolved.contains(r.key.as_str()) {
                    continue;
                }
                if let Some(slot) = pos.get(&r.key).and_then(|&i| unresolved.get_mut(i)) {
                    *slot = r.clone();
                } else {
                    pos.insert(r.key.clone(), unresolved.len());
                    unresolved.push(r.clone());
                }
            }
            let compacted = resolved.len();

            // Write the survivors to a temp file, fsync, then rename over the
            // original. The rename is atomic, so a crash mid-compaction leaves
            // either the old log or the new one, never a truncated one.
            let tmp = path.with_extension("recover.tmp");
            {
                use std::io::Write as _;
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&tmp)
                    .map_err(|e| wal_error("open the temp log", Some(Box::new(e))))?;
                for r in &unresolved {
                    let mut line = serde_json::to_vec(r)
                        .map_err(|e| wal_error("serialize during compaction", Some(Box::new(e))))?;
                    line.push(b'\n');
                    f.write_all(&line)
                        .map_err(|e| wal_error("write the temp log", Some(Box::new(e))))?;
                }
                f.sync_all()
                    .map_err(|e| wal_error("fsync the temp log", Some(Box::new(e))))?;
            }
            std::fs::rename(&tmp, path.as_ref())
                .map_err(|e| wal_error("rename the temp log", Some(Box::new(e))))?;

            Ok(RecoverySummary {
                compacted,
                unresolved,
            })
        })
        .await
        .map_err(|e| wal_error("the recovery task failed", Some(Box::new(e))))?
    }
}

/// What an executor offers a plugin that performs an effect: the optional
/// write-ahead log and the audit sinks that observe effects.
///
/// Built once per executor and shared by `Arc`, because attaching it costs a
/// clone per plugin per request and effects are rare.
#[derive(Default)]
pub struct EffectSink {
    log: Option<Arc<dyn DurableEffectLog>>,
    handlers: Vec<Arc<dyn crate::audit::AuditHandler>>,
}

impl std::fmt::Debug for EffectSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EffectSink")
            .field("log", &self.log.is_some())
            .field("handlers", &self.handlers.len())
            .finish()
    }
}

impl EffectSink {
    /// A sink recording to `log` and notifying `handlers`. Either may be
    /// empty: a host that configured a log but no sink still gets durability,
    /// and one that configured sinks but no log still gets the events.
    pub fn new(
        log: Option<Arc<dyn DurableEffectLog>>,
        handlers: Vec<Arc<dyn crate::audit::AuditHandler>>,
    ) -> Self {
        Self { log, handlers }
    }

    /// Whether this sink would record anything at all.
    pub fn is_empty(&self) -> bool {
        self.log.is_none() && self.handlers.is_empty()
    }

    /// The durable log, for the engine to run recovery against.
    pub fn log(&self) -> Option<Arc<dyn DurableEffectLog>> {
        self.log.clone()
    }
}

/// Whether the plugin holding these extensions may perform an irreversible
/// effect, and where the record goes if it does.
///
/// The payload is private and the type is deliberately not `Clone`. A plugin
/// that could take the `Arc` out, or clone the slot from the `&Extensions` it
/// is lent, could append records outside any invocation and under a
/// `plugin_name` it chose. For a log whose purpose is accounting for
/// irreversible acts, a forged record is worse than a missing one: a gap is
/// visible, a forgery is not.
///
/// The field on `Extensions` has to stay public, because functional-update
/// construction (`..Default::default()`) is used at hundreds of sites and Rust
/// forbids it when any field is invisible. A public *field* need not imply a
/// public *payload*, and the missing `Clone` is what closes the rest: without
/// it there is no way to take a copy out of the borrowed `Extensions` a plugin
/// is lent, so the slot cannot outlive the invocation it was built for.
///
/// ```compile_fail
/// use praxis_policy_core::effect::EffectLogSlot;
/// use praxis_policy_core::hooks::payload::Extensions;
/// let ext = Extensions::default();
/// let _stashed: EffectLogSlot = ext.effect_log.clone();
/// ```
#[derive(Debug, Default)]
pub struct EffectLogSlot(EffectLogState);

#[derive(Debug, Default)]
enum EffectLogState {
    /// Not the extensions a handler was given: a copy, or one built by hand.
    ///
    /// The default, and what `Extensions::clone` produces. Effects are refused
    /// here because a copy is detached from the invocation that authorized
    /// them. Without this, a plugin in a phase that may not act could clone
    /// its extensions and perform the act through the copy, and a plugin that
    /// may act could clone away the recording. The executor sets a real state
    /// on every view it hands a plugin, so this is only ever reached through a
    /// copy.
    #[default]
    Detached,
    /// Effects may be performed and nothing records them. What a host that
    /// configured no auditing gets: a plugin's effects run exactly as they
    /// would have.
    Unrecorded,
    /// Effects may be performed and are recorded.
    Recorded {
        sink: Arc<EffectSink>,
        /// Stamped onto every record, so attribution comes from the executor
        /// rather than from whatever the plugin put in the record.
        plugin_name: Arc<str>,
    },
    /// Effects may not be performed from this phase.
    NotPermitted(crate::plugin::PluginMode),
}

impl EffectLogSlot {
    /// Effects permitted, nothing recording them.
    #[must_use]
    pub fn unrecorded() -> Self {
        Self(EffectLogState::Unrecorded)
    }

    /// Effects permitted and recorded, attributed to `plugin_name`.
    #[must_use]
    pub fn recorded(sink: Arc<EffectSink>, plugin_name: &str) -> Self {
        Self(EffectLogState::Recorded {
            sink,
            plugin_name: Arc::from(plugin_name),
        })
    }

    /// Effects refused, because this phase cannot perform them soundly.
    #[must_use]
    pub fn not_permitted(mode: crate::plugin::PluginMode) -> Self {
        Self(EffectLogState::NotPermitted(mode))
    }

    /// Whether an effect performed here would be recorded anywhere.
    #[must_use]
    pub fn is_recorded(&self) -> bool {
        matches!(self.0, EffectLogState::Recorded { .. })
    }
}

/// The error a plugin gets for performing an effect through a copy of its
/// extensions rather than the ones it was handed.
fn detached_error() -> Box<PluginError> {
    PluginError::Execution {
        plugin_name: "effect".into(),
        message: "these extensions are a copy, not the ones this handler was given, so the \
                  effect cannot be attributed to an invocation or recorded against it. \
                  Perform effects on the `&Extensions` passed to `handle`."
            .into(),
        source: None,
        code: Some("effect_extensions_detached".into()),
        details: HashMap::new(),
        proto_error_code: None,
    }
    .boxed()
}

/// The error a plugin gets for performing an effect from a phase that cannot
/// support one. It names the fix, because the alternative is a mint that runs
/// with no record and no complaint.
fn phase_error(mode: crate::plugin::PluginMode) -> Box<PluginError> {
    PluginError::Execution {
        plugin_name: "effect".into(),
        message: format!(
            "a plugin in {mode:?} mode cannot perform an irreversible effect: work in this              phase is cancelled or discarded when the pipeline short-circuits, and an              external act cannot be taken back. Move the plugin to sequential or transform              mode, where it runs to completion and its result is honored."
        ),
        source: None,
        code: Some("effect_phase_not_permitted".into()),
        details: HashMap::new(),
        proto_error_code: None,
    }
    .boxed()
}

impl crate::hooks::payload::Extensions {
    /// Record the intent to perform an irreversible effect, before performing
    /// it.
    ///
    /// Fail-closed when a log is configured: an error means the intent is not
    /// on stable storage, so the caller must not act. With no log configured
    /// this records nothing and returns `Ok`, which is what makes auditing
    /// optional rather than load-bearing.
    ///
    /// Prefer [`Self::perform_effect`], which brackets the act so the protocol
    /// cannot be skipped or reordered.
    ///
    /// # Errors
    ///
    /// Returns an error when this phase may not perform effects, or when a
    /// configured log could not durably record the intent.
    pub async fn begin_effect(&self, effect: &EffectRecord) -> Result<(), Box<PluginError>> {
        self.emit_effect(effect, EffectState::Prepared).await
    }

    /// Record how an effect turned out.
    ///
    /// Unlike [`Self::begin_effect`] this is not fail-closed: the act has
    /// already happened, so a write failure here cannot un-happen it. The
    /// record stays unresolved for recovery to reconcile, and the caller is
    /// free to log and carry on.
    ///
    /// # Errors
    ///
    /// Returns an error when this phase may not perform effects, or when a
    /// configured log could not record the outcome.
    pub async fn complete_effect(
        &self,
        effect: &EffectRecord,
        state: EffectState,
    ) -> Result<(), Box<PluginError>> {
        self.emit_effect(effect, state).await
    }

    /// Perform an irreversible external act under write-ahead recording.
    ///
    /// Brackets `act` between a fail-closed [`Self::begin_effect`] and a
    /// best-effort [`Self::complete_effect`], so a caller cannot skip,
    /// reorder, or forget the protocol.
    ///
    /// - If the intent cannot be recorded, `act` never runs.
    /// - On success the effect is recorded `Confirmed`.
    /// - On failure it is recorded `Unknown`, not `Rejected`. A call that
    ///   errored may still have landed at the participant, with the response
    ///   lost on the way back, so recovery reconciles it by `key` instead of
    ///   asserting it did not happen.
    ///
    /// # Errors
    ///
    /// Returns the write-ahead failure when the intent could not be recorded,
    /// otherwise whatever `act` returned.
    pub async fn perform_effect<F, Fut, T>(
        &self,
        effect: &EffectRecord,
        act: F,
    ) -> Result<T, Box<PluginError>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, Box<PluginError>>>,
    {
        self.begin_effect(effect).await?;

        let outcome = act().await;

        let terminal = if outcome.is_ok() {
            EffectState::Confirmed
        } else {
            EffectState::Unknown
        };
        if let Err(e) = self.complete_effect(effect, terminal).await {
            tracing::warn!(
                effect_key = %effect.key,
                "the outcome of an effect was not recorded: {e}"
            );
        }

        outcome
    }

    /// Write one lifecycle record, then tell the audit sinks about it.
    async fn emit_effect(
        &self,
        effect: &EffectRecord,
        state: EffectState,
    ) -> Result<(), Box<PluginError>> {
        let (sink, plugin_name) = match &self.effect_log.0 {
            EffectLogState::Unrecorded => return Ok(()),
            EffectLogState::Detached => return Err(detached_error()),
            EffectLogState::NotPermitted(mode) => return Err(phase_error(*mode)),
            EffectLogState::Recorded { sink, plugin_name } => (sink, plugin_name),
        };

        let mut record = effect.clone().into_state(state);
        // Attribution comes from the executor, so a record cannot claim to
        // come from a plugin that did not produce it.
        record.plugin_name = Some(plugin_name.to_string());

        // Durability first. A sink that saw the event while the log rejected
        // it would report an act the write-ahead guarantee says never happened.
        if let Some(log) = &sink.log {
            log.append(&record).await?;
        }
        for handler in &sink.handlers {
            handler.on_effect(&record, self).await;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use std::sync::atomic::AtomicU32;

    use serde_json::json;

    use super::*;

    /// A distinct path per test. No temp-dir crate is pulled in for this.
    fn wal_path(tag: &str) -> std::path::PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("ppe_{tag}_{}_{n}.ndjson", std::process::id()))
    }

    /// Removes the log and its compaction temp file when the test ends,
    /// including on a panic.
    struct Cleanup(std::path::PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::remove_file(self.0.with_extension("recover.tmp"));
        }
    }

    fn lines(path: &std::path::Path) -> Vec<EffectRecord> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("a well-formed record"))
            .collect()
    }

    #[test]
    fn a_prepared_record_starts_as_intent_and_names_no_plugin() {
        let e = EffectRecord::prepared("token_mint", "exchange for workday-api", "k-1")
            .with_detail("audience", "workday-api")
            .with_detail("scopes", json!(["read_compensation"]));

        assert_eq!(e.kind, "token_mint");
        assert_eq!(e.key, "k-1");
        assert_eq!(e.state, EffectState::Prepared);
        assert_eq!(e.details["audience"], "workday-api");
        // The framework stamps this, so a plugin-built record carries nothing.
        assert!(e.plugin_name.is_none());
    }

    #[tokio::test]
    async fn an_appended_record_is_on_disk_when_append_returns() {
        let path = wal_path("append");
        let _c = Cleanup(path.clone());
        let log = FileEffectLog::new(&path);

        log.append(&EffectRecord::prepared("token_mint", "d", "k-1"))
            .await
            .unwrap();

        // The whole write-ahead guarantee is that this holds the instant
        // append returns, before the caller performs the act.
        let on_disk = lines(&path);
        assert_eq!(on_disk.len(), 1);
        assert_eq!(on_disk[0].key, "k-1");
        assert_eq!(on_disk[0].state, EffectState::Prepared);
    }

    #[tokio::test]
    async fn a_completed_effect_is_dropped_and_an_orphan_is_kept() {
        let path = wal_path("recover");
        let _c = Cleanup(path.clone());
        let log = FileEffectLog::new(&path).with_compaction_threshold(0);

        // One effect that ran to completion.
        let done = EffectRecord::prepared("token_mint", "d", "done");
        log.append(&done).await.unwrap();
        log.append(&done.clone().into_state(EffectState::Confirmed))
            .await
            .unwrap();
        // One that recorded intent and never reported an outcome, which is
        // what a crash between the two writes leaves behind.
        log.append(&EffectRecord::prepared("token_mint", "d", "orphan"))
            .await
            .unwrap();

        let summary = log.recover().await.unwrap();

        assert_eq!(summary.compacted, 1);
        assert_eq!(summary.unresolved.len(), 1);
        assert_eq!(summary.unresolved[0].key, "orphan");
        // And the rewritten file holds only the survivor.
        assert_eq!(lines(&path).len(), 1);
        assert_eq!(lines(&path)[0].key, "orphan");
    }

    #[tokio::test]
    async fn a_rejected_outcome_counts_as_resolved() {
        let path = wal_path("rejected");
        let _c = Cleanup(path.clone());
        let log = FileEffectLog::new(&path).with_compaction_threshold(0);

        let e = EffectRecord::prepared("token_mint", "d", "k-1");
        log.append(&e).await.unwrap();
        log.append(&e.into_state(EffectState::Rejected))
            .await
            .unwrap();

        let summary = log.recover().await.unwrap();
        assert_eq!(summary.compacted, 1);
        assert!(summary.unresolved.is_empty());
    }

    #[tokio::test]
    async fn recovering_a_log_that_was_never_written_is_a_no_op() {
        let path = wal_path("missing");
        let _c = Cleanup(path.clone());

        let summary = FileEffectLog::new(&path).recover().await.unwrap();

        assert_eq!(summary.compacted, 0);
        assert!(summary.unresolved.is_empty());
    }

    #[tokio::test]
    async fn recovery_is_idempotent() {
        let path = wal_path("idempotent");
        let _c = Cleanup(path.clone());
        let log = FileEffectLog::new(&path).with_compaction_threshold(0);
        log.append(&EffectRecord::prepared("token_mint", "d", "orphan"))
            .await
            .unwrap();

        let first = log.recover().await.unwrap();
        let second = log.recover().await.unwrap();

        assert_eq!(first.unresolved.len(), 1);
        assert_eq!(
            second.unresolved.len(),
            1,
            "a second sweep finds the same orphan"
        );
        assert_eq!(lines(&path).len(), 1, "and does not duplicate it");
    }

    /// A reconciler that answers the same way for every effect.
    struct Fixed(EffectState);

    #[async_trait]
    impl EffectReconciler for Fixed {
        async fn reconcile(&self, _effect: &EffectRecord) -> EffectState {
            self.0.clone()
        }
    }

    #[tokio::test]
    async fn a_reconciled_effect_is_recorded_and_compacted_away() {
        let path = wal_path("reconcile_ok");
        let _c = Cleanup(path.clone());
        let log = FileEffectLog::new(&path).with_compaction_threshold(0);
        log.append(&EffectRecord::prepared("token_mint", "d", "orphan"))
            .await
            .unwrap();

        let still = log
            .recover_and_reconcile(&Fixed(EffectState::Confirmed))
            .await
            .unwrap();

        assert!(
            still.is_empty(),
            "the ledger answered, so nothing is left open"
        );
        assert!(
            lines(&path).is_empty(),
            "and the resolved pair is compacted out"
        );
    }

    /// The default case: nothing can confirm the act, so the record stays open
    /// rather than being written off as if it never happened.
    #[tokio::test]
    async fn an_unresolvable_effect_is_kept_not_marked_rejected() {
        let path = wal_path("reconcile_unknown");
        let _c = Cleanup(path.clone());
        let log = FileEffectLog::new(&path).with_compaction_threshold(0);
        log.append(&EffectRecord::prepared("token_mint", "d", "orphan"))
            .await
            .unwrap();

        let still = log
            .recover_and_reconcile(&LogUnknownsReconciler)
            .await
            .unwrap();

        assert_eq!(still.len(), 1);
        assert_eq!(still[0].key, "orphan");
        assert_eq!(
            lines(&path).len(),
            1,
            "and it survives in the log for a later sweep"
        );
    }

    #[tokio::test]
    async fn concurrent_appends_do_not_interleave() {
        let path = wal_path("concurrent");
        let _c = Cleanup(path.clone());
        let log = FileEffectLog::new(&path).with_compaction_threshold(0);

        let mut tasks = Vec::new();
        for i in 0..32 {
            let log = log.clone();
            tasks.push(tokio::spawn(async move {
                log.append(&EffectRecord::prepared("token_mint", "d", format!("k-{i}")))
                    .await
                    .unwrap();
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }

        // Every record parses, which is the property the write lock buys: a
        // torn line would fail to deserialize and take recovery down with it.
        let on_disk = lines(&path);
        assert_eq!(on_disk.len(), 32);
        let keys: std::collections::HashSet<&str> =
            on_disk.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(keys.len(), 32, "no record was lost or duplicated");
    }

    #[tokio::test]
    async fn crossing_the_threshold_compacts_without_failing_the_append() {
        let path = wal_path("autocompact");
        let _c = Cleanup(path.clone());
        let log = FileEffectLog::new(&path).with_compaction_threshold(2);

        let e = EffectRecord::prepared("token_mint", "d", "k-1");
        log.append(&e).await.unwrap();
        log.append(&e.clone().into_state(EffectState::Confirmed))
            .await
            .unwrap();

        // The second append crosses the threshold and compacts the completed
        // pair away. The append itself still reports success.
        assert!(lines(&path).is_empty());
    }

    #[tokio::test]
    async fn a_log_that_cannot_be_written_fails_closed() {
        // A path under a plain file cannot be opened, so the append fails.
        // What matters is that it reports the failure rather than swallowing
        // it: the caller reads an error here as "do not act".
        let blocker = wal_path("blocker");
        let _c = Cleanup(blocker.clone());
        std::fs::write(&blocker, b"not a directory").unwrap();
        let log = FileEffectLog::new(blocker.join("nested.ndjson"));

        let result = log
            .append(&EffectRecord::prepared("token_mint", "d", "k-1"))
            .await;

        assert!(result.is_err(), "an unwritable log must not report success");
    }

    // =================================================================
    // The bracket on Extensions
    // =================================================================

    use crate::hooks::payload::Extensions;

    /// A log that refuses every write, standing in for a full disk.
    #[derive(Debug)]
    struct RefusingLog;

    #[async_trait]
    impl DurableEffectLog for RefusingLog {
        async fn append(&self, _effect: &EffectRecord) -> Result<(), Box<PluginError>> {
            Err(wal_error("write anything", None))
        }
    }

    /// A log that records what it was asked to write.
    #[derive(Debug, Default)]
    struct SpyLog(std::sync::Mutex<Vec<EffectRecord>>);

    impl SpyLog {
        fn seen(&self) -> Vec<EffectRecord> {
            self.0.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl DurableEffectLog for SpyLog {
        async fn append(&self, effect: &EffectRecord) -> Result<(), Box<PluginError>> {
            self.0.lock().unwrap().push(effect.clone());
            Ok(())
        }
    }

    fn ext_with(slot: EffectLogSlot) -> Extensions {
        Extensions {
            effect_log: slot,
            ..Default::default()
        }
    }

    fn recorded_ext(log: Arc<dyn DurableEffectLog>, plugin: &str) -> Extensions {
        ext_with(EffectLogSlot::recorded(
            Arc::new(EffectSink::new(Some(log), Vec::new())),
            plugin,
        ))
    }

    /// Auditing off must not change what a plugin does. This is the case an
    /// operator gets by default, and the delegator has to keep working in it.
    #[tokio::test]
    async fn with_nothing_recording_the_act_still_runs() {
        let ext = ext_with(EffectLogSlot::unrecorded());
        let effect = EffectRecord::prepared("token_mint", "d", "k-1");

        let out: i32 = ext
            .perform_effect(&effect, || async { Ok(7) })
            .await
            .unwrap();

        assert_eq!(out, 7);
        assert!(!ext.effect_log.is_recorded());
    }

    #[tokio::test]
    async fn a_successful_act_is_recorded_as_intent_then_confirmed() {
        let log = Arc::new(SpyLog::default());
        let ext = recorded_ext(log.clone(), "delegator");
        let effect = EffectRecord::prepared("token_mint", "d", "k-1");

        ext.perform_effect(&effect, || async { Ok(()) })
            .await
            .unwrap();

        let seen = log.seen();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].state, EffectState::Prepared);
        assert_eq!(seen[1].state, EffectState::Confirmed);
        // Attribution comes from the executor, not from the record the plugin
        // built, which carried no name at all.
        assert_eq!(seen[0].plugin_name.as_deref(), Some("delegator"));
        assert!(effect.plugin_name.is_none());
    }

    /// A failed call may still have landed at the participant, so the outcome
    /// is unknown rather than rejected. Recording it as rejected would assert
    /// that no token was minted when nobody can say.
    #[tokio::test]
    async fn a_failed_act_is_recorded_unknown_not_rejected() {
        let log = Arc::new(SpyLog::default());
        let ext = recorded_ext(log.clone(), "delegator");
        let effect = EffectRecord::prepared("token_mint", "d", "k-1");

        let result: Result<(), _> = ext
            .perform_effect(&effect, || async {
                Err(PluginError::Config {
                    message: "idp unreachable".into(),
                }
                .boxed())
            })
            .await;

        assert!(result.is_err(), "the caller still sees its own failure");
        let seen = log.seen();
        assert_eq!(seen[1].state, EffectState::Unknown);
    }

    /// The write-ahead guarantee: no durable intent, no act.
    #[tokio::test]
    async fn an_unrecordable_intent_stops_the_act() {
        let ext = recorded_ext(Arc::new(RefusingLog), "delegator");
        let effect = EffectRecord::prepared("token_mint", "d", "k-1");
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let ran_in = Arc::clone(&ran);
        let result: Result<(), _> = ext
            .perform_effect(&effect, || async move {
                ran_in.store(true, Ordering::Relaxed);
                Ok(())
            })
            .await;

        assert!(result.is_err());
        assert!(
            !ran.load(Ordering::Relaxed),
            "the act must not run when its intent was not recorded"
        );
    }

    /// A phase whose work gets cancelled or discarded cannot perform an act
    /// that cannot be taken back. The error names the fix rather than letting
    /// the mint run unrecorded.
    #[tokio::test]
    async fn a_phase_that_cannot_support_effects_refuses_them() {
        let ext = ext_with(EffectLogSlot::not_permitted(
            crate::plugin::PluginMode::Concurrent,
        ));
        let effect = EffectRecord::prepared("token_mint", "d", "k-1");
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let ran_in = Arc::clone(&ran);
        let result: Result<(), _> = ext
            .perform_effect(&effect, || async move {
                ran_in.store(true, Ordering::Relaxed);
                Ok(())
            })
            .await;

        let err = result.unwrap_err().to_string();
        assert!(!ran.load(Ordering::Relaxed), "the act must not run");
        assert!(
            err.contains("sequential or transform"),
            "the error should name the fix, got: {err}"
        );
    }

    /// Cloning `Extensions` must not carry the slot: a clone that kept it
    /// could outlive the invocation and write records under a plugin name
    /// that is no longer the one running.
    #[test]
    fn cloning_extensions_drops_the_effect_slot() {
        let ext = recorded_ext(Arc::new(SpyLog::default()), "delegator");
        assert!(ext.effect_log.is_recorded());

        assert!(!ext.clone().effect_log.is_recorded());
    }

    /// The slot being non-`Clone` stops a plugin copying it directly, but
    /// `Extensions` itself is cloneable and has to stay that way. If a copy
    /// permitted effects, a plugin in a phase that may not act could clone its
    /// way around the gate, and one that may act could clone away the
    /// recording. A copy refuses instead.
    #[tokio::test]
    async fn a_copy_of_the_extensions_cannot_perform_an_effect() {
        let effect = EffectRecord::prepared("token_mint", "d", "k-1");

        for (label, original) in [
            (
                "a refused phase",
                ext_with(EffectLogSlot::not_permitted(
                    crate::plugin::PluginMode::Concurrent,
                )),
            ),
            (
                "a permitted, recorded phase",
                recorded_ext(Arc::new(SpyLog::default()), "delegator"),
            ),
        ] {
            let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let ran_in = Arc::clone(&ran);
            let result: Result<(), _> = original
                .clone()
                .perform_effect(&effect, || async move {
                    ran_in.store(true, Ordering::Relaxed);
                    Ok(())
                })
                .await;

            assert!(result.is_err(), "{label}: a copy must refuse");
            assert!(
                !ran.load(Ordering::Relaxed),
                "{label}: the act must not run through a copy"
            );
        }
    }

    /// A hand-built `Extensions` is a copy for this purpose too: the executor
    /// sets a real state on every view it hands a plugin, so anything else is
    /// detached from an invocation.
    #[tokio::test]
    async fn a_default_extensions_cannot_perform_an_effect() {
        let effect = EffectRecord::prepared("token_mint", "d", "k-1");

        let result: Result<(), _> = Extensions::default()
            .perform_effect(&effect, || async { Ok(()) })
            .await;

        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("passed to `handle`"),
            "the error should name where effects belong, got: {err}"
        );
    }

    /// Modes are the single answer to which phases may act, so the executor
    /// and any config check agree rather than each deciding for itself.
    #[test]
    fn only_the_serial_modes_permit_effects() {
        use crate::plugin::PluginMode;
        assert!(PluginMode::Sequential.permits_effects());
        assert!(PluginMode::Transform.permits_effects());
        assert!(!PluginMode::Audit.permits_effects());
        assert!(!PluginMode::Concurrent.permits_effects());
        assert!(!PluginMode::FireAndForget.permits_effects());
        assert!(!PluginMode::Disabled.permits_effects());
    }

    /// Retries append a second unresolved record under the same key. Recovery
    /// keeps the latest, so a sweep reports the current state of the attempt
    /// rather than the intent it started from.
    #[tokio::test]
    async fn the_latest_record_wins_for_an_unresolved_key() {
        let path = wal_path("latest");
        let _c = Cleanup(path.clone());
        let log = FileEffectLog::new(&path).with_compaction_threshold(0);

        let e = EffectRecord::prepared("token_mint", "d", "k-1");
        log.append(&e).await.unwrap();
        log.append(&e.clone().into_state(EffectState::Unknown))
            .await
            .unwrap();

        let summary = log.recover().await.unwrap();

        assert_eq!(summary.unresolved.len(), 1, "one key, one record");
        assert_eq!(summary.unresolved[0].state, EffectState::Unknown);
    }

    /// A torn trailing write leaves a blank line. Recovery reads past it
    /// instead of failing and stranding every record in the file.
    #[tokio::test]
    async fn blank_lines_in_the_log_are_skipped() {
        let path = wal_path("blank");
        let _c = Cleanup(path.clone());
        let log = FileEffectLog::new(&path).with_compaction_threshold(0);
        log.append(&EffectRecord::prepared("token_mint", "d", "k-1"))
            .await
            .unwrap();
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            f.write_all(b"\n\n").unwrap();
        }

        let summary = log.recover().await.unwrap();

        assert_eq!(summary.unresolved.len(), 1);
    }

    /// A host implementing the trait for a sink with no readable back-end gets
    /// a recovery that reports nothing rather than having to write one.
    #[tokio::test]
    async fn a_log_without_recoverable_state_recovers_nothing() {
        #[derive(Debug)]
        struct AppendOnly;

        #[async_trait]
        impl DurableEffectLog for AppendOnly {
            async fn append(&self, _effect: &EffectRecord) -> Result<(), Box<PluginError>> {
                Ok(())
            }
        }

        let left = AppendOnly
            .recover_and_reconcile(&LogUnknownsReconciler)
            .await
            .unwrap();

        assert!(left.is_empty());
    }
}
