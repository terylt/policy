<!--
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Praxis Contributors
-->

# Auditing

PPE decides who may call which tool and what comes back. Auditing is the record
of those decisions, and of the irreversible acts its plugins perform to carry
them out.

There are two records and they answer different questions. A **decision** says
how the pipeline ruled on one request: which plugins ran, what each did, and
whether the request was allowed or blocked. An **effect** says what a plugin
did to the outside world, such as minting a token at an IdP. Effects outlive
the request and cannot be undone, which is why they are recorded separately and
before the fact rather than after it.

Both are off until configured.

What consumes them is a **sink**: a plugin the engine hands each record to,
which decides what the record looks like and where it goes. The engine builds
the records and owns when they are emitted; a sink only serializes. PPE ships
one, `audit-logger`, and a deployment needing a different format or destination
writes its own.

## What the engine promises

A verdict that was reached is emitted. Emission happens at the executor's
return points rather than in a pipeline phase, so allow, deny and modify all
produce one record and nobody has to reason about which phase runs before which
deny.

When an effect log is configured, a completed act has a durable record of its
intent. The record is `fsync`ed before the act happens, and if it cannot be
written the act does not happen. That is what makes a crash recoverable: an
intent with no outcome means the act may or may not have occurred, which is a
question the **participant** can be asked: the external system the act was
performed against, such as the IdP that would have minted the token.

Durable here means the record was written to the local filesystem and `fsync`ed
before the logging append returns, so it survives the process dying and the machine
losing power. The append that creates the log also syncs the directory
holding it, because a file's own `fsync` does not make the directory entry
naming it durable, and a crash in that window would otherwise leave no file at
all.

It does not mean the record is replicated, and it is only as good as the
storage underneath: a device that acknowledges a flush before the data is on
stable media will lose records a crash should have kept. Nothing above that
layer can detect it.

A plugin behaves the same whether or not auditing is on. There is no capability
a plugin needs and no setting that makes a working deployment stop working.
Turning auditing off costs the record, not the behavior.

What the engine does not promise is that a record reached storage before the
response left. Sinks are awaited, but a sink that buffers internally before
writing to a network destination is past the point the engine can see.

## Turning it on

The reference `audit-logger` runs as a sink when it lists no hooks:

```yaml
plugins:
  - name: audit
    kind: audit/logger
    mode: audit
    config:
      destination: stderr      # or `tracing`
      source: gateway-eu-1     # optional, stamped on every record
```

Any plugin becomes a sink by overriding `Plugin::as_audit_handler`. A sink has
two entry points. `handle` receives every decision. `on_effect` receives every
effect, and has a default that ignores them, so a sink that only cares about
verdicts implements nothing extra.

Effect records need a log:

```yaml
engine_settings:
  effect_log_path: /var/lib/praxis/effects.ndjson
  effect_log_compaction_threshold: 1024   # optional; 0 disables auto-compaction
```

With a path set, intent is durably recorded before a plugin acts. Without one,
effects still reach a sink's `on_effect`, but nothing survives a restart, so an
act interrupted by a crash leaves nothing behind to follow up.

The file holds one JSON record per line and is compacted in place: once an
effect has both an intent and an outcome the pair is dropped, so it tracks what
is in flight rather than growing without bound.

A host that wires plugins in code calls `PolicyEngine::set_effect_log` before
`initialize`. That install does not survive `load_config`, which rebuilds the
executor from the config it is given, so a log that has to outlive a reload
belongs in config.

A record says which plugins ran and how the pipeline ruled. It does not say
whether any of them changed the request on the way through. A **content hash**
answers that: a digest of the payload taken at entry and again at the end. Equal
digests mean nothing altered the content, different ones mean something did, and
a reader learns which without the audit trail holding either version.

Withholding the content is the point rather than a limitation. A redaction
plugin exists to take content out of a request, and writing that content into an
audit record puts it straight back. A digest says the content changed, or did
not, and nothing else about it.

```yaml
engine_settings:
  capture_content_provenance: true
```

Only payloads that opt in are hashed, which today means the CMF
`MessagePayload`. Anything else records no digest rather than a misleading one.
It is off by default because hashing sits on the request path.

## The records

A decision:

```json
{
  "ts": "2026-09-06T10:15:00.123Z",
  "plugin": "audit",
  "verdict": { "deny": {
    "code": "not_permitted",
    "reason": "no grant covers this tool",
    "plugin": "cedar-pdp"
  }},
  "decision_steps": [
    { "plugin": "identity-jwt", "phase": "Sequential", "action": "allowed" },
    { "plugin": "cedar-pdp", "phase": "Sequential", "action": "denied",
      "detail": { "code": "not_permitted", "reason": "no grant covers this tool" } }
  ],
  "span": {
    "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
    "span_id": "3c9f7d21e4075c68",
    "parent_span_id": "71e5093fd0c41822"
  },
  "taint": { "input": ["PII"], "final": ["CONFIDENTIAL", "PII"] }
}
```

`decision_steps` is in execution order. `action` is one of `allowed`, `denied`,
`deny_ignored`, `modified_payload`, `modified_extensions`, `aborted` or
`error`; the ones with something to say also carry `detail`.

`deny_ignored` means a plugin in a phase that cannot block asked to stop and was
overruled. It is not an allow, and a consumer mapping actions onto a disposition
that reads it as one will report the opposite of what the plugin asked for. The
verdict names nothing in that case, so the step is the only place the objection
survives.

`span` is W3C trace context, the same identifiers a tracing system uses to
stitch one end-to-end request back together out of the hops that served it. The
`trace_id` is shared by everything belonging to that request, the `span_id`
names this interception, and the `parent_span_id` names the call that caused it.
A reader with records from several hops can rebuild the order they happened in.
PPE stamps these but does not propagate trace context downstream, so chaining
across hops needs the host to carry it.

`taint` tracks security labels, the markers plugins attach to a request to
record what kind of data it is carrying, such as `PII`. Labels only accumulate,
never disappear, so the difference between the labels at entry and the labels at
the end is exactly what this node added.

`content` appears only with provenance enabled, holding `input_hash` and
`output_hash`.

An effect is its own event:

```json
{
  "event": "effect",
  "effect_kind": "token_mint",
  "effect_state": "confirmed",
  "effect_key": "9f1c...",
  "effect_plugin": "oauth-delegator",
  "effect_details": { "audience": "https://hr.example.com", "scope": "read:compensation" }
}
```

`effect_plugin` is stamped from the plugin the executor was running, not from
anything the plugin supplied, so a record cannot claim to come from somewhere
it did not.

## Effects

An effect moves through four states.

| State | Meaning |
|---|---|
| `prepared` | Intent recorded. Nothing external has happened yet. |
| `confirmed` | The act completed. |
| `rejected` | The act provably did not happen. |
| `unknown` | Nobody can say. Reconcile it. |

`unknown` is the one that matters. A call that timed out may still have landed
at the participant with the answer lost coming back, so recording it as
`rejected` asserts no token was minted when nothing checked. The OAuth
delegator maps precisely: a non-2xx is `rejected`, a timeout or unreachable IdP
is `unknown`, and a 2xx whose body will not parse is `confirmed`, because the
token exists whether or not we managed to read it.

### Which phases may act

Only `sequential` and `transform`. A plugin in any other mode is refused, with
a violation naming the plugin, the mode and the key to change.

This is not about auditing and does not switch off with it. A concurrent branch
is cancelled when another branch short-circuits the phase, `audit` is read-only
by contract, and `fire_and_forget` runs after the verdict is returned. An act in
any of them happens for work the pipeline discarded, and an external act cannot
be discarded. A delegator configured in `concurrent` mode was minting a real
credential and having the result thrown away.

The same refusal applies to a copy of a plugin's extensions. Effects are
performed on the `&Extensions` a handler was given. A clone is detached from
the invocation that authorised it, and without the refusal a plugin could clone
its way around the phase rule.

### Recovery

A restart leaves whatever was in flight when the process stopped: intents whose
outcome was never written. Settling those is **reconciliation**, and it means
asking the participant that would have performed the act whether it did, using
the key the intent recorded. Only the participant knows.

`PolicyEngine::initialize` sweeps the log once, before traffic. Completed
effects are compacted away and the rest are reconciled with an external service
that can answer for the participant, if one is configured.

In practice there is nothing to configure. The question an orphaned intent
raises is "did this mint land at the IdP before we died", and an OAuth IdP has
no endpoint that takes a mint key and reports whether that token was issued, so
the question has nowhere to go.

The reconciler PPE ships by default connects to nothing. It records that the
effect is unresolved, and leaves it `unknown` for an operator to chase.

A host with an authoritative issuance ledger, one that does know what was
minted, implements `EffectReconciler` and calls
`PolicyEngine::recover_effects_with`. The reconciler reads the self-describing
record and looks up `EffectRecord::key`, so it is specific to the participant at
most, never to the plugin.

`EffectRecord::key` must be unique per attempt. Recovery resolves keys across
the whole file, so a key reused across retries lets an earlier attempt's outcome
mask a later attempt's orphaned intent, and the one act nobody can account for
is the one skipped.

## Writing a sink

```rust
use std::sync::Arc;
use async_trait::async_trait;
use praxis_policy_core::audit::AuditHandler;
use praxis_policy_core::decision::{DecisionLog, Verdict};
use praxis_policy_core::effect::EffectRecord;
use praxis_policy_core::hooks::payload::{Extensions, PluginPayload};
use praxis_policy_core::plugin::{Plugin, PluginConfig};

struct MySink { cfg: PluginConfig }

#[async_trait]
impl AuditHandler for MySink {
    async fn handle(
        &self,
        payload: &dyn PluginPayload,
        extensions: &Extensions,
        decisions: &DecisionLog,
    ) {
        let blocked = matches!(decisions.verdict(), Some(Verdict::Deny(_)));
        let _ = (payload, extensions, blocked);
    }

    // Optional. Effects only reach a sink that wants them.
    async fn on_effect(&self, _effect: &EffectRecord, _extensions: &Extensions) {}

    fn name(&self) -> &str { &self.cfg.name }
}

impl Plugin for MySink {
    fn config(&self) -> &PluginConfig { &self.cfg }

    fn as_audit_handler(self: Arc<Self>) -> Option<Arc<dyn AuditHandler>> {
        Some(self)
    }
}
```

`handle` runs once per pipeline invocation. `on_effect` runs once per lifecycle
transition, so a completed mint calls it twice, once for the intent and once
for the outcome, and a consumer counting mints should count terminal states
rather than calls.

A sink fires for every hook family, so `payload` is not always a CMF
`MessagePayload`. Downcast and handle the case where it is not.

The executor awaits every sink before returning the pipeline result, so a
verdict that was emitted cannot be lost to a crash. The cost is that sink
latency is request latency. A sink writing to a network destination should hand
off to its own queue rather than block. Each call is bounded by the plugin
timeout and its panics are contained; a sink that fails is logged and skipped,
because the verdict is already decided and a lost record does not justify
failing the request.

## Performing an effect

```rust
use praxis_policy_core::effect::EffectRecord;

let intent = EffectRecord::prepared("token_mint", "exchange for hr-api", fresh_key())
    .with_detail("audience", "https://hr.example.com");

let token = ext.perform_effect(&intent, || async {
    idp.mint().await          // the irreversible act
}).await?;
```

`perform_effect` brackets the act so the protocol cannot be skipped or
reordered. If the intent cannot be recorded the act never runs. On success the
effect is `confirmed`, on failure `unknown`. A plugin that can tell a refusal
from a lost answer should call `begin_effect` and `complete_effect` directly and
classify the outcome itself, as the OAuth delegator does.

## What it costs

| Setting | Cost per invocation |
|---|---|
| Nothing configured | A length check. |
| A sink attached | A span, so two UUIDs and two allocations, plus the taint labels, plus the sink's work. |
| `effect_log_path` | One `fsync` per lifecycle transition. Effects are rare. |
| `capture_content_provenance` | One hash of the payload, plus one per sink. |

Provenance is built only when a sink will read it. Decision steps and the
verdict are recorded either way, since the phases record them as they run.

## When something is wrong

A denied request produces no record. Check the logger is in sink mode with no
`hooks:` listed; with hooks listed it is a post-hook observer and never runs on
the deny path.

`delegation.effects_not_permitted`, or an `effect_phase_not_permitted` error.
The plugin is in a mode that cannot perform irreversible acts. Set its `mode:`
to `sequential` or `transform`.

`effect_extensions_detached`. The plugin called `perform_effect` on a copy of
its extensions instead of the `&Extensions` passed to `handle`.

`delegation.effect_log_failed`. The phase is fine but the record could not be
written; check the path is writable. The delegation is denied rather than
minting a credential nothing accounts for.

Recovery reports unresolved effects at startup. Expected with the default
reconciler, which cannot confirm anything and leaves them `unknown`. Each names
its `key` and the plugin that caused it. Resolving them means asking the
participant, or installing a reconciler that can.

## See also

- [`assertions.md`](assertions.md) for what the engine puts on the wire
- `crates/ppe-core/src/audit.rs` for the sink trait
- `crates/ppe-core/src/decision.rs` for the decision log
- `crates/ppe-core/src/effect.rs` for effect records, the log and recovery
