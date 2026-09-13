# PLAN_RESOURCE_LEAK_HARDENING.md

**Status:** Survey complete — hardening not started
**Created:** 2026-09-12
**Last Updated:** 2026-09-12

## Overview

Read-only survey of `src/` (all 19 modules), `macula-rust-ffi/src/lib.rs`,
and the tests/examples that reveal usage patterns, for potential memory and
resource leaks — run as a cross-check against the just-completed survey of
the C# sibling (`macula-dotnet/plans/PLAN_RESOURCE_LEAK_HARDENING.md`). No
code was changed; every finding below is verified against the current tree
with file:line references, and quinn 0.11.11's own Drop semantics were
checked in the vendored source (`send_stream.rs:344-362`,
`recv_stream.rs:509-531`, `endpoint.rs:718-728`, `connection.rs:929-948`)
before anything was claimed released or retained.

The headline result: **the C# survey's CRITICAL stream-slot leaks do not
exist in Rust.** quinn's own Drop impls release every dedicated stream
(dropped `SendStream` → FIN, dropped `RecvStream` → STOP_SENDING(0), last
`ConnectionRef` → implicit close), `OpenSessions` holds `Weak` handles
instead of strong ones, the inbound CALL queue is bounded at 64, both
crates forbid `unsafe` (`unsafe_code = "forbid"` in each Cargo.toml), and
UniFFI scaffolding owns all raw-pointer marshalling — there is no
hand-written `Box::into_raw`/`from_raw` anywhere. What remains is a set of
Rust-shaped resource-lifetime issues: abandoned detached handler tasks,
unobserved panics in fire-and-forget tasks, missing app-level stream
teardown on error paths, and FFI objects with no Drop-side protocol
signaling.

General hygiene found GOOD and not repeated here: `Pool::close` aborts and
awaits every background task via `JoinSet::shutdown` before draining links
(pool.rs:551-562); `PooledLink` state is never held across a round trip;
`Waiting` (control_channel.rs:827-836) removes a call's reply slot on every
exit path; `transport::connect`'s local `Endpoint` drop is safe (quinn's
`EndpointRef` keeps the driver alive while connections exist); the CBOR
decoder caps nesting (`MAX_NESTING_DEPTH = 128`), validates declared
lengths before slicing, and caps list preallocation (cbor.rs:317, 366-411,
491); `frame::MAX_FRAME_BYTES` (16 MiB) caps every frame decode
(frame.rs:41, 1087-1138); direct-dial lease accounting releases on every
request outcome (direct_dial.rs:1437-1454).

---

## Findings (ranked)

### CRITICAL

None. The three C# CRITICALs (F1-F3: dedicated streams never released,
consuming outbound stream slots until the connection dies) are **not
present**: every dedicated stream in this crate is owned by a `FrameStream`
whose quinn halves release the QUIC stream slot on drop. Verified against
quinn 0.11.11 source, not assumed. The residual gap is that this teardown
is bare (FIN + STOP_SENDING code 0) rather than an app-level
finish/abort — see F3, ranked MEDIUM for that reason.

### HIGH

#### F1. `serve_one_call_gated` timeout abandons the running handler task, detached
`connection.rs:978-993` (the `tokio::time::timeout(...).unwrap_or(...)`
wrap) + `connection.rs:1346` (`tokio::spawn(async move { handler(payload).await })`).

When the serve timeout fires (or the caller cancels the future), the
in-flight `build_call_reply` future is dropped, which drops the
`JoinHandle` of the spawned handler task **without aborting it**. The
handler keeps running to completion in the background, detached, holding
whatever it captured (its `Arc<CallHandler>` / `FfiCallHandler`, the
payload, any app state it moved in). A handler that hangs (waiting on a
network call, a lock, a blocking API) leaks its task forever; every
timed-out serve of a hung handler accumulates one detached task. An app
looping `serve_one_call` with short timeouts against a slow handler grows
background work without bound. The reply the detached handler eventually
produces is dropped as an unrouted frame, which is fine for the caller's
timeout contract — the leak is the task itself.

Fix direction: on timeout, abort the handler task (`JoinHandle::abort()`
inside `build_call_reply`'s own timeout/guard) or run handlers under an
explicit watchdog, so a timed-out serve leaves no live task; add a test
with a hung handler asserting the task count returns to baseline.

#### F2. Background tasks spawned without JoinHandle observation — a panic is unobserved, and a dead reader leaves a session that still reports live
`control_channel.rs:381` (reader task), `:382` (hand-off writer task),
`:960-967` (`Subscription::drop` → `runtime.spawn(remove_subscription)`),
`control_channel/drop_warning.rs:188-194` (interval closer),
`connection.rs:1346` (per-call handler).

Every one of these spawns discards its `JoinHandle`, so a panic inside is
observed by nothing (the default panic hook prints; the `JoinError` is
never awaited). The reader task is the sharpest case: `SessionInner::is_live`
(connection.rs:351-353) checks only `end_reason` and `close_reason` — a
reader that panicked leaves both `None`, so the session still reports
live, still sits in `open_sessions::live()` (as the registry's `Weak` is
upgradable through the app's own still-held handles), and is handed out
for reuse while it can never route a frame again. Retained resources: the
whole `Channel` (writer mutex, pending-calls map, subscriptions) plus a
QUIC connection, for as long as any `Session` handle exists.

Fix direction: retain and observe the reader/writer `JoinHandle`s (e.g.
store them in `Channel`, `end()` on a reader `Err(join)`), attach
observation continuations to the fire-and-forget spawns (`Subscription::drop`,
`drop_warning::record`), and treat a panic in `read` as a session end
(`SessionEndReason::StreamFailed`-shaped), which also drives the
`on_ended` unregister.

### MEDIUM

#### F3. Dedicated streams never receive an app-level finish/abort on any path
`content.rs:144-149` (`put`), `:180-185` (`get`), `:225-322`
(`put_block`/`put_manifest`/`get_block`/`get_manifest` error paths);
`stream.rs:202-229` (`open_on`, STREAM_OPEN write failure path);
`connection.rs:154-165` (the `abort_both`/`finish_and_stop_reading`
helpers that these callers never call).

`content::put`/`get` and `StreamHandle::open_on` open a dedicated stream
and simply drop the `FrameStream` on success and every failure path —
never `finish_and_stop_reading` (success) or `abort_both` (failure). The
stream is released by quinn's Drop (FIN + STOP_SENDING(0)), so this is
**not** the C# slot-exhaustion leak — but the peer's only signal is a bare
code-0 teardown: a mid-transfer failure (hash mismatch, remote error,
timeout) is indistinguishable from a clean end of transfer, and the
protocol's own refusal code (`stream::REFUSED_STREAM = 2`) is used only on
the accept/refuse paths, never here. Consequence is protocol-level
mis-signaling and harder debugging on the station side, not local memory
growth.

Fix direction: give `put_on`/`get_on`/`open_on` a teardown guard —
finish-and-stop on success, abort with an appropriate code on every error
return; same for `FrameStream::call`'s send-failure path.

#### F4. `fetch_content` timeout drops a leased, dialed session mid-transfer without release or GOODBYE
`direct_dial.rs:601-614`: on the `Err(_)` branch of the fetch timeout the
`fetch(target, ...)` future — which owns the `StationTarget`, the lease,
and the in-flight `FrameStream` — is dropped wholesale. The dialed
session's lease is never released through `Leases::release`, and the
session is closed only when the last handle drops, i.e. abruptly via
`SessionInner::drop` (connection.rs:341-348): no GOODBYE, no bounded drain,
the station sees a bare connection close. Released, not leaked — but the
lease accounting is bypassed, and a request that the app still holds a
handle to (through a clone) survives past its deadline with the
connection torn out from under it.

Fix direction: make the timeout branch release the target through the same
`run_then_release`/`close_last` path the non-timeout outcomes use, and
have dropped leases close leased sessions explicitly (GOODBYE) where a
runtime is available.

#### F5. FFI wrapper objects have no Drop that performs protocol teardown
`macula-rust-ffi/src/lib.rs:1626-1654` (`FfiSubscription`), `:1662-1789`
(`FfiStream`), `:733` (`FfiSessionLease`), `:865` (`FfiSession`).

UniFFI cannot await in `Drop`, so all four objects delegate teardown to
explicit methods (`close`, `abort`, `refuse`, `release`). A foreign
(Kotlin/Swift) caller that lets an object be GC'd without calling those
gets quinn's bare teardown (F3) plus: an **accepted** inbound stream
(`accept_stream`, lib.rs:1525-1540) that is never served and never
`refuse`d leaves the peer's `await_reply`/`recv` hanging until its own
timeout (no error, no refusal frame ever arrives), while the local stream
slot stays consumed for that whole window; a `FfiSession` GC'd without
`close` tears the connection down without GOODBYE (documented, but
every Ffi object makes it easier to hit); a `FfiSessionLease` GC'd without
`release` skips lease accounting exactly as in F4. Resources are
ultimately freed by Rust drops — this is protocol-lifetime hardening, the
FFI-shaped analog of the C# F6 finding.

Fix direction: where a runtime handle is available, mirror
`Subscription::drop`'s pattern (spawn a teardown task from `Drop`); at
minimum add `close`/`abort` destructor guidance and an accepted-stream
watchdog that refuses never-served streams after a bound.

### LOW

#### F6. Frame/reader buffers grow to the frame cap and never shrink
`connection.rs:72-78` (`FrameStream.buf`), `connection.rs:178-196`
(`recv_frame`), `control_channel.rs:838-884` (reader `buf`). Each buffer
grows to at most `frame::MAX_FRAME_BYTES` (~16 MiB) and retains that
capacity for the rest of the session's life; the inbound CALL queue
(control_channel.rs:51) can simultaneously hold 64 payloads of up to
16 MiB each worst case. Bounded — the C# equivalent of `Envelope.MaxFrameBytes`
is present and respected — but a memory-pressure knob under large-frame
traffic. Consider releasing/shrinking `FrameStream.buf` on finish and
capping aggregate queued payload bytes.

#### F7. Stale weak entries in `OpenSessions` when a session dies without `end()`
`open_sessions.rs:89-131`. Unregister happens through the `on_ended`
callback (connection.rs:515); if the reader task panics before `end()`
runs (F2's scenario), the weak entry survives until the next
`find`/`unregister` for that (identity, station) pair. Harmless (weak, ~80
bytes), bounded by pairs ever used — but prune-on-find is the only
recovery, and it should also run when `SessionInner::drop` fires outside
`end`.

#### F8. `KeyPair::save` leaves a `.tmp` file on failure before rename
`identity.rs:160-163` — same shape as the C# survey's
`KeyPair.Save` LOW: a write that fails at `fs::write`/`set_permissions`/
`rename` leaves the sibling `.tmp` behind. Delete on error.

#### F9. `StreamHandle::accept`'s shared-deadline loop can be monopolized by refused stream-open floods
`stream.rs:244-265` — the same note as the C# survey's LOW for
`AcceptAsync`: a peer flooding STREAM_OPENs that all get refused keeps the
loop consuming the one total deadline. Refused streams are properly
aborted (`refuse` → `abort_both(REFUSED_STREAM)`, stream.rs:109-112), so
this is a liveness/budget concern, not a leak.

#### F10. `Subscription::drop` spawn can silently fail outside a runtime
`control_channel.rs:954-969` — `try_current()` returning `Err` falls back
to the retain path, which is correct and documented; the `spawn` path's
fire-and-forget JoinHandle is part of F2. No action beyond F2's.

---

## Cross-check against the dotnet survey (record for completeness)

| dotnet finding | Rust status |
|----------------|-------------|
| F1 `ContentTransfer` never releases its stream | **Not present as a leak** — quinn Drop releases the QUIC stream (FIN + STOP_SENDING(0), verified in quinn 0.11.11 `send_stream.rs:344-362`, `recv_stream.rs:509-531`). Residual app-level teardown gap: F3 here. |
| F2 `StreamHandle.AcceptAsync` abandons stream on non-refusal failures | **Not present as a leak** — `open_inbound`'s `Inbound::Failed` and `accept`'s timeout both drop the `FrameStream`, which quinn releases (stream.rs:272-303, 250-263). Refusal paths use the proper `REFUSED_STREAM` abort. |
| F3 `StreamHandle.OpenAsync` leaks on STREAM_OPEN write failure | **Not present as a leak** — same quinn Drop release on the `stream.rs:222` error path. |
| F4 `OperationCanceledException` misclassified as timeout | **Not present** — Rust's typed errors keep session-end (`SessionEnded`) and timeout (`Timeout`) distinct; `tokio::time::timeout` only errors on its own timer. The timeout-drop *consequence* (abandoned work) surfaces as F1 here. |
| F5 Untrusted `manifest.Size` drives unbounded allocation | **Not present — deliberately addressed**: `get_on` grows the buffer only from individually hash-verified chunks (content.rs:202-219), and `from_wire` rejects `chunk_size: 0` and mismatched `chunk_count` (manifest.rs:352-368, 408-413). |
| F6 No `IDisposable` safety net on handles | **Resource side not present** — quinn's Drop *is* the safety net; the app-code side (no abort codes on drop) is F3/F5 here. |
| F7 Unbounded task fan-out per inbound CALL | **Mostly not present** — inbound queue bounded at 64 (control_channel.rs:51); the per-call handler task is awaited inline (connection.rs:1346), not fire-and-forget. The abandoned-on-timeout case is F1. |
| F8 `EventDedup` growth between sweeps | **Not present** — no event-dedup map exists in this crate (verified by search). |
| F9 Fire-and-forget close with unobserved fault | **Present, Rust-shaped** — F2 here (reader/writer/subscription-removal/drop-warning spawns, all JoinHandle-discarded). |
| F10 Publisher CTS ownership / unobserved callbacks | **Not present** — no CTS pattern; `run_publisher` (connection.rs:1050-1095) is fully awaited; fact-publish failures are deliberately discarded as in the reference. |
| F11 Dead subscriptions retained by ended channel | **Not present materially** — `end()` drops every entry's event sender (control_channel.rs:626-628); remaining `Entry` strings are bounded by session lifetime. |
| F12 Static `OpenSessions` registry retains undisposed sessions | **Not present** — registry holds `Weak` (open_sessions.rs:77) and unregisters via `on_ended` (connection.rs:515); dropped sessions are unreachable by `find`. Residual hygiene: F7. |
| LOW `.tmp` file after failed `KeyPair.Save` | **Present** — F8. |
| LOW accept-loop budget under refusal floods | **Present** — F9. |

**Rust-specific additions not in the dotnet survey:** F1 (detached handler
tasks — no equivalent "abandoned task on timeout" shape in the C# list),
F2's reader-panic-leaves-session-"live" consequence, F4 (lease bypass on
fetch timeout), F5 (UniFFI objects without Drop-side protocol teardown),
F6 (buffer retention). Also verified clean: `unsafe` is forbidden in both
crates, so the "unsafe code in ffi leaking across the boundary" item from
the survey list has no hand-written counterpart — UniFFI's generated
scaffolding owns all marshalling.

---

## Phases

- [ ] Phase 1 — Detached-task closure (F1, F2): abort handler tasks on
      serve timeout; retain and observe the reader/writer JoinHandles;
      panic in the reader ends the session (drives `on_ended` unregister).
      Test: N timed-out serves of a hung handler leave zero live tasks.
- [ ] Phase 2 — Dedicated-stream teardown (F3, F4): finish/abort guards on
      `content::put_on`/`get_on` and `StreamHandle::open_on`; lease-aware
      release on the `fetch_content` timeout branch. Test: repeated
      put/get and open-failure cycles show no station-side open-stream
      growth and correct RESET codes on failure.
- [ ] Phase 3 — FFI lifetime (F5): Drop-side teardown where a runtime is
      available (spawn-on-drop like `Subscription::drop`), destructor
      guidance, and a bounded watchdog refusing never-served accepted
      streams.
- [ ] Phase 4 — Hygiene (F6-F10): buffer release/caps, stale-weak prune
      on drop, `.tmp` cleanup, accept-loop budget.

## Files to Create/Modify

| File | Purpose | Status |
|------|---------|--------|
| `src/connection.rs` | F1 handler-task abort on timeout, F2 reader/writer JoinHandle observation, F6 buffer release | Not started |
| `src/content.rs` | F3 finish/abort teardown on `put_on`/`get_on` | Not started |
| `src/stream.rs` | F3 teardown on `open_on`/accept error paths, F9 accept budget | Not started |
| `src/direct_dial.rs` | F4 lease release + close on fetch-timeout drop | Not started |
| `src/control_channel.rs` | F2 spawned-task observation, F6 queue byte cap, F10 | Not started |
| `src/control_channel/drop_warning.rs` | F2 observation of the interval-closer spawn | Not started |
| `src/open_sessions.rs` | F7 prune on `SessionInner` drop | Not started |
| `src/identity.rs` | F8 `.tmp` cleanup on save failure | Not started |
| `macula-rust-ffi/src/lib.rs` | F5 Drop-side teardown, accepted-stream watchdog | Not started |
| `tests/` (new leak-regression tests) | Prove F1-F4 fixes: task-count stability, stream-count stability, correct abort codes | Not started |

## Success Criteria

- [ ] A live-session stress test (N sequential `content::put`/`get` calls,
      interleaved with induced failures) shows no growth in station-side
      open-stream count, and failure teardown carries a non-zero
      RESET_STREAM/STOP_SENDING code.
- [ ] `serve_one_call` with a hung handler, timed out 1000x, leaves zero
      additional live tasks (task count stable after each cycle).
- [ ] A panicking reader task ends the session (`end_reason` set,
      `on_ended` ran, `open_sessions` no longer finds it) instead of a
      live-reporting zombie.
- [ ] `fetch_content` timeout on a dialed session releases the lease and
      closes the session with GOODBYE, not a bare drop-close.
- [ ] A foreign-side GC of `FfiStream`/`FfiSubscription`/`FfiSessionLease`
      produces the same teardown (abort frame / UNSUBSCRIBE / lease
      release) as the explicit close/abort/refuse methods.
- [ ] All tests green (`cargo test` in workspace root and
      `macula-rust-ffi`), clippy clean under the repo's deny config, and
      `unsafe_code = "forbid"` still holds in both crates.
