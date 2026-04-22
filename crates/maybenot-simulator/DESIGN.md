# Simulator Design

Generated design document. To be confirmed/refined by Johan. Input for discussion.

## Trace Parsing and the Main Loop

Here's how `parse_trace` shapes the queue so that `pick_next` is cheap.

### The problem parsing has to solve

The simulator's main loop picks the next event from a `BinaryHeap<SimEvent>` (`src/lib.rs:251`). The naïve approach — convert every line of the trace into a `SimEvent`, push it all in, and let the heap sort it out — works, but has two bad properties:

1. **The heap is huge.** Every `pop()` and `push()` is O(log n) where n is the full trace length. A 100k-packet trace means every decoy/delay action a machine schedules pays log₂(100k) ≈ 17 comparisons.
2. **You can't react to defenses.** In real traffic, a server response only happens *because* the client's request arrived. If the client machine delays that request by 200 ms, the response must slide too. A flat pre-populated heap has no way to express "this event is caused by that one."

The parser solves both in the same move.

### The two-bucket split

`traffic_trace_prepare` (`src/traffic_parse.rs:222`) walks the parsed packet list once and classifies every event as **seed** or **dependent**:

- **Client-send events**: if no prior receive exists, the send is an *initial request* — goes to `client_simq_push`. Otherwise it's assumed to be a reply to the last receive, and gets recorded as `(packet_id, delta, ClientSend)` in `dependent_tx[prev_recv.packet_id]` (`src/traffic_parse.rs:237`).
- **Client-recv events**: the parser looks for a client-send that's old enough to plausibly be the request that caused this receive (`≥ 2 × one_way_delay` earlier, `src/traffic_parse.rs:259`). If it finds one, this receive becomes a dependent of that send. Otherwise it's a server-initiated push and goes to `endpoint_simq_push`.

`fill_simq` (`src/traffic_parse.rs:319`) then pushes only the two seed vectors into `SimQueue`, and stashes the dependency table on `SimInfo.dependent_tx` (`src/traffic_parse.rs:389`).

The result: the heap starts out holding **only the events that have no causal predecessor**. Everything else is an index lookup away, but not *in* the heap.

### How dependents enter the heap

When a `NormalRecv` event pops and the corresponding node processes it, `check_dependent_packets` (`src/topology/nodes.rs:114`) does exactly one thing:

```rust
if !si.dependent_tx[s_event.packet_id].is_empty() {
    for (new_pktidx, delta, event_kind) in &si.dependent_tx[s_event.packet_id] {
        sq.push(SimEvent {
            event: TriggerEvent::NormalQueued,
            time: s_event.time + additional_duration,
            ...
        });
    }
}
```

Called from `ClientBasic::handle_event` (`src/topology/nodes.rs:310`) and `EndpointBasic::handle_event` (`src/topology/nodes.rs:430`). The `delta` that was computed at parse time as the gap between the receive and the send it triggered is now *added to whatever time the receive actually happened at*. If a defense delayed the receive by 200 ms, its dependent send slides by 200 ms for free — no re-parsing, no rewriting of timestamps.

### Why the main loop stays fast

At any moment, the heap holds roughly:
- seed events not yet processed,
- dependent events unlocked by receives that have already fired,
- plus machine-generated decoys and internal control events.

In practice this is a small working set, not the full trace. `pick_next` in the no-defense case is a single `sq.pop()` (`src/lib.rs:739`) on a heap whose size is bounded by active-flow fan-out, not trace length. The Maybenot path (`src/maybenot_helpers.rs:78`) adds a constant-sized scan of each node's scheduled actions/timers and picks the earliest among {heap top, scheduled action, internal timer, delay expiry} — also O(1) beyond the heap peek.

### Two supporting details worth knowing

- **Timeline shift** (`src/traffic_parse.rs:349`): when the parser's `2 × one_way_delay` correction pushes some endpoint events to negative times, `fill_simq` shifts the whole timeline forward by `-min` so every `SimEvent.time` stays a non-negative `Duration`. `SimInfo.time_zero` records that offset so callers can reconstruct original-trace timestamps without the simulator itself having to carry signed times.
- **Deterministic tie-break** (`src/lib.rs:183-190`): `SimEvent::cmp` orders by `time`, then by `event_to_usize` (packets before control, wire before enqueue, normal before decoy), then by `q_sequence_nr` — a monotonically incremented counter that `SimQueue::push` assigns (`src/lib.rs:269`). Same heap contents always yield the same pop order, regardless of insertion noise.

The short version: parsing trades a one-time linear dependency analysis for a heap that stays small throughout the run, and the same `delta` values that encode dependencies also transparently absorb whatever time-shifts the defense introduces. That's the efficiency.

## Topology: nodes, links, and the coreside/edgeside convention

`NodeType` (`src/topology/nodes.rs:16`) has six variants: `ClientBasic`, `RouterBasic`, `EndpointBasic`, and the three Maybenot-enabled counterparts `ClientMaybenot`, `RelayMaybenot`, `RelayMaybenotEndpoint`. They differ in which link handles they carry and what `handle_event` will accept: `ClientBasic` only emits `NormalQueued`/`NormalRecv`; `EndpointBasic` only receives; routers forward; the Maybenot variants interpose delay/decoy logic before forwarding.

The directionality is a convention every node-lookup method relies on:

- **`coreside_*`** points *toward the endpoint* (away from the client).
- **`edgeside_*`** points *toward the client* (the return path).

So `get_coreside_out_id()` (`src/topology/nodes.rs:63`) returns the link a node uses to push traffic deeper into the network, and `get_edgeside_out_id()` (`src/topology/nodes.rs:78`) returns the link it uses to reply. Endpoints panic on `coreside_out`; clients panic on any `edgeside_*`. Routers additionally hold an `edgeside_in` for accepting return traffic and a `routes` lookup — `routes[node_id][in_link] = Some(out_link)` (`src/topology/mod.rs:84`) — so that a router receiving on a given link knows which link to forward on.

```
                coreside_out →          coreside_out →
   Client ─────────── Router/Relay ─────────── Endpoint
         ← edgeside_out           ← edgeside_out

   (Endpoint has no coreside_out — it only replies via edgeside_out.)
   (Router has edgeside_in on the return path; Endpoint does not.)

   Maybenot variant inserts defense nodes on the path:
     Client → ClientMaybenot → … → RelayMaybenot(Endpoint) → Endpoint
```

`parse_trace` uses this convention directly: initial client sends are placed at `topology.client` on the client's `get_coreside_out_id()`, initial endpoint-initiated sends at `topology.endpoint` on the endpoint's `get_edgeside_out_id()` (`src/traffic_parse.rs:353-387`). `check_dependent_packets` does the same lookup when injecting cascaded events.

Topologies come from TOML (`src/topology/parse.rs`, `load_topology_from_file` / `load_topology_from_str`) or from a baked-in `Setting` template — see the last section.

## Link sampling: how network delay enters event times

`LinkType` (`src/links/mod.rs:17`) has three variants: `FixedTput`, `HiTraceTput`, `StdTraceTput`. All three expose a single mutating method — `sample(current_duration, pkt_size) -> Duration` (`src/links/mod.rs:24`) — that returns the transmission-plus-queueing delay for one packet.

All realization of "the network took some time" happens in `make_network_receive_from_sent` (`src/topology/nodes.rs:152`):

```rust
let transmission_delay = link_state.links[link_id].sample(current_duration, link_state.packet_size);
let prop_us = if link.fixed_propagation() { link.get_prop_us_fixed() } else { link.get_prop_us_variable(...) };
// recv.time = sent.time + transmission + propagation
```

Two design notes worth internalizing:

- **Links are stateful.** `FixedTputLink::sample` (`src/links/mod.rs:153`) keeps a `next_busy_to_duration` cursor: a packet that arrives while the link is still draining the previous one accrues queueing delay. This is why `sample` takes `&mut self` and `NetworkLinkState` has to be threaded as `&mut` through the main loop.
- **Propagation can be time-varying.** `get_prop_us_variable` (`src/links/mod.rs:72`) indexes a `prop_us_vec` by `current_time_ms`, clamping to the last entry once the simulation outruns the measured window. This is how measured RTT traces get replayed; fixed links just return a constant.

Links also reset (`reset()`) and randomize (`randomize()`) per-run, which is how `NetworkLinkState::clone_randomized` (`src/topology/mod.rs:71`) produces independent Monte-Carlo runs.

## The `SimEvent` payload

A `SimEvent` (`src/lib.rs:54`) is not just `(time, event)`. It also carries:

- **`packet_id`** — index into `SimInfo.dependent_tx`. The sentinel `usize::MAX` (`src/lib.rs:296`) means "no trace row" — i.e. a machine-generated decoy or internal event. `SimQueue::no_normal_packets` filters on this to decide whether only machine-generated traffic is left.
- **`node_id` / `link_id`** — routing. `node_id` is what `pick_next` dispatches into (`topology.nodes[next.node_id].handle_event(...)`, `src/lib.rs:657`); `link_id` tells the link sampler which link to charge.
- **`contains_decoy`** — propagates through `PacketSent` → `PacketRecv` so the receiving side knows whether to emit `NormalRecv` or `DecoyRecv` (`src/topology/maybenot_nodes.rs:600`).
- **`bypass` / `replace`** — the Maybenot action flags. Their semantics are queue-level and covered below.
- **`q_sequence_nr`** — assigned by `SimQueue::push` for deterministic tie-breaks (already covered in the parsing section).

`is_client` is populated only on events written to the output trace (`src/lib.rs:694-696`); internal events leave it `false`.

## Maybenot wiring and `pick_next_maybenot`

Each Maybenot node (`ClientMaybenot`, `RelayMaybenot`, `RelayMaybenotEndpoint`) owns a `RefCell<MaybenotState>` (`src/topology/maybenot_nodes.rs:121`). The relevant fields for scheduling are:

- `action_producer` — usually a `maybenot::Framework`, wrapped through an `ActionProducer` trait so `sim_user_provided` can swap in a competing defense (`src/lib.rs:581`).
- `scheduled_action: Vec<Option<ScheduledAction>>` — one slot per machine, each holding `(TriggerAction, fire_time)`.
- `scheduled_internal_timer: Vec<Option<Duration>>` — framework-internal deadlines, one slot per machine.
- `delay_until: Option<Duration>` — set when a `DelayBegin` action fires, cleared on `DelayEnd`.

After every event the main loop processes, it calls `trigger_update` on whichever Maybenot node owns the event (`src/lib.rs:660-685`). That feeds the event into the framework, collects any resulting `TriggerAction`s, and parks them in the `scheduled_action` / `scheduled_internal_timer` slots.

`pick_next_maybenot` (`src/maybenot_helpers.rs:78`) is what makes those parked actions show up in the main loop. Instead of just `sq.pop()`, it races four time sources and picks the earliest:

1. the heap top (`sq.peek()`),
2. the minimum `scheduled_action.time` across both Maybenot nodes,
3. the minimum `scheduled_internal_timer` across both Maybenot nodes,
4. the earliest `delay_until` expiry.

This is the *only* place where non-heap time sources enter scheduling. Everything else — decoys being sent, delays ending, internal timers firing — gets synthesized into a `SimEvent` at the moment of selection and then flows through the normal `handle_event` path.

## Delay queues: `bypass`, `replace`, and drain strategies

When a `DelayBegin` action fires at a Maybenot node, `delay_until` is set. From that point on, outbound packets no longer go into `SimQueue` — they go into per-node `queue_normal` / `queue_decoy` `VecDeque`s (`src/topology/maybenot_nodes.rs:540-542`). `maybenot_handle_packet_sent_creation` (`src/topology/maybenot_nodes.rs:250`) is the branch point.

Two flags let defense logic punch through the delay without stalling legitimate traffic:

- **`bypass`** — if the event is marked `bypass=true` *and* the active delay is `delay_bypassable`, the packet skips the queue entirely and goes straight to `sq`. Used for packets the defense has decided shouldn't be held (e.g. control traffic).
- **`replace`** — a `DecoyQueued` marked `replace=true` does *not* enqueue if there's already a normal packet waiting — the normal packet goes out in its place. This prevents padding from piling up on top of already-delayed real traffic.

A third, v3-specific escape valve: `delay_max_packets` (`src/topology/maybenot_nodes.rs:137`) is the `DelayTraffic` N-cap. Each queued packet decrements it (`decrement_delay_n_cap`, `src/topology/maybenot_nodes.rs:327`); when it hits zero the code collapses `delay_until` to "right now" so the next `pick_next` iteration emits `DelayEnd` via the normal delay-expiry path.

`DelayEnd` (`src/topology/maybenot_nodes.rs:629`) drains both queues via `maybenot_release_delayed_events` (`src/topology/maybenot_nodes.rs:343`). Two drain strategies, controlled by `drain_delayed_by_time`:

- **Time-ordered** (`true`): normal and decoy events are merged by their original timestamp and released in chronological order.
- **Type-ordered** (`false`, default): all normal events first, then all decoy events.

Either way, every released event has its `time` overwritten to the current simulation time before being pushed onto the heap — the delay has "happened," and the events now race whatever else is pending.

## Integration delays

`Integration` (`src/integration.rs:8`) models the gap between what a Maybenot machine thinks and what a real implementation actually does. Three `BinDist` distributions, sampled per use:

- **`reporting_delay`** — time between an event happening in the protocol and the framework being told about it. Added to the timestamp passed to `trigger_update` (`src/lib.rs:664-682`), so the framework sees slightly stale events.
- **`action_delay`** — time between the framework deciding to act and the action materializing. Added when scheduled actions fire.
- **`trigger_delay`** — added to any scheduled action's fire time, so a "zero-timeout" decoy still takes a small nonzero time to execute.

Accessors live on `MaybenotState` (`src/topology/maybenot_nodes.rs:221-240`). When `Integration` is `None`, all three return zero — the framework sees a clean synchronous world.

This is a correction term, not its own subsystem, but it's worth naming: otherwise the `+reporting_delay` / `+action_delay` terms sprinkled around the framework boundary look unmotivated.

## Decoy and delay limits

`DecoyLimitConfig` (`src/limits.rs:22`) has three shapes:

- **`None`** — unbounded.
- **`Frac { frac }`** — cap decoys as a fraction of all packets.
- **`FracWindowed { frac, window_ms, min_normal }`** — same, but over a sliding window and with a floor on how many normal packets must have been seen.

`DelayLimitConfig` (`src/limits.rs:38`) has `None` and `Frac { frac, window_ms, max_packets }`.

These get wrapped into `DynamicLimitDecoy` / `DynamicLimitDelay` (`src/limits.rs:51`) — enum-dispatch wrappers that implement the `LimitDecoy` / `LimitDelay` traits from `maybenot` — and passed into `Framework::new` during `MaybenotState::new` (`src/topology/maybenot_nodes.rs:166-219`). The framework consults them at action time, inside `trigger_events`.

The practical consequence: limits are the *principled* way to bound defense overhead. The `max_trace_length` kill-switch on `SimulatorArgs` is a safety cap against infinite-decoy machines, but for realistic results the limit configs are what you tune.

## Settings templates

`Setting` (`src/settings/mod.rs:111`) gives you a set of named topologies without writing TOML:

- **`Vpn`** — Client (Maybenot) ↔ Relay (Maybenot) ↔ Endpoint.
- **`VpnCustom`** — same shape, caller-chosen link parameters.
- **`MultihopGuard`** / **`MultihopExit`** — two-hop topologies with Maybenot on the first or second hop respectively.
- **`Custom`** — load from a caller-supplied TOML file.

The first three are backed by embedded TOML (`src/settings/mod.rs:89-91`, `templates/vpn.toml` etc.) parsed through the same `load_topology_from_str` path as user TOML. `PACKET_SIZE_WG = 1500` and `PACKET_SIZE_TOR = 514` (`src/settings/mod.rs:29-33`) are the canonical MTUs — the value feeds directly into `LinkType::sample` via `NetworkLinkState.packet_size` (`src/topology/mod.rs:24`).

If you're starting out, `Setting::Vpn.create()` is the shortest path from zero to "valid topology + link-state." If you need more nodes, links, or unusual routing, fall back to TOML.
