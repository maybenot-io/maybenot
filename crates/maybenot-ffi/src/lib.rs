use core::{mem::MaybeUninit, str::FromStr, time::Duration};
use std::time::Instant;

use maybenot::{
    Framework, LimitDecoy, LimitDecoyFrac, LimitDecoyNone, LimitDelay, LimitDelayFrac,
    LimitDelayNone, Machine, MachineId, TriggerEvent,
};

mod error;
pub use error::MaybenotResult;

mod ffi;
pub use ffi::*;
use rand::rngs::{OsRng, ReseedingRng};

/// A dynamic limit that can be either no limit or a fraction-based
/// limit. This allows FFI to choose the limit type at runtime.
#[derive(Debug, Clone)]
enum DynamicLimitDecoy {
    None(LimitDecoyNone),
    Frac(LimitDecoyFrac),
}

impl LimitDecoy<Instant> for DynamicLimitDecoy {
    fn allow_decoy(&self, current_time: Instant, machine: MachineId) -> bool {
        match self {
            DynamicLimitDecoy::None(t) => t.allow_decoy(current_time, machine),
            DynamicLimitDecoy::Frac(t) => t.allow_decoy(current_time, machine),
        }
    }

    fn max_decoys(&self, current_time: Instant, machine: MachineId) -> usize {
        match self {
            DynamicLimitDecoy::None(t) => t.max_decoys(current_time, machine),
            DynamicLimitDecoy::Frac(t) => t.max_decoys(current_time, machine),
        }
    }

    fn packet_sent(&mut self, current_time: Instant) {
        match self {
            DynamicLimitDecoy::None(t) => t.packet_sent(current_time),
            DynamicLimitDecoy::Frac(t) => t.packet_sent(current_time),
        }
    }

    fn normal_queued(&mut self, current_time: Instant) {
        match self {
            DynamicLimitDecoy::None(t) => t.normal_queued(current_time),
            DynamicLimitDecoy::Frac(t) => t.normal_queued(current_time),
        }
    }

    fn decoy_queued(&mut self, current_time: Instant, machine: MachineId) {
        match self {
            DynamicLimitDecoy::None(t) => t.decoy_queued(current_time, machine),
            DynamicLimitDecoy::Frac(t) => t.decoy_queued(current_time, machine),
        }
    }

    fn congestion(&mut self, current_time: Instant) {
        match self {
            DynamicLimitDecoy::None(t) => t.congestion(current_time),
            DynamicLimitDecoy::Frac(t) => t.congestion(current_time),
        }
    }
}

/// A dynamic limit that can be either no limit or a fraction-based
/// limit for delays. This allows FFI to choose the limit type at
/// runtime.
#[derive(Debug, Clone)]
enum DynamicLimitDelay {
    None(LimitDelayNone),
    Frac(LimitDelayFrac<Instant>),
}

impl LimitDelay<Instant> for DynamicLimitDelay {
    fn allow_delay(&self, current_time: Instant, machine: MachineId) -> bool {
        match self {
            DynamicLimitDelay::None(t) => t.allow_delay(current_time, machine),
            DynamicLimitDelay::Frac(t) => t.allow_delay(current_time, machine),
        }
    }

    fn max_delayed_packets(&self, current_time: Instant, machine: MachineId) -> usize {
        match self {
            DynamicLimitDelay::None(t) => t.max_delayed_packets(current_time, machine),
            DynamicLimitDelay::Frac(t) => t.max_delayed_packets(current_time, machine),
        }
    }

    fn max_delayed_duration(&self, current_time: Instant, machine: MachineId) -> Duration {
        match self {
            DynamicLimitDelay::None(t) => t.max_delayed_duration(current_time, machine),
            DynamicLimitDelay::Frac(t) => t.max_delayed_duration(current_time, machine),
        }
    }

    fn delay_begin(&mut self, current_time: Instant) {
        match self {
            DynamicLimitDelay::None(t) => t.delay_begin(current_time),
            DynamicLimitDelay::Frac(t) => t.delay_begin(current_time),
        }
    }

    fn delay_end(&mut self, current_time: Instant) {
        match self {
            DynamicLimitDelay::None(t) => t.delay_end(current_time),
            DynamicLimitDelay::Frac(t) => t.delay_end(current_time),
        }
    }
}

/// A running Maybenot instance.
///
/// - Create it: [maybenot_start].
/// - Feed it actions: [maybenot_on_events].
/// - Stop it: [maybenot_stop].
pub struct MaybenotFramework {
    framework: Framework<Vec<Machine>, Rng, Instant, DynamicLimitDecoy, DynamicLimitDelay>,

    /// A buffer used internally for converting from [MaybenotEvent]s.
    events_buf: Vec<TriggerEvent>,
}

/// The randomness generator used for the framework.
///
/// This setup uses [OsRng] as the source of entropy, but extrapolates each call to [OsRng] into
/// at least [RNG_RESEED_THRESHOLD] bytes of randomness using [rand_chacha::ChaCha12Core].
///
/// This is the same Rng that [rand::thread_rng] uses internally,
/// but unlike thread_rng, this is Sync.
type Rng = ReseedingRng<rand_chacha::ChaCha12Core, OsRng>;
const RNG_RESEED_THRESHOLD: u64 = 1024 * 64; // 64 KiB

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MaybenotEvent {
    pub event_type: MaybenotEventType,

    /// The ID of the machine that triggered the event, if any.
    pub machine: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MaybenotDuration {
    /// Number of whole seconds
    pub secs: u64,

    /// A nanosecond fraction of a second.
    pub nanos: u32,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum MaybenotEventType {
    NormalRecv = 0,
    DecoyRecv = 1,
    PacketRecv = 2,

    NormalQueued = 3,
    DecoyQueued = 4,
    PacketSent = 5,

    BlockingBegin = 6,
    BlockingEnd = 7,

    TimerBegin = 8,
    TimerEnd = 9,
}

/// The action to be taken by the framework user.
#[repr(C, u32)]
#[derive(Debug, Clone, Copy)]
pub enum MaybenotAction {
    /// Cancel the timer for a machine.
    Cancel {
        /// The machine that generated the action.
        machine: usize,

        timer: MaybenotTimer,
    } = 0,

    /// Schedule decoy traffic to be injected after the given timeout for a
    /// machine.
    DecoyTraffic {
        /// The machine that generated the action.
        machine: usize,

        /// The number of packets to inject.
        n: usize,

        /// The time to wait before injecting decoy packets.
        timeout: MaybenotDuration,

        replace: bool,
        bypass: bool,
    } = 1,

    /// Schedule delay of outgoing traffic after the given timeout for a machine.
    DelayTraffic {
        /// The machine that generated the action.
        machine: usize,

        /// The time to wait before delay.
        timeout: MaybenotDuration,

        replace: bool,
        bypass: bool,

        /// The maximum duration to delay packets.
        duration: MaybenotDuration,

        /// The maximum number of packets to delay.
        n: usize,
    } = 2,

    /// Update the timer duration for a machine.
    UpdateTimer {
        machine: usize,

        duration: MaybenotDuration,

        replace: bool,
    } = 3,
}

/// The different types of timers used by a [Machine].
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum MaybenotTimer {
    /// The scheduled timer for actions with a timeout.
    Action = 0,

    /// The machine's internal timer, updated by the machine using [MaybenotAction::UpdateTimer].
    Internal = 1,

    /// Apply to all timers.
    All = 2,
}

impl MaybenotFramework {
    fn start(
        machines_str: &str,
        max_decoy_frac: f64,
        max_delay_frac: f64,
    ) -> Result<Self, MaybenotResult> {
        let machines: Vec<_> = machines_str
            .lines()
            .map(Machine::from_str)
            .collect::<Result<_, _>>()
            .map_err(|_e| MaybenotResult::InvalidMachineString)?;

        let machines_count = machines.len();

        let rng = Rng::new(RNG_RESEED_THRESHOLD, OsRng).unwrap();

        // Convert max_decoy_frac to limit: if 0, use no limit (allows all decoys)
        let decoy_limit = if max_decoy_frac > 0.0 {
            DynamicLimitDecoy::Frac(
                LimitDecoyFrac::new(max_decoy_frac).map_err(|_| MaybenotResult::StartFramework)?,
            )
        } else {
            DynamicLimitDecoy::None(LimitDecoyNone)
        };

        // Convert max_delay_frac to limit: if 0, use no limit (allows all delays)
        let delay_limit = if max_delay_frac > 0.0 {
            DynamicLimitDelay::Frac(
                LimitDelayFrac::new(max_delay_frac, Duration::from_secs(1), usize::MAX)
                    .map_err(|_| MaybenotResult::StartFramework)?,
            )
        } else {
            DynamicLimitDelay::None(LimitDelayNone)
        };

        let framework = Framework::new(machines, decoy_limit, delay_limit, Instant::now(), rng)
            .map_err(|_e| MaybenotResult::StartFramework)?;

        Ok(MaybenotFramework {
            framework,
            events_buf: Vec::with_capacity(machines_count),
        })
    }

    fn on_events(
        &mut self,
        events: &[MaybenotEvent],
        actions: &mut [MaybeUninit<MaybenotAction>],
    ) -> usize {
        let now = Instant::now();

        // convert from the repr(C) events and store them temporarily in our buffer
        self.events_buf.clear();
        for &event in events {
            self.events_buf.push(convert_event(event));
        }

        self.framework
            .trigger_events(&self.events_buf, now)
            // convert maybenot actions to repr(C) equivalents
            .map(convert_action)
            // write the actions to the out buffer
            // NOTE: trigger_events will not emit more than one action per machine.
            .zip(actions.iter_mut())
            .map(|(action, out)| out.write(action))
            .count()
    }
}

/// Convert an action from [maybenot] to our own `repr(C)` action type.
fn convert_action(action: &maybenot::TriggerAction) -> MaybenotAction {
    match *action {
        maybenot::TriggerAction::Cancel { machine, timer } => MaybenotAction::Cancel {
            machine: machine.into_raw(),
            timer: timer.into(),
        },
        maybenot::TriggerAction::DecoyTraffic {
            timeout,
            n,
            bypass,
            replace,
            machine,
        } => MaybenotAction::DecoyTraffic {
            timeout: timeout.into(),
            n,
            replace,
            bypass,
            machine: machine.into_raw(),
        },
        maybenot::TriggerAction::DelayTraffic {
            timeout,
            n,
            duration,
            bypass,
            replace,
            machine,
        } => MaybenotAction::DelayTraffic {
            timeout: timeout.into(),
            n,
            duration: duration.into(),
            replace,
            bypass,
            machine: machine.into_raw(),
        },
        maybenot::TriggerAction::UpdateTimer {
            duration,
            replace,
            machine,
        } => MaybenotAction::UpdateTimer {
            duration: duration.into(),
            replace,
            machine: machine.into_raw(),
        },
    }
}

fn convert_event(event: MaybenotEvent) -> TriggerEvent {
    let machine = MachineId::from_raw(event.machine);

    match event.event_type {
        MaybenotEventType::NormalRecv => TriggerEvent::NormalRecv,
        MaybenotEventType::DecoyRecv => TriggerEvent::DecoyRecv,
        MaybenotEventType::PacketRecv => TriggerEvent::PacketRecv,

        MaybenotEventType::NormalQueued => TriggerEvent::NormalQueued,
        MaybenotEventType::DecoyQueued => TriggerEvent::DecoyQueued { machine },
        MaybenotEventType::PacketSent => TriggerEvent::PacketSent,

        MaybenotEventType::BlockingBegin => TriggerEvent::DelayBegin { machine },
        MaybenotEventType::BlockingEnd => TriggerEvent::DelayEnd,

        MaybenotEventType::TimerBegin => TriggerEvent::TimerBegin { machine },
        MaybenotEventType::TimerEnd => TriggerEvent::TimerEnd { machine },
    }
}

impl From<Duration> for MaybenotDuration {
    #[inline]
    fn from(duration: Duration) -> Self {
        MaybenotDuration {
            secs: duration.as_secs(),
            nanos: duration.subsec_nanos(),
        }
    }
}

impl From<maybenot::Timer> for MaybenotTimer {
    fn from(timer: maybenot::Timer) -> Self {
        match timer {
            maybenot::Timer::Action => MaybenotTimer::Action,
            maybenot::Timer::Internal => MaybenotTimer::Internal,
            maybenot::Timer::All => MaybenotTimer::All,
        }
    }
}
