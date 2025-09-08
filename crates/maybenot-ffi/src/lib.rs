use core::{mem::MaybeUninit, str::FromStr, time::Duration};
use std::time::Instant;

use maybenot::{Framework, Machine, MachineId, TriggerEvent};

mod error;
pub use error::MaybenotResult;

mod ffi;
pub use ffi::*;
use rand::rngs::{OsRng, ReseedingRng};

/// A running Maybenot instance.
///
/// - Create it: [maybenot_start].
/// - Feed it actions: [maybenot_on_events].
/// - Stop it: [maybenot_stop].
pub struct MaybenotFramework {
    framework: Framework<Vec<Machine>, Rng>,

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
    PaddingRecv = 1,
    TunnelRecv = 2,

    NormalSent = 3,
    PaddingSent = 4,
    TunnelSent = 5,

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

    /// Schedule padding to be injected after the given timeout for a machine.
    SendPadding {
        /// The machine that generated the action.
        machine: usize,

        /// The time to wait before injecting a padding packet.
        timeout: MaybenotDuration,

        replace: bool,
        bypass: bool,
    } = 1,

    /// Schedule blocking of outgoing traffic after the given timeout for a machine.
    BlockOutgoing {
        /// The machine that generated the action.
        machine: usize,

        /// The time to wait before blocking.
        timeout: MaybenotDuration,

        replace: bool,
        bypass: bool,

        /// How long to block.
        duration: MaybenotDuration,
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
        max_padding_frac: f64,
        max_blocking_frac: f64,
    ) -> Result<Self, MaybenotResult> {
        let machines: Vec<_> = machines_str
            .lines()
            .map(Machine::from_str)
            .collect::<Result<_, _>>()
            .map_err(|_e| MaybenotResult::InvalidMachineString)?;

        let machines_count = machines.len();

        let rng = Rng::new(RNG_RESEED_THRESHOLD, OsRng).unwrap();

        let framework = Framework::new(
            machines,
            max_padding_frac,
            max_blocking_frac,
            Instant::now(),
            rng,
        )
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
        maybenot::TriggerAction::SendPadding {
            timeout,
            bypass,
            replace,
            machine,
        } => MaybenotAction::SendPadding {
            timeout: timeout.into(),
            replace,
            bypass,
            machine: machine.into_raw(),
        },
        maybenot::TriggerAction::BlockOutgoing {
            timeout,
            duration,
            bypass,
            replace,
            machine,
        } => MaybenotAction::BlockOutgoing {
            timeout: timeout.into(),
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
        MaybenotEventType::PaddingRecv => TriggerEvent::PaddingRecv,
        MaybenotEventType::TunnelRecv => TriggerEvent::TunnelRecv,

        MaybenotEventType::NormalSent => TriggerEvent::NormalSent,
        MaybenotEventType::PaddingSent => TriggerEvent::PaddingSent { machine },
        MaybenotEventType::TunnelSent => TriggerEvent::TunnelSent,

        MaybenotEventType::BlockingBegin => TriggerEvent::BlockingBegin { machine },
        MaybenotEventType::BlockingEnd => TriggerEvent::BlockingEnd,

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
