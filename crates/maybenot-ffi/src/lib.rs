use core::{mem::MaybeUninit, str::FromStr, time::Duration};
use std::time::Instant;

use maybenot::{
    framework::{Framework, MachineId, TriggerEvent},
    machine::Machine,
};

mod error;
pub use error::*;

mod ffi;
pub use ffi::*;

/// A running Maybenot instance.
///
/// - Create it: [maybenot_start].
/// - Feed it actions: [maybenot_on_event].
/// - Stop it: [maybenot_stop].
pub struct MaybenotFramework {
    framework: Framework<Vec<Machine>>,
}

#[repr(C)]
#[derive(Debug)]
pub struct MaybenotEvent {
    pub event_type: MaybenotEventType,

    /// The number of bytes that was sent or received.
    pub xmit_bytes: u16,

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
    /// We sent a normal packet.
    NonpaddingSent = 0,

    /// We received a normal packet.
    NonpaddingReceived = 1,

    /// We send a padding packet.
    PaddingSent = 2,

    /// We received a padding packet.
    PaddingReceived = 3,
}

#[repr(C, u32)]
#[derive(Debug, Clone, Copy)]
pub enum MaybenotAction {
    Cancel {
        /// The machine that generated the action.
        machine: usize,
    } = 0,

    /// Send a padding packet.
    InjectPadding {
        /// The machine that generated the action.
        machine: usize,

        /// The time to wait before injecting a padding packet.
        timeout: MaybenotDuration,

        replace: bool,
        bypass: bool,

        /// The size of the padding packet.
        size: u16,
    } = 1,

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
}

impl MaybenotFramework {
    pub fn start(
        machines_str: &str,
        max_padding_bytes: f64,
        max_blocking_bytes: f64,
        mtu: u16,
    ) -> Result<Self, Error> {
        let machines: Vec<_> = machines_str
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .filter(|line| !line.starts_with('#'))
            .map(Machine::from_str)
            .collect::<Result<_, _>>()
            .map_err(|_e| Error::InvalidMachineString)?;

        let framework = Framework::new(
            machines,
            max_padding_bytes,
            max_blocking_bytes,
            mtu,
            Instant::now(),
        )
        .map_err(|_e| Error::StartFramework)?;

        Ok(MaybenotFramework { framework })
    }

    pub fn on_event(
        &mut self,
        event: MaybenotEvent,
        actions: &mut [MaybeUninit<MaybenotAction>],
    ) -> usize {
        let num_actions = self
            .framework
            .trigger_events(&[convert_event(event)], Instant::now())
            // convert maybenot actions to repr(C) equivalents
            .map(convert_action)
            // write the actions to the out buffer
            .zip(actions.iter_mut())
            .map(|(action, out)| out.write(action))
            .count();

        num_actions
    }
}

/// Convert an action from [maybenot] to our own `repr(C)` action type.
fn convert_action(action: &maybenot::framework::Action) -> MaybenotAction {
    match *action {
        maybenot::framework::Action::Cancel { machine } => MaybenotAction::Cancel {
            machine: machine.into_raw(),
        },
        maybenot::framework::Action::InjectPadding {
            timeout,
            size,
            bypass,
            replace,
            machine,
        } => MaybenotAction::InjectPadding {
            timeout: timeout.into(),
            size,
            replace,
            bypass,
            machine: machine.into_raw(),
        },
        maybenot::framework::Action::BlockOutgoing {
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
    }
}

fn convert_event(event: MaybenotEvent) -> TriggerEvent {
    match event.event_type {
        MaybenotEventType::NonpaddingSent => TriggerEvent::NonPaddingSent {
            bytes_sent: event.xmit_bytes,
        },
        MaybenotEventType::NonpaddingReceived => TriggerEvent::NonPaddingRecv {
            bytes_recv: event.xmit_bytes,
        },
        MaybenotEventType::PaddingSent => TriggerEvent::PaddingSent {
            bytes_sent: event.xmit_bytes,
            machine: MachineId::from_raw(event.machine),
        },
        MaybenotEventType::PaddingReceived => TriggerEvent::PaddingRecv {
            bytes_recv: event.xmit_bytes,
        },
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
