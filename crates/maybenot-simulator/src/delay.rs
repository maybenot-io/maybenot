use std::time::{Duration, Instant};

use log::debug;

use crate::{queue::SimQueue, SimEvent};

/// on blocking expiration, this function determines the duration, if any, that
/// should be added as aggregated delay as a consequence of packets being
/// blocked
pub fn agg_delay_on_blocking_expire(
    sq: &SimQueue,
    is_client: bool,
    expire_time: Instant,
    blocking_head: &SimEvent,
    aggregate_base_delay: Duration,
) -> Option<Duration> {
    // how far into the future in the ingress queue (base events of NormalSent)
    // to consider the blocking head event as part of a burst
    const BASE_WINDOW: Duration = Duration::from_millis(1);
    // the maximum duration of the hypothetical burst as part of the blocked
    // (buffered) TunnelSent events
    const BUFFER_WINDOW: Duration = Duration::from_millis(1);

    let (blocking, bypassable) = match is_client {
        true => (&sq.client.blocking, &sq.client.bypassable),
        false => (&sq.server.blocking, &sq.server.bypassable),
    };

    // we have a buffer of blocked packets
    let buffer_size = blocking.len() + bypassable.len();

    // and the packet to be sent next in the simulator (either at expire_time or
    // in the future)
    let base = match is_client {
        // at the client, it's the next packet from the application layer
        true => sq.client.base.peek(),
        // at the server, it's the next packet on the ingress from the
        // destination
        false => sq.server.base.peek(),
    };

    // we look for the tail of the buffered packets within the window
    let mut tail = blocking_head.time;
    if buffer_size > 2 {
        // many packets, note that the blocking_head has been blocked for the
        // longest duration of all blocked packets. We now check all the blocked
        // packets, determining the timestamp of the event with the largest
        // timestamp still within the window (the tail packet)
        blocking.iter().chain(bypassable.iter()).for_each(|e| {
            if e.time - blocking_head.time <= BUFFER_WINDOW && e.time > tail {
                tail = e.time;
            }
        });
    }

    // edge case: no need to schedule 0 duration
    if expire_time == tail {
        return None;
    }

    match base {
        Some(base) => {
            let base_time = base.time + aggregate_base_delay;
            if base_time - blocking_head.time <= BASE_WINDOW {
                debug!("base is within blocking head window");
                // if the blocking head event (not the tail, or we get a sliding
                // window) and the next base event are within the window, we
                // assume that they are related and don't add any delay, instead
                // any later blocking of the tail should cause delay, if any
                None
            } else {
                debug!("base is outside of the window");
                // the base packet is outside of the window, this is a tail,
                // compute the delay
                Some(expire_time - tail)
            }
        }
        // no base, so use the found tail
        None => {
            debug!("no base");
            Some(expire_time - tail)
        }
    }
}

/// when a padding packet with bypass replace is sent through bypassable
/// blocking, this function determines the duration, if any, that should be
/// added as aggregated delay as a consequence of packets being blocked
pub fn agg_delay_on_padding_bypass_replace(
    sq: &SimQueue,
    is_client: bool,
    current_time: Instant,
    blocking_head: &SimEvent,
    aggregate_base_delay: Duration,
) -> Option<Duration> {
    const ADJACENT_WINDOW: Duration = Duration::from_millis(100);
    const BASE_WINDOW: Duration = Duration::from_millis(1);

    let (blocking, bypassable) = match is_client {
        true => (&sq.client.blocking, &sq.client.bypassable),
        false => (&sq.server.blocking, &sq.server.bypassable),
    };

    // and the packet to be sent next in the simulator (either at current_time
    // or in the future)
    let base = match is_client {
        // at the client, it's the next packet from the application layer
        true => sq.client.base.peek(),
        // at the server, it's the next packet on the ingress from the
        // destination
        false => sq.server.base.peek(),
    };

    // before calling agg_delay_on_padding_bypass_replace() in network.rs, the
    // blocking packet has been temporarily popped, so we look for any adjacent
    // packet either in the blocking or bypassable queues
    for e in blocking.iter().chain(bypassable.iter()) {
        if e.time - blocking_head.time <= ADJACENT_WINDOW {
            debug!("found adjacently blocked packet");
            return None;
        }
    }

    if let Some(base) = base {
        let base_time = base.time + aggregate_base_delay;
        if base_time - blocking_head.time <= BASE_WINDOW {
            debug!("base is within blocking head window");
            return None;
        }
        debug!("base is outside of the window");
    }

    Some(current_time - blocking_head.time)
}

/// when the network bottleneck determines that a network packet has been
/// further delayed due to congestion, this function determines if this delay
/// should contribute to the aggregated delay
pub fn should_delayed_packet_prop_agg_delay(
    sq: &SimQueue,
    is_client: bool,
    delayed_packet: &SimEvent,
    aggregate_base_delay: Duration,
) -> bool {
    const ADJACENT_WINDOW: Duration = Duration::from_millis(100);
    const BASE_WINDOW: Duration = Duration::from_millis(1);

    let (blocking, bypassable) = match is_client {
        true => (&sq.client.blocking, &sq.client.bypassable),
        false => (&sq.server.blocking, &sq.server.bypassable),
    };

    // we look for any adjacent packet either in the blocking or bypassable
    // queues...
    for e in blocking.iter().chain(bypassable.iter()) {
        if e.time - delayed_packet.time <= ADJACENT_WINDOW {
            debug!("found adjacently queued packet");
            return false;
        }
    }

    // ...and the packet to be sent next in the simulator
    let base = match is_client {
        // at the client, it's the next packet from the application layer
        true => sq.client.base.peek(),
        // at the server, it's the next packet on the ingress from the
        // destination
        false => sq.server.base.peek(),
    };

    if let Some(base) = base {
        let base_time = base.time + aggregate_base_delay;
        if base_time - delayed_packet.time <= BASE_WINDOW {
            debug!("base is within adjacent window");
            return false;
        }
        debug!("base is outside of adjacency window");
    }

    true
}
