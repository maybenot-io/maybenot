// Submodules
pub mod bundle;
pub mod trace;

// Re-exports
pub use bundle::{LinkBundle, load_linkbundle_from_file, save_linkbundle_to_file};
pub use trace::{
    LinkTrace, SizebinLookupTable, load_linktrace_from_file, mk_sizebin_lookuptable,
    save_linktrace_to_file,
};

use rand::{Rng, RngExt};
use std::{cmp::max, sync::Arc, time::Duration};

/////// High-performance enum-based link dispatch
#[derive(Debug, Clone)]
pub enum LinkType {
    FixedTput(FixedTputLink),
    HiTraceTput(HiTraceTputLink),
    StdTraceTput(StdTraceTputLink),
}

impl LinkType {
    pub fn sample(&mut self, current_duration: Duration, pkt_size: usize) -> Duration {
        match self {
            LinkType::FixedTput(link) => link.sample(current_duration, pkt_size),
            LinkType::HiTraceTput(link) => link.sample(current_duration, pkt_size),
            LinkType::StdTraceTput(link) => link.sample(current_duration, pkt_size),
        }
    }

    pub fn link_id(&self) -> usize {
        match self {
            LinkType::FixedTput(link) => link.id,
            LinkType::HiTraceTput(link) => link.id,
            LinkType::StdTraceTput(link) => link.id,
        }
    }

    pub fn from_node(&self) -> usize {
        match self {
            LinkType::FixedTput(link) => link.from,
            LinkType::HiTraceTput(link) => link.from,
            LinkType::StdTraceTput(link) => link.from,
        }
    }

    pub fn to_node(&self) -> usize {
        match self {
            LinkType::FixedTput(link) => link.to,
            LinkType::HiTraceTput(link) => link.to,
            LinkType::StdTraceTput(link) => link.to,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            LinkType::FixedTput(_) => "FixedTput",
            LinkType::HiTraceTput(_) => "HiTraceTput",
            LinkType::StdTraceTput(_) => "StdTraceTput",
        }
    }

    pub fn get_prop_us_fixed(&self) -> Duration {
        match self {
            LinkType::FixedTput(link) => link.prop_us,
            LinkType::HiTraceTput(link) => link.prop_us,
            LinkType::StdTraceTput(link) => link.prop_us,
        }
    }

    pub fn get_prop_us_variable(&self, current_time_ms: usize) -> Duration {
        let prop_us_vec = match self {
            LinkType::FixedTput(link) => &link.prop_us_vec,
            LinkType::HiTraceTput(link) => &link.prop_us_vec,
            LinkType::StdTraceTput(link) => &link.prop_us_vec,
        };

        // Use time-dependent propagation with bounds checking
        let index = if current_time_ms >= prop_us_vec.len() {
            // If beyond the end of the vector, use the last available value
            prop_us_vec.len() - 1
        } else {
            current_time_ms
        };
        Duration::from_micros(prop_us_vec[index])
    }

    pub fn fixed_propagation(&self) -> bool {
        match self {
            LinkType::FixedTput(link) => link.fixed_propagation,
            LinkType::HiTraceTput(link) => link.fixed_propagation,
            LinkType::StdTraceTput(link) => link.fixed_propagation,
        }
    }

    pub fn reset(&mut self) {
        match self {
            LinkType::FixedTput(_) => {} // No reset needed for fixed throughput
            LinkType::HiTraceTput(link) => link.reset(),
            LinkType::StdTraceTput(link) => link.reset(),
        }
    }

    /// Randomize link parameters for Monte Carlo simulations.
    ///
    /// The `factor` parameter controls the variation range (e.g., 0.2 = ±20%).
    /// For fixed throughput links, applies ±factor variation to throughput and propagation delay.
    /// For trace-based links, randomizes the starting offset in the trace.
    pub fn randomize<R: Rng>(&mut self, rng: &mut R, factor: f64) {
        match self {
            LinkType::FixedTput(link) => link.randomize(rng, factor),
            LinkType::HiTraceTput(link) => link.randomize(rng, factor),
            LinkType::StdTraceTput(link) => link.randomize(rng, factor),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FixedTputLink {
    pub id: usize,
    pub from: usize,
    pub to: usize,
    pub prop_us: Duration,
    pub tput_bps: u64,
    pub next_busy_to_duration: Duration,
    pub fixed_propagation: bool,
    pub prop_us_vec: Vec<u64>,
}

impl FixedTputLink {
    pub fn new(
        id: usize,
        from: usize,
        to: usize,
        prop_us: Duration,
        tput_bps: u64,
        fixed_propagation: bool,
        prop_us_vec: Vec<u64>,
    ) -> Self {
        Self {
            id,
            from,
            to,
            prop_us,
            tput_bps,
            next_busy_to_duration: Duration::default(),
            fixed_propagation,
            prop_us_vec,
        }
    }

    pub fn sample(&mut self, current_duration: Duration, pkt_size: usize) -> Duration {
        // Calculate the transmission delay for a packet with a given size:
        // this_packet_duration (ns) = (pkt_size * 8 * 1e9) / throughput (bits/s)
        let packet_size_bits = pkt_size * 8;
        let this_packet_duration =
            Duration::from_nanos((packet_size_bits as u64 * 1_000_000_000) / self.tput_bps);

        // Compute the new busy time and any queueing delay.
        let (new_busy_to_dur, queueing_delay_duration) =
            if self.next_busy_to_duration <= current_duration {
                // No waiting required.
                (current_duration + this_packet_duration, Duration::default())
            } else {
                // Packet must wait: the queueing delay is the gap between current time and the stored busy time.
                let q_delay = self.next_busy_to_duration - current_duration;
                (self.next_busy_to_duration + this_packet_duration, q_delay)
            };

        // Update the stored busy time (in ns) from the computed Duration.
        self.next_busy_to_duration = new_busy_to_dur;

        queueing_delay_duration + this_packet_duration
    }

    /// Randomize throughput and propagation delay by ±factor variation.
    ///
    /// # Panics
    ///
    /// Panics if `factor` is negative or greater than 1.0.
    pub fn randomize<R: Rng>(&mut self, rng: &mut R, factor: f64) {
        assert!(factor >= 0.0, "factor must be non-negative");
        assert!(factor <= 1.0, "factor must be at most 1.0");

        // Randomize throughput ±factor
        let delta = (self.tput_bps as f64 * factor) as u64;
        let min = self.tput_bps.saturating_sub(delta);
        let max = self.tput_bps.saturating_add(delta);
        self.tput_bps = rng.random_range(min..=max);

        // Randomize propagation ±factor if fixed
        if self.fixed_propagation {
            let delay_us = self.prop_us.as_micros() as u64;
            let delta = (delay_us as f64 * factor) as u64;
            let min = delay_us.saturating_sub(delta);
            let max = delay_us.saturating_add(delta);
            self.prop_us = Duration::from_micros(rng.random_range(min..=max));
        }
        // Note: Variable propagation (prop_us_vec) randomization not implemented
    }
}

#[derive(Debug, Clone)]
pub struct HiTraceTputLink {
    pub id: usize,
    pub from: usize,
    pub to: usize,
    pub prop_us: Duration,
    // High resolution sampling state (simplex only)
    next_busy_to: usize,
    linktrace: Arc<LinkTrace>,
    pub fixed_propagation: bool,
    pub prop_us_vec: Vec<u64>,
}

impl HiTraceTputLink {
    pub fn new(
        id: usize,
        from: usize,
        to: usize,
        prop_us: Duration,
        linktrace: Arc<LinkTrace>,
        fixed_propagation: bool,
        prop_us_vec: Vec<u64>,
    ) -> Self {
        Self {
            id,
            from,
            to,
            prop_us,
            next_busy_to: 0,
            linktrace,
            fixed_propagation,
            prop_us_vec,
        }
    }

    pub fn sample(&mut self, current_duration: Duration, pkt_size: usize) -> Duration {
        // Determine the current time slot and trace length for wrap-around
        let current_time_slot = current_duration.as_micros() as usize;
        let trace_len = self.linktrace.bw_trace.len();

        let mut queueing_delay_duration = Duration::default();

        // Determine lookup time based on queueing state
        let lookup_time = if self.next_busy_to <= current_time_slot {
            current_time_slot
        } else {
            self.next_busy_to
        };

        // Wrap lookup time into trace range
        let wrapped_lookup = lookup_time % trace_len;
        let raw_busy_to = self.linktrace.get_busy_to(wrapped_lookup, pkt_size as i32);

        // Handle trace end condition with wrap-around
        let busy_to = if raw_busy_to == 0 {
            // Packet doesn't fit before trace end - wrap to next cycle
            let current_cycle = lookup_time / trace_len;
            let next_cycle_busy_to = self.linktrace.get_busy_to(0, pkt_size as i32);

            if next_cycle_busy_to == 0 {
                panic!("Packet size {} exceeds total trace capacity", pkt_size);
            }

            // busy_to is in next cycle
            (current_cycle + 1) * trace_len + next_cycle_busy_to
        } else {
            // Normal case: reconstruct absolute time from wrapped result
            let current_cycle = lookup_time / trace_len;
            current_cycle * trace_len + raw_busy_to
        };

        // Calculate durations
        let this_packet_duration = if self.next_busy_to <= current_time_slot {
            Duration::from_micros((busy_to - current_time_slot) as u64)
        } else {
            queueing_delay_duration =
                Duration::from_micros((self.next_busy_to - current_time_slot) as u64);
            Duration::from_micros((busy_to - self.next_busy_to) as u64)
        };

        // Update next_busy_to in preparation for the next packet
        self.next_busy_to = busy_to;

        // Return only the total delay (queueing + transmission)
        if queueing_delay_duration > Duration::default() {
            queueing_delay_duration + this_packet_duration
        } else {
            this_packet_duration
        }
    }

    pub fn reset(&mut self) {
        self.next_busy_to = 0;
    }

    /// Set a random starting offset in the trace for Monte Carlo simulations.
    /// This is used by the randomization feature to start traces at different positions.
    pub fn set_random_offset(&mut self, offset: usize) {
        let trace_len = self.linktrace.bw_trace.len();
        self.next_busy_to = offset % trace_len;
    }

    /// Get the trace length in microseconds.
    pub fn get_trace_len(&self) -> usize {
        self.linktrace.bw_trace.len()
    }

    /// Randomize trace offset and propagation delay for Monte Carlo simulations.
    ///
    /// # Panics
    ///
    /// Panics if `factor` is negative or greater than 1.0.
    pub fn randomize<R: Rng>(&mut self, rng: &mut R, factor: f64) {
        assert!(factor >= 0.0, "factor must be non-negative");
        assert!(factor <= 1.0, "factor must be at most 1.0");

        // Randomize starting offset in trace
        let trace_len = self.get_trace_len();
        let random_offset = rng.random_range(0..trace_len);
        self.set_random_offset(random_offset);

        // Randomize propagation ±factor if fixed
        if self.fixed_propagation {
            let delay_us = self.prop_us.as_micros() as u64;
            let delta = (delay_us as f64 * factor) as u64;
            let min = delay_us.saturating_sub(delta);
            let max = delay_us.saturating_add(delta);
            self.prop_us = Duration::from_micros(rng.random_range(min..=max));
        }
        // Note: Variable propagation (prop_us_vec) randomization not implemented
    }
}

#[derive(Debug, Clone)]
pub struct StdTraceTputLink {
    pub id: usize,
    pub from: usize,
    pub to: usize,
    pub prop_us: Duration,
    // Standard resolution sampling state (simplex only)
    next_busy_to: usize,
    busy_ns_in_slot: u64,
    bw_trace: Vec<i32>,
    pub fixed_propagation: bool,
    pub prop_us_vec: Vec<u64>,
}

impl StdTraceTputLink {
    pub fn new(
        id: usize,
        from: usize,
        to: usize,
        prop_us: Duration,
        linktrace: Arc<LinkTrace>,
        fixed_propagation: bool,
        prop_us_vec: Vec<u64>,
    ) -> Self {
        // For simplex operation, use the single trace
        let bw_trace = linktrace.bw_trace.clone();

        Self {
            id,
            from,
            to,
            prop_us,
            next_busy_to: 0,
            busy_ns_in_slot: 0,
            bw_trace,
            fixed_propagation,
            prop_us_vec,
        }
    }

    pub fn sample(&mut self, current_duration: Duration, pkt_size: usize) -> Duration {
        // Determine the current time slot and trace length for wrap-around
        let current_time_slot = current_duration.as_millis() as usize;
        let current_slot_ns_position: u64 = (current_duration.as_nanos() % 1_000_000) as u64;
        let trace_len = self.bw_trace.len();

        // Note: Timing calculation code below is intricate, order between
        // statements can matter. Establish if the packet will have to queue, or
        // can start sending immediately
        let packet_sees_queuing = self.next_busy_to > current_time_slot
            || ((self.next_busy_to == current_time_slot)
                && (self.busy_ns_in_slot > current_slot_ns_position));

        // If we are in a new slot after network having been idle, reset
        // busy_ns_in_slot
        if self.next_busy_to < current_time_slot {
            self.busy_ns_in_slot = 0
        };

        // Get the slot index for the slot where we can first send
        let mut slot_index = max(current_time_slot, self.next_busy_to);

        // Get the ns offset inside the slot we first can send in
        let first_slot_start_send_ns = if slot_index == current_time_slot {
            max(current_slot_ns_position, self.busy_ns_in_slot)
        } else {
            self.busy_ns_in_slot
        };

        // Wrap slot_index for trace array access
        let mut wrapped_slot = slot_index % trace_len;
        let mut ns_to_slot_end = 1_000_000 - first_slot_start_send_ns;
        let mut bytes_to_slot_end =
            (ns_to_slot_end * self.bw_trace[wrapped_slot] as u64) / 1_000_000;

        // Packet transmission take place possibly across multiple slots
        let mut remaining_pkt_size = pkt_size as u64;
        let mut this_packet_duration_ns = 0_u64;
        let mut slot_boundaries_crossed = 0_u64;

        // Cross into new slot(s) until the remaining packet bytes fits in the
        // slot
        while remaining_pkt_size > bytes_to_slot_end {
            this_packet_duration_ns += ns_to_slot_end;
            remaining_pkt_size -= bytes_to_slot_end;
            slot_boundaries_crossed += 1;
            slot_index += 1;

            // Wrap slot_index for trace array access
            wrapped_slot = slot_index % trace_len;

            // Safety check: prevent infinite loops for pathological cases
            if slot_boundaries_crossed > trace_len as u64 * 2 {
                panic!(
                    "Packet transmission exceeds 2x trace length - likely configuration error. \
                     Packet size: {}, trace length: {} slots",
                    pkt_size, trace_len
                );
            }

            bytes_to_slot_end = self.bw_trace[wrapped_slot] as u64;
            ns_to_slot_end = 1_000_000;
        }

        // We are now at the slot which allows the last byte of the packet to be
        // sent
        let ns_to_send_remaining =
            ((remaining_pkt_size as f64 / self.bw_trace[wrapped_slot] as f64) * 1e6_f64).round()
                as u64;
        this_packet_duration_ns += ns_to_send_remaining;

        // Either we are in the first slot, or we have moved, this affects
        // send_end_ns calculation
        let last_slot_send_end_ns = if slot_boundaries_crossed == 0 {
            first_slot_start_send_ns + ns_to_send_remaining
        } else {
            ns_to_send_remaining
        };

        // Update the struct values for next invocation (use unwrapped slot_index for state continuity)
        self.next_busy_to = slot_index;
        self.busy_ns_in_slot = last_slot_send_end_ns;

        let total_ns_now_to_end: u64 = ((self.next_busy_to - current_time_slot) as i64 * 1_000_000
            + (last_slot_send_end_ns as i64 - current_slot_ns_position as i64) as i64)
            as u64;

        // Round to us resolution and make duration
        let total_ns_now_to_end = (total_ns_now_to_end / 1000) * 1000;
        let this_packet_duration_ns = (this_packet_duration_ns / 1000) * 1000;

        let total_queueing_delay_duration = Duration::from_nanos(total_ns_now_to_end);
        let this_packet_duration = Duration::from_nanos(this_packet_duration_ns);

        // Return only the total delay (queueing + transmission)
        if packet_sees_queuing {
            total_queueing_delay_duration
        } else {
            this_packet_duration
        }
    }

    pub fn reset(&mut self) {
        self.next_busy_to = 0;
        self.busy_ns_in_slot = 0;
    }

    /// Set a random starting offset in the trace for Monte Carlo simulations.
    /// This is used by the randomization feature to start traces at different positions.
    pub fn set_random_offset(&mut self, offset: usize) {
        let trace_len = self.bw_trace.len();
        self.next_busy_to = offset % trace_len;
        self.busy_ns_in_slot = 0; // Start at slot beginning
    }

    /// Get the trace length in milliseconds.
    pub fn get_trace_len(&self) -> usize {
        self.bw_trace.len()
    }

    /// Randomize trace offset and propagation delay for Monte Carlo simulations.
    ///
    /// # Panics
    ///
    /// Panics if `factor` is negative or greater than 1.0.
    pub fn randomize<R: Rng>(&mut self, rng: &mut R, factor: f64) {
        assert!(factor >= 0.0, "factor must be non-negative");
        assert!(factor <= 1.0, "factor must be at most 1.0");

        // Randomize starting offset in trace
        let trace_len = self.get_trace_len();
        let random_offset = rng.random_range(0..trace_len);
        self.set_random_offset(random_offset);

        // Randomize propagation ±factor if fixed
        if self.fixed_propagation {
            let delay_us = self.prop_us.as_micros() as u64;
            let delta = (delay_us as f64 * factor) as u64;
            let min = delay_us.saturating_sub(delta);
            let max = delay_us.saturating_add(delta);
            self.prop_us = Duration::from_micros(rng.random_range(min..=max));
        }
        // Note: Variable propagation (prop_us_vec) randomization not implemented
    }
}
