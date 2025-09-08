use std::time::Duration;

/// Statistics for a simulated defended trace based on a base trace used for
/// simulation. Create in aggregate for a dataset to create aggregated
/// statistics for defense evaluation.
#[derive(Debug, Clone)]
pub struct DefendedTraceStats {
    /// number of normal packets sent
    pub normal_sent: f64,
    /// number of normal packets received
    pub normal_received: f64,
    /// number of padding packets sent, including tail packets
    pub padding_sent: f64,
    /// number of padding packets received, including tail packets
    pub padding_received: f64,
    /// number of (padding) packets sent after the last normal packet
    pub tail_sent: f64,
    /// number of (padding) packets received after the last normal packet
    pub tail_received: f64,
    /// duration until the last packet in the trace
    pub last_packet: Duration,
    /// duration until the last normal packet in the trace
    pub last_normal: Duration,
    /// duration until the last undefended packet in the base trace
    pub base_last_undefended: Duration,
    /// number of normal packets sent in the base trace that are missing in the
    /// defended trace
    pub missing_normal_sent: f64,
    /// number of normal packets received in the base trace that are missing in
    /// the defended trace
    pub missing_normal_received: f64,
}

impl DefendedTraceStats {
    pub fn new(defended: &str, base: &str) -> Self {
        let normal_sent = defended.lines().filter(|l| l.contains("sn")).count();
        let normal_received = defended.lines().filter(|l| l.contains("rn")).count();
        let padding_sent = defended.lines().filter(|l| l.contains("sp")).count();
        let padding_received = defended.lines().filter(|l| l.contains("rp")).count();

        // for the tail, we first filter out the tail packets by reversing the lines then collecting until we hit a normal packet
        let tail_vec = defended
            .lines()
            .rev()
            .take_while(|l| l.contains("sp") || l.contains("rp"))
            .collect::<Vec<&str>>();
        let tail_sent = tail_vec.iter().filter(|l| l.contains("sp")).count();
        let tail_received = tail_vec.iter().filter(|l| l.contains("rp")).count();

        let last_packet = defended
            .lines()
            .last()
            .and_then(|l| l.split(',').next())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(Duration::from_nanos)
            .unwrap_or(Duration::ZERO);
        let last_normal = defended
            .lines()
            .filter(|l| l.contains("sn") || l.contains("rn"))
            .next_back()
            .and_then(|l| l.split(',').next())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(Duration::from_nanos)
            .unwrap_or(Duration::ZERO);
        let last_undefended = base
            .lines()
            .last()
            .and_then(|l| l.split(',').next())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(Duration::from_nanos)
            .unwrap_or(Duration::ZERO);

        let missing_normal_sent = base
            .lines()
            .filter(|l| l.contains("s"))
            .count()
            .saturating_sub(normal_sent);
        let missing_normal_received = base
            .lines()
            .filter(|l| l.contains("r"))
            .count()
            .saturating_sub(normal_received);

        DefendedTraceStats {
            normal_sent: normal_sent as f64,
            normal_received: normal_received as f64,
            padding_sent: padding_sent as f64,
            padding_received: padding_received as f64,
            tail_sent: tail_sent as f64,
            tail_received: tail_received as f64,
            last_packet,
            last_normal,
            base_last_undefended: last_undefended,
            missing_normal_sent: missing_normal_sent as f64,
            missing_normal_received: missing_normal_received as f64,
        }
    }

    /// Returns the total number of packets in the base trace. Note that this
    /// includes both sent and received packets, as well as packets missing in
    /// the defended trace.
    pub fn base_packets(&self) -> f64 {
        self.normal_sent
            + self.normal_received
            + self.missing_normal_sent
            + self.missing_normal_received
    }

    /// Returns the total number of packets sent in the base trace.
    pub fn base_packets_sent(&self) -> f64 {
        self.normal_sent + self.missing_normal_sent
    }

    /// Returns the total number of packets received in the base trace.
    pub fn base_packets_received(&self) -> f64 {
        self.normal_received + self.missing_normal_received
    }

    /// Returns the total number of defended packets, including padding.
    pub fn defended_packets(&self) -> f64 {
        self.normal_sent + self.normal_received + self.padding_sent + self.padding_received
    }

    /// Returns the total number of defended packets sent, including padding.
    pub fn defended_packets_sent(&self) -> f64 {
        self.normal_sent + self.padding_sent
    }

    /// Returns the total number of defended packets received, including padding.
    pub fn defended_packets_received(&self) -> f64 {
        self.normal_received + self.padding_received
    }

    /// Returns the total number of missing packets, i.e. packets that were sent
    /// or received in the base trace but are not present in the defended trace.
    pub fn missing_packets(&self) -> f64 {
        self.missing_normal_sent + self.missing_normal_received
    }

    /// Returns the total number of padding packets.
    pub fn padding_total(&self) -> f64 {
        self.padding_sent + self.padding_received
    }

    /// Returns the total number of padding packets sent in the tail, i.e.,
    /// after the last normal packet.
    pub fn tail_padding(&self) -> f64 {
        self.tail_sent + self.tail_received
    }

    /// Returns the overhead of the defended trace compared to the base trace.
    /// This is calculated up until the last normal packet in the defended
    /// trace, so it does not include the tail packets. This is normal in the
    /// website fingerprinting community. Note also that overhead is defined as
    /// the ratio of additional data, i.e., the data overhead when there is no
    /// padding is 0.0.
    pub fn overhead_data(&self) -> Option<f64> {
        if self.normal_sent + self.normal_received == 0.0 {
            return None;
        }
        Some(
            (self.normal_sent + self.normal_received + self.padding_sent + self.padding_received
                - self.tail_sent
                - self.tail_received)
                / (self.normal_sent + self.normal_received)
                - 1.0,
        )
    }

    /// Returns the overhead data sent.
    pub fn overhead_data_sent(&self) -> Option<f64> {
        if self.normal_sent == 0.0 {
            return None;
        }
        Some((self.normal_sent + self.padding_sent - self.tail_sent) / self.normal_sent - 1.0)
    }

    /// Returns the overhead data received.
    pub fn overhead_data_recv(&self) -> Option<f64> {
        if self.normal_received == 0.0 {
            return None;
        }
        Some(
            (self.normal_received + self.padding_received - self.tail_received)
                / self.normal_received
                - 1.0,
        )
    }

    /// Returns the overhead duration of the defended trace compared to the base
    /// trace as a ratio. Can only be calculated if there are no missing
    /// packets, i.e., the defended trace is a perfect representation of the
    /// base trace.
    pub fn overhead_duration(&self) -> Option<f64> {
        if self.missing_normal_sent == 0.0
            && self.missing_normal_received == 0.0
            && self.base_last_undefended.as_secs_f64() > 0.0
        {
            // we can only reliably calculate the duration overhead if there are no missing packets
            Some((self.last_normal.as_secs_f64() / self.base_last_undefended.as_secs_f64()) - 1.0)
        } else {
            None
        }
    }
}
