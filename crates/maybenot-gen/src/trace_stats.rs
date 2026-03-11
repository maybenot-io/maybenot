use std::time::Duration;

/// Minimum number of time bins for decoy-normal density correlation.
const MIN_CORRELATION_BINS: usize = 10;

/// Fixed window size for capacity excess computation (100ms in nanoseconds).
const CAPACITY_WINDOW_NS: u64 = 100_000_000;

/// Measures how often and how severely the defended trace exceeds the maximum
/// packet rate observed in the undefended base trace within fixed 100ms windows.
/// Exceeding natural capacity would trigger congestion control, degrade
/// performance, and be detectable by an adversary.
#[derive(Debug, Clone, Copy)]
pub struct CapacityExcess {
    /// Fraction of windows where defended traffic exceeds base max [0.0, 1.0].
    pub fraction: f64,
    /// Peak ratio of defended window count to base max across all windows.
    /// A value of 1.5 means 50% over capacity at peak.
    pub peak_ratio: f64,
    /// Longest run of consecutive violating windows. Sustained violations cause
    /// TCP to enter multiplicative decrease or slow-start.
    pub max_consecutive: usize,
}

/// Computes the Pearson correlation coefficient between two slices.
/// Returns `None` if either slice has zero variance or if they are empty.
fn pearson_correlation(x: &[f64], y: &[f64]) -> Option<f64> {
    let n = x.len();
    if n == 0 || n != y.len() {
        return None;
    }
    let n_f = n as f64;
    let mean_x = x.iter().sum::<f64>() / n_f;
    let mean_y = y.iter().sum::<f64>() / n_f;

    let mut cov = 0.0;
    let mut var_x = 0.0;
    let mut var_y = 0.0;
    for i in 0..n {
        let dx = x[i] - mean_x;
        let dy = y[i] - mean_y;
        cov += dx * dy;
        var_x += dx * dx;
        var_y += dy * dy;
    }

    if var_x == 0.0 || var_y == 0.0 {
        return None;
    }
    Some(cov / (var_x.sqrt() * var_y.sqrt()))
}

/// Statistics for a simulated defended trace based on a base trace used for
/// simulation. Create in aggregate for a dataset to create aggregated
/// statistics for defense evaluation.
#[derive(Debug, Clone)]
pub struct DefendedTraceStats {
    /// number of normal packets sent
    pub normal_sent: f64,
    /// number of normal packets received
    pub normal_received: f64,
    /// number of decoy packets sent, including tail packets
    pub decoy_sent: f64,
    /// number of decoy packets received, including tail packets
    pub decoy_received: f64,
    /// number of (decoy) packets sent after the last normal packet
    pub tail_sent: f64,
    /// number of (decoy) packets received after the last normal packet
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
    /// Pearson correlation between decoy and normal packet density (bidirectional)
    decoy_normal_correlation: Option<f64>,
    /// Pearson correlation between decoy and normal packet density (sent only)
    decoy_normal_correlation_sent: Option<f64>,
    /// Pearson correlation between decoy and normal packet density (received only)
    decoy_normal_correlation_recv: Option<f64>,
    /// Capacity excess metric (bidirectional)
    capacity_excess: Option<CapacityExcess>,
    /// Capacity excess metric (sent only)
    capacity_excess_sent: Option<CapacityExcess>,
    /// Capacity excess metric (received only)
    capacity_excess_recv: Option<CapacityExcess>,
}

/// Computes [`CapacityExcess`] by comparing defended window counts against a
/// base maximum. Returns `None` if `base_max` is 0.
fn compute_capacity_excess(defended_windows: &[usize], base_max: usize) -> Option<CapacityExcess> {
    if base_max == 0 {
        return None;
    }
    let base_max_f = base_max as f64;
    let num_windows = defended_windows.len();
    if num_windows == 0 {
        return None;
    }

    let mut violations = 0usize;
    let mut peak_ratio = 0.0f64;
    let mut max_consecutive = 0usize;
    let mut current_consecutive = 0usize;

    for &count in defended_windows {
        let ratio = count as f64 / base_max_f;
        peak_ratio = peak_ratio.max(ratio);
        if count > base_max {
            violations += 1;
            current_consecutive += 1;
            max_consecutive = max_consecutive.max(current_consecutive);
        } else {
            current_consecutive = 0;
        }
    }

    Some(CapacityExcess {
        fraction: violations as f64 / num_windows as f64,
        peak_ratio,
        max_consecutive,
    })
}

impl DefendedTraceStats {
    pub fn new(defended: &str, base: &str) -> Self {
        let normal_sent = defended.lines().filter(|l| l.contains("sn")).count();
        let normal_received = defended.lines().filter(|l| l.contains("rn")).count();
        let decoy_sent = defended
            .lines()
            .filter(|l| l.contains("sp") || l.contains("sd"))
            .count();
        let decoy_received = defended
            .lines()
            .filter(|l| l.contains("rp") || l.contains("rd"))
            .count();

        // for the tail, we first filter out the tail packets by reversing the lines then collecting until we hit a normal packet
        let tail_vec = defended
            .lines()
            .rev()
            .take_while(|l| {
                l.contains("sp") || l.contains("rp") || l.contains("sd") || l.contains("rd")
            })
            .collect::<Vec<&str>>();
        let tail_sent = tail_vec
            .iter()
            .filter(|l| l.contains("sp") || l.contains("sd"))
            .count();
        let tail_received = tail_vec
            .iter()
            .filter(|l| l.contains("rp") || l.contains("rd"))
            .count();

        let last_packet = defended
            .lines()
            .last()
            .and_then(|l| l.split(',').next())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(Duration::from_nanos)
            .unwrap_or(Duration::ZERO);
        let last_normal = defended
            .lines()
            .rfind(|l| l.contains("sn") || l.contains("rn"))
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

        // compute decoy-normal density correlation
        let last_normal_nanos = last_normal.as_nanos() as u64;
        let (
            decoy_normal_correlation,
            decoy_normal_correlation_sent,
            decoy_normal_correlation_recv,
        ) = if last_normal_nanos == 0 {
            (None, None, None)
        } else {
            let num_bins = (last_normal.as_millis() as usize / 100).max(MIN_CORRELATION_BINS);
            let bin_width = last_normal_nanos / num_bins as u64;
            if bin_width == 0 {
                (None, None, None)
            } else {
                let mut normal_counts = vec![0.0f64; num_bins];
                let mut decoy_counts = vec![0.0f64; num_bins];
                let mut normal_sent_counts = vec![0.0f64; num_bins];
                let mut decoy_sent_counts = vec![0.0f64; num_bins];
                let mut normal_recv_counts = vec![0.0f64; num_bins];
                let mut decoy_recv_counts = vec![0.0f64; num_bins];

                for line in defended.lines() {
                    let mut parts = line.split(',');
                    let ts = parts.next().and_then(|s| s.trim().parse::<u64>().ok());
                    let tag = parts.next().map(str::trim);

                    if let (Some(ts), Some(tag)) = (ts, tag) {
                        if ts > last_normal_nanos {
                            continue;
                        }
                        let bin = ((ts / bin_width) as usize).min(num_bins - 1);
                        let is_sent = tag.starts_with('s');
                        let is_normal = tag == "sn" || tag == "rn";
                        let is_decoy = tag == "sp" || tag == "sd" || tag == "rp" || tag == "rd";

                        if is_normal {
                            normal_counts[bin] += 1.0;
                            if is_sent {
                                normal_sent_counts[bin] += 1.0;
                            } else {
                                normal_recv_counts[bin] += 1.0;
                            }
                        } else if is_decoy {
                            decoy_counts[bin] += 1.0;
                            if is_sent {
                                decoy_sent_counts[bin] += 1.0;
                            } else {
                                decoy_recv_counts[bin] += 1.0;
                            }
                        }
                    }
                }

                (
                    pearson_correlation(&normal_counts, &decoy_counts),
                    pearson_correlation(&normal_sent_counts, &decoy_sent_counts),
                    pearson_correlation(&normal_recv_counts, &decoy_recv_counts),
                )
            }
        };

        // compute capacity excess metrics using fixed 100ms windows
        let (capacity_excess, capacity_excess_sent, capacity_excess_recv) =
            if last_normal_nanos == 0 {
                (None, None, None)
            } else {
                // bin base trace into fixed 100ms windows
                let base_num_windows =
                    (last_undefended.as_nanos() as u64 / CAPACITY_WINDOW_NS + 1).max(1) as usize;
                let mut base_both = vec![0usize; base_num_windows];
                let mut base_sent_w = vec![0usize; base_num_windows];
                let mut base_recv_w = vec![0usize; base_num_windows];

                for line in base.lines() {
                    let mut parts = line.split(',');
                    let ts = parts.next().and_then(|s| s.trim().parse::<u64>().ok());
                    let tag = parts.next().map(str::trim);
                    if let (Some(ts), Some(tag)) = (ts, tag) {
                        let bin = (ts / CAPACITY_WINDOW_NS) as usize;
                        let bin = bin.min(base_num_windows - 1);
                        base_both[bin] += 1;
                        if tag.starts_with('s') {
                            base_sent_w[bin] += 1;
                        } else {
                            base_recv_w[bin] += 1;
                        }
                    }
                }

                let base_max_both = base_both.iter().copied().max().unwrap_or(0);
                let base_max_sent = base_sent_w.iter().copied().max().unwrap_or(0);
                let base_max_recv = base_recv_w.iter().copied().max().unwrap_or(0);

                // bin defended trace into fixed 100ms windows (up to last_normal)
                let def_num_windows = (last_normal_nanos / CAPACITY_WINDOW_NS + 1).max(1) as usize;
                let mut def_both = vec![0usize; def_num_windows];
                let mut def_sent_w = vec![0usize; def_num_windows];
                let mut def_recv_w = vec![0usize; def_num_windows];

                for line in defended.lines() {
                    let mut parts = line.split(',');
                    let ts = parts.next().and_then(|s| s.trim().parse::<u64>().ok());
                    let tag = parts.next().map(str::trim);
                    if let (Some(ts), Some(tag)) = (ts, tag) {
                        if ts > last_normal_nanos {
                            continue;
                        }
                        let bin = (ts / CAPACITY_WINDOW_NS) as usize;
                        let bin = bin.min(def_num_windows - 1);
                        def_both[bin] += 1;
                        if tag.starts_with('s') {
                            def_sent_w[bin] += 1;
                        } else {
                            def_recv_w[bin] += 1;
                        }
                    }
                }

                (
                    compute_capacity_excess(&def_both, base_max_both),
                    compute_capacity_excess(&def_sent_w, base_max_sent),
                    compute_capacity_excess(&def_recv_w, base_max_recv),
                )
            };

        DefendedTraceStats {
            normal_sent: normal_sent as f64,
            normal_received: normal_received as f64,
            decoy_sent: decoy_sent as f64,
            decoy_received: decoy_received as f64,
            tail_sent: tail_sent as f64,
            tail_received: tail_received as f64,
            last_packet,
            last_normal,
            base_last_undefended: last_undefended,
            missing_normal_sent: missing_normal_sent as f64,
            missing_normal_received: missing_normal_received as f64,
            decoy_normal_correlation,
            decoy_normal_correlation_sent,
            decoy_normal_correlation_recv,
            capacity_excess,
            capacity_excess_sent,
            capacity_excess_recv,
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

    /// Returns the total number of defended packets, including decoys.
    pub fn defended_packets(&self) -> f64 {
        self.normal_sent + self.normal_received + self.decoy_sent + self.decoy_received
    }

    /// Returns the total number of defended packets sent, including decoys.
    pub fn defended_packets_sent(&self) -> f64 {
        self.normal_sent + self.decoy_sent
    }

    /// Returns the total number of defended packets received, including decoys.
    pub fn defended_packets_received(&self) -> f64 {
        self.normal_received + self.decoy_received
    }

    /// Returns the total number of missing packets, i.e. packets that were sent
    /// or received in the base trace but are not present in the defended trace.
    pub fn missing_packets(&self) -> f64 {
        self.missing_normal_sent + self.missing_normal_received
    }

    /// Returns the total number of decoy packets.
    pub fn decoy_total(&self) -> f64 {
        self.decoy_sent + self.decoy_received
    }

    /// Returns the total number of decoy packets sent in the tail, i.e.,
    /// after the last normal packet.
    pub fn tail_decoy(&self) -> f64 {
        self.tail_sent + self.tail_received
    }

    /// Returns the overhead of the defended trace compared to the base trace.
    /// This is calculated up until the last normal packet in the defended
    /// trace, so it does not include the tail packets. This is normal in the
    /// website fingerprinting community. Note also that overhead is defined as
    /// the ratio of additional data, i.e., the data overhead when there is no
    /// decoy packets is 0.0.
    pub fn overhead_data(&self) -> Option<f64> {
        if self.normal_sent + self.normal_received == 0.0 {
            return None;
        }
        Some(
            (self.normal_sent + self.normal_received + self.decoy_sent + self.decoy_received
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
        Some((self.normal_sent + self.decoy_sent - self.tail_sent) / self.normal_sent - 1.0)
    }

    /// Returns the overhead data received.
    pub fn overhead_data_recv(&self) -> Option<f64> {
        if self.normal_received == 0.0 {
            return None;
        }
        Some(
            (self.normal_received + self.decoy_received - self.tail_received)
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

    /// Returns the Pearson correlation between decoy and normal packet density
    /// across time bins (bidirectional). Positive values indicate reactive
    /// placement (decoys cluster with normal traffic), negative values indicate
    /// proactive placement (decoys fill gaps between normal traffic). Returns
    /// `None` when correlation is undefined (e.g., no decoys or zero variance).
    pub fn decoy_normal_correlation(&self) -> Option<f64> {
        self.decoy_normal_correlation
    }

    /// Returns the Pearson correlation between decoy and normal packet density
    /// across time bins (sent only). See [`Self::decoy_normal_correlation`] for
    /// interpretation.
    pub fn decoy_normal_correlation_sent(&self) -> Option<f64> {
        self.decoy_normal_correlation_sent
    }

    /// Returns the Pearson correlation between decoy and normal packet density
    /// across time bins (received only). See [`Self::decoy_normal_correlation`]
    /// for interpretation.
    pub fn decoy_normal_correlation_recv(&self) -> Option<f64> {
        self.decoy_normal_correlation_recv
    }

    /// Returns the capacity excess metric (bidirectional). See
    /// [`CapacityExcess`] for details.
    pub fn capacity_excess(&self) -> Option<CapacityExcess> {
        self.capacity_excess
    }

    /// Returns the capacity excess metric (sent only).
    pub fn capacity_excess_sent(&self) -> Option<CapacityExcess> {
        self.capacity_excess_sent
    }

    /// Returns the capacity excess metric (received only).
    pub fn capacity_excess_recv(&self) -> Option<CapacityExcess> {
        self.capacity_excess_recv
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pearson_perfect_positive() {
        let x = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let y = vec![2.0, 4.0, 6.0, 8.0, 10.0];
        let r = pearson_correlation(&x, &y).unwrap();
        assert!((r - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_pearson_perfect_negative() {
        let x = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let y = vec![10.0, 8.0, 6.0, 4.0, 2.0];
        let r = pearson_correlation(&x, &y).unwrap();
        assert!((r + 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_pearson_zero_variance() {
        let x = vec![1.0, 1.0, 1.0];
        let y = vec![2.0, 4.0, 6.0];
        assert!(pearson_correlation(&x, &y).is_none());
    }

    #[test]
    fn test_pearson_empty() {
        assert!(pearson_correlation(&[], &[]).is_none());
    }

    /// Helper to build a trace line: "timestamp,tag"
    fn trace_line(ts_nanos: u64, tag: &str) -> String {
        format!("{ts_nanos},{tag}")
    }

    fn build_trace(lines: &[(u64, &str)]) -> String {
        lines
            .iter()
            .map(|(ts, tag)| trace_line(*ts, tag))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn test_correlation_decoys_colocated_with_normals() {
        // Normal and decoy packets clustered together in the first half of bins → positive correlation
        let mut lines = Vec::new();
        // Cluster normals and decoys in the first half; need a final normal to anchor last_normal
        for i in 0..5 {
            let ts = i * 1000;
            lines.push((ts, "sn"));
            lines.push((ts + 1, "sd"));
        }
        // Final normal at the end to ensure bins span the full range
        lines.push((9999, "sn"));
        let defended = build_trace(&lines);
        let base = build_trace(
            &lines
                .iter()
                .filter(|(_, t)| *t == "sn")
                .copied()
                .collect::<Vec<_>>(),
        );
        let stats = DefendedTraceStats::new(&defended, &base);
        let corr = stats.decoy_normal_correlation();
        assert!(corr.is_some(), "correlation should be defined");
        assert!(
            corr.unwrap() > 0.0,
            "expected positive correlation, got {}",
            corr.unwrap()
        );
    }

    #[test]
    fn test_correlation_decoys_in_gaps() {
        // Normal packets in first half, decoy packets in second half → negative correlation
        let mut lines = Vec::new();
        // normals in first 10 bins
        for i in 0..10 {
            let ts = i * 1000;
            lines.push((ts, "sn"));
        }
        // decoys in last 10 bins
        for i in 10..20 {
            let ts = i * 1000;
            lines.push((ts, "sd"));
        }
        // need a final normal to set last_normal far enough
        let last_ts = 19 * 1000 + 50;
        lines.push((last_ts, "sn"));
        lines.sort_by_key(|(ts, _)| *ts);

        let defended = build_trace(&lines);
        let base = build_trace(
            &lines
                .iter()
                .filter(|(_, t)| *t == "sn")
                .copied()
                .collect::<Vec<_>>(),
        );
        let stats = DefendedTraceStats::new(&defended, &base);
        let corr = stats.decoy_normal_correlation();
        assert!(corr.is_some(), "correlation should be defined");
        assert!(
            corr.unwrap() < 0.0,
            "expected negative correlation, got {}",
            corr.unwrap()
        );
    }

    #[test]
    fn test_correlation_no_decoys() {
        let lines = vec![(0, "sn"), (100, "sn"), (200, "rn")];
        let defended = build_trace(&lines);
        let base = build_trace(&lines);
        let stats = DefendedTraceStats::new(&defended, &base);
        // no decoys → zero variance in decoy counts → None
        assert!(stats.decoy_normal_correlation().is_none());
    }

    #[test]
    fn test_correlation_empty_trace() {
        let stats = DefendedTraceStats::new("", "");
        assert!(stats.decoy_normal_correlation().is_none());
    }

    // --- capacity excess tests ---

    #[test]
    fn test_capacity_excess_no_violations() {
        // Base trace has 5 packets in one 100ms window, defended has same → no excess
        let base = build_trace(&[
            (0, "sn"),
            (10_000_000, "sn"),
            (20_000_000, "rn"),
            (30_000_000, "sn"),
            (40_000_000, "rn"),
        ]);
        // Defended: same normal packets, no decoys
        let defended = base.clone();
        let stats = DefendedTraceStats::new(&defended, &base);
        let ce = stats.capacity_excess();
        assert!(ce.is_some());
        let ce = ce.unwrap();
        assert_eq!(ce.fraction, 0.0);
        assert!(ce.peak_ratio <= 1.0);
        assert_eq!(ce.max_consecutive, 0);
    }

    #[test]
    fn test_capacity_excess_every_window_exceeds() {
        // Base: 1 packet per 100ms window across 3 windows
        let base = build_trace(&[(10_000_000, "sn"), (110_000_000, "sn"), (210_000_000, "sn")]);
        // Defended: 2 packets (normal + decoy) per window → all exceed base max of 1
        // Place decoys before normals so last_normal captures all windows
        let defended = build_trace(&[
            (10_000_000, "sd"),
            (20_000_000, "sn"),
            (110_000_000, "sd"),
            (120_000_000, "sn"),
            (210_000_000, "sd"),
            (220_000_000, "sn"),
        ]);
        let stats = DefendedTraceStats::new(&defended, &base);
        let ce = stats.capacity_excess().unwrap();
        assert_eq!(ce.fraction, 1.0);
        assert!((ce.peak_ratio - 2.0).abs() < 1e-10);
        assert_eq!(ce.max_consecutive, 3);
    }

    #[test]
    fn test_capacity_excess_single_window() {
        // Base: 2 packets per window across 3 windows
        let base = build_trace(&[
            (10_000_000, "sn"),
            (20_000_000, "sn"),
            (110_000_000, "sn"),
            (120_000_000, "sn"),
            (210_000_000, "sn"),
            (220_000_000, "sn"),
        ]);
        // Defended: only exceed in the first window (3 packets vs base max of 2)
        let defended = build_trace(&[
            (10_000_000, "sn"),
            (20_000_000, "sn"),
            (30_000_000, "sd"),
            (110_000_000, "sn"),
            (120_000_000, "sn"),
            (210_000_000, "sn"),
            (220_000_000, "sn"),
        ]);
        let stats = DefendedTraceStats::new(&defended, &base);
        let ce = stats.capacity_excess().unwrap();
        assert!((ce.fraction - 1.0 / 3.0).abs() < 1e-10);
        assert_eq!(ce.max_consecutive, 1);
        assert!((ce.peak_ratio - 1.5).abs() < 1e-10);
    }

    #[test]
    fn test_capacity_excess_consecutive_burst() {
        // Base: 1 packet per window, 5 windows
        let base = build_trace(&[
            (10_000_000, "sn"),
            (110_000_000, "sn"),
            (210_000_000, "sn"),
            (310_000_000, "sn"),
            (410_000_000, "sn"),
        ]);
        // Defended: exceed in windows 1,2,3 (consecutive), not in 0 and 4
        let defended = build_trace(&[
            (10_000_000, "sn"),
            // window 1: 2 packets
            (110_000_000, "sn"),
            (120_000_000, "sd"),
            // window 2: 2 packets
            (210_000_000, "sn"),
            (220_000_000, "sd"),
            // window 3: 2 packets
            (310_000_000, "sn"),
            (320_000_000, "sd"),
            // window 4: 1 packet
            (410_000_000, "sn"),
        ]);
        let stats = DefendedTraceStats::new(&defended, &base);
        let ce = stats.capacity_excess().unwrap();
        assert_eq!(ce.max_consecutive, 3);
        assert!((ce.fraction - 3.0 / 5.0).abs() < 1e-10);
    }

    #[test]
    fn test_capacity_excess_empty_base() {
        let stats = DefendedTraceStats::new("", "");
        assert!(stats.capacity_excess().is_none());
        assert!(stats.capacity_excess_sent().is_none());
        assert!(stats.capacity_excess_recv().is_none());
    }

    #[test]
    fn test_capacity_excess_direction_specific() {
        // Base: 1 sent + 1 recv per window
        let base = build_trace(&[
            (10_000_000, "sn"),
            (20_000_000, "rn"),
            (110_000_000, "sn"),
            (120_000_000, "rn"),
        ]);
        // Defended: add extra sent decoy only → sent should exceed, recv should not
        let defended = build_trace(&[
            (10_000_000, "sn"),
            (15_000_000, "sd"),
            (20_000_000, "rn"),
            (110_000_000, "sn"),
            (115_000_000, "sd"),
            (120_000_000, "rn"),
        ]);
        let stats = DefendedTraceStats::new(&defended, &base);

        let ce_sent = stats.capacity_excess_sent().unwrap();
        assert!(ce_sent.fraction > 0.0, "sent should have violations");

        let ce_recv = stats.capacity_excess_recv().unwrap();
        assert_eq!(ce_recv.fraction, 0.0, "recv should have no violations");
    }
}
