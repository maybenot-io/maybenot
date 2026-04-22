use bincode;
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use ndarray::Array2;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::sync::Arc;

/// Link trace that represent the throughput evolution for a simplex link.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LinkTrace {
    // Filename used for linktrace, if trace is read from file. Otherwise, holds
    // the string used to create the trace (Useful for debugging).
    traceinput: String,

    // Throughput trace, used for std_res traces
    pub bw_trace: Vec<i32>,

    pub is_tput_trace_high_res: bool,

    //// Data for High Resolution throughput traces below
    // The lookuptable to select which busy_to table is appropriate for the
    // packetsize of the specific packet
    sizebin_lookuptable: SizebinLookupTable,

    // The busy_to lookupmatrix precomputed from the link traces
    busy_to_mtx: Array2<i32>,
}

impl LinkTrace {
    /// Creates a high-resolution link trace from raw trace input.
    ///
    /// # Internal API
    ///
    /// This function is primarily for developer tooling (xtask). Most users
    /// should use [`load_linktrace_from_file`] to load pre-computed traces.
    pub fn new_hi_res(traceinput: &str, sizebin_lookuptable: SizebinLookupTable) -> Self {
        Self::new(traceinput, sizebin_lookuptable, true)
    }

    /// Creates a standard-resolution link trace from raw trace input.
    ///
    /// # Internal API
    ///
    /// This function is primarily for developer tooling (xtask). Most users
    /// should use [`load_linktrace_from_file`] to load pre-computed traces.
    pub fn new_std_res(traceinput: &str) -> Self {
        let dummy_sizebin = SizebinLookupTable::new(&[0, 1501], &[1500]);
        Self::new(traceinput, dummy_sizebin, false)
    }

    /// Creates a new `LinkTrace` instance, filling in the trace based on the
    /// input string. If High Resolution traces, precompute busy_to lookup
    /// tables according to packet sizes set as per-bin representative pkt_size
    /// values.
    fn new(
        traceinput: &str,
        sizebin_lookuptable: SizebinLookupTable,
        is_tput_trace_high_res: bool,
    ) -> Self {
        let bw_trace = if traceinput.contains('\n') {
            // If input contains newlines, assume it's a raw trace string and
            // parse it
            Self::parse_linktrace(traceinput)
        } else if traceinput.contains(r".gz") {
            // Otherwise, assume it's a filename and read the trace from gzipped
            // file
            Self::parse_linktrace(&Self::read_gzipped_linktrace(traceinput))
        } else {
            // Otherwise, assume it's a filename and read the trace from file
            Self::parse_linktrace(&Self::read_linktrace(traceinput))
        };

        let busy_to_mtx = if is_tput_trace_high_res {
            // Create a temporary instance and precompute the busy_to matrix
            Self {
                traceinput: traceinput.to_string(),
                bw_trace: bw_trace.clone(),
                is_tput_trace_high_res: true,
                sizebin_lookuptable: sizebin_lookuptable.clone(),
                busy_to_mtx: Array2::<i32>::zeros((0, 0)), // placeholder
            }
            .precompute_busy_to_mtx()
        } else {
            // Default matrix if high-resolution is not needed
            Array2::<i32>::zeros((0, 0))
        };

        Self {
            traceinput: traceinput.to_string(),
            bw_trace,
            is_tput_trace_high_res,
            sizebin_lookuptable,
            busy_to_mtx,
        }
    }

    /// A function that creates a 2D ndarray where dim1 has the size of the
    /// number of items in `sizebin_lookuptable.bin_pktsize_values` and where
    /// dim2 has the size of the number of items in `bw_trace`. The function
    /// loops through each `bin_pktsize_value` in an outer loop, and each
    /// `bw_trace` value in an inner loop. The corresponding `busy_to_mtx` cell
    /// is populated with the index of the upcoming `bw_trace` index for which
    /// the sum of values from current to upcoming `bw_trace` is the same or
    /// larger than the `bin_pktsize_value`.
    fn precompute_busy_to_mtx(&self) -> Array2<i32> {
        let num_bins = self.sizebin_lookuptable.bin_pktsize_values.len();
        let num_traces = self.bw_trace.len();

        // Initialize matrix with zeros (stored as i32 for space efficiency)
        let mut busy_to_mtx = Array2::<i32>::zeros((num_bins, num_traces));

        for (bin_idx, &pkt_size) in self
            .sizebin_lookuptable
            .bin_pktsize_values
            .iter()
            .enumerate()
        {
            // Precompute busy_to for the trace
            for start_idx in 0..num_traces {
                let mut sum = 0;
                for end_idx in start_idx..num_traces {
                    sum += self.bw_trace[end_idx];
                    if sum >= pkt_size {
                        busy_to_mtx[(bin_idx, start_idx)] = (end_idx + 1) as i32;
                        break;
                    }
                }
            }
        }

        busy_to_mtx
    }

    /// Reads the entire content of a link trace file into a String.
    fn read_linktrace(filename: &str) -> String {
        // Open the file (will panic if the file cannot be opened)
        let mut file = File::open(filename).unwrap_or_else(|err| {
            panic!("Failed to open file '{}': {}", filename, err);
        });

        // Read the file content into a string
        let mut tracestring = String::new();
        file.read_to_string(&mut tracestring).unwrap_or_else(|err| {
            panic!("Failed to read content from file '{}': {}", filename, err);
        });
        tracestring
    }

    /// Reads the entire content of a gzipped link trace file into a String.
    /// TODO: merge with above
    fn read_gzipped_linktrace(filename: &str) -> String {
        // Open the Gzipped file
        let file = File::open(filename).unwrap_or_else(|err| {
            panic!("Failed to open file '{}': {}", filename, err);
        });
        let decoder = GzDecoder::new(file);
        let mut reader = BufReader::new(decoder);

        // Read the contents of the file into a string
        let mut tracestring = String::new();
        reader
            .read_to_string(&mut tracestring)
            .unwrap_or_else(|err| {
                panic!("Failed to read content from file '{}': {}", filename, err);
            });
        tracestring
    }

    /// Parses the content of a link trace string and returns a vector of
    /// integers.
    fn parse_linktrace(tracestring: &str) -> Vec<i32> {
        // Initialize an empty vector to store the integers
        let mut bw_trace = Vec::new();

        // Iterate over each line in the content with line numbers
        for (line_number, line) in tracestring.lines().enumerate() {
            let ts_bw = line.trim().parse::<i32>().unwrap_or_else(|err| {
                panic!(
                    "Failed to parse integer on line {}: '{}' - {}",
                    line_number + 1,
                    line,
                    err
                );
            });

            bw_trace.push(ts_bw);
        }
        bw_trace
    }

    pub fn get_nr_timeslots(&self) -> i32 {
        self.bw_trace.len() as i32
    }

    pub fn get_busy_to(&self, time_slot: usize, pkt_size: i32) -> usize {
        let bin_idx = self.sizebin_lookuptable.get_bin_idx(pkt_size) as usize;
        self.busy_to_mtx[(bin_idx, time_slot)] as usize
    }
}

impl fmt::Display for LinkTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Calculate the duration of the link trace in seconds
        let slots_per_sec = if self.is_tput_trace_high_res {
            1e6_f64
        } else {
            1e3_f64
        };
        let duration_sec = self.bw_trace.len() as f64 / slots_per_sec;
        // Calculate average throughput in Mbps
        let avg_throughput_mbps =
            self.bw_trace.iter().sum::<i32>() as f64 * 8.0 / duration_sec / 1e6_f64;

        // Print out the duration and average throughput
        writeln!(f, "\nLink trace details:")?;
        writeln!(f, "  Duration (seconds): {:.3}", duration_sec)?;
        writeln!(f, "  Average throughput (Mbps): {:.3}", avg_throughput_mbps)?;

        // Print the trace input file (or lack thereof)
        if !self.traceinput.is_empty() {
            writeln!(f, "\nTracefile: {:?}", self.traceinput)?;
        } else {
            writeln!(f, "No trace-file found")?;
        }
        if self.is_tput_trace_high_res {
            writeln!(f, "\nHigh resolution trace (1 us)")?;
            // Print out the bin boundaries and packet sizes from SizebinLookupTable
            writeln!(f, "\nSizebin Lookup Table:")?;
            writeln!(
                f,
                "  Bin boundaries: {:?}",
                self.sizebin_lookuptable.boundaries
            )?;
            writeln!(
                f,
                "  Bin packet sizes: {:?}",
                self.sizebin_lookuptable.bin_pktsize_values
            )?;

            // Print the shape of the lookup matrix
            writeln!(f, "Shape of lookup matrix: {:?}", self.busy_to_mtx.shape())
        } else {
            writeln!(f, "\nStandard resolution trace (1 ms)")
        }
    }
}

/// Lookup table for mapping packet sizes to bins for high-resolution trace processing.
///
/// # Internal API
///
/// This struct is primarily for developer tooling (xtask) when creating link traces.
/// Most users should use [`load_linktrace_from_file`] to load pre-computed traces.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SizebinLookupTable {
    boundaries: Vec<i32>,
    sizebin_lookuptable: Vec<i32>,
    bin_pktsize_values: Vec<i32>,
    max_value: i32,
}

impl SizebinLookupTable {
    /// Creates a new lookup table for mapping packet sizes to bins.
    ///
    /// # Arguments
    /// * `boundaries` - Bin boundary values (must start with 0 and be sorted)
    /// * `bin_pktsize_values` - Representative packet size for each bin (one less than boundaries)
    pub fn new(boundaries: &[i32], bin_pktsize_values: &[i32]) -> Self {
        assert!(!boundaries.is_empty(), "Boundaries array cannot be empty.");
        assert!(
            *boundaries.first().unwrap() == 0,
            "First boundary must be zero"
        );
        assert!(
            boundaries.len() <= 100,
            "Boundaries array cannot have more than 100 elements."
        );
        assert!(
            bin_pktsize_values.len() == boundaries.len() - 1,
            "There should be exactly one less throughput value than boundary values."
        );

        // Check if boundaries are already sorted
        let mut sorted_boundaries = boundaries.to_vec();
        sorted_boundaries.sort();

        if sorted_boundaries != boundaries {
            panic!("Boundaries array is not sorted.");
        }

        let max_value = *boundaries.last().unwrap();

        // Initialize the lookup table
        let mut sizebin_lookuptable: Vec<i32> = vec![0; max_value as usize];

        // Fill the lookup table
        let mut current_bin = 0;
        for value in 0..max_value {
            while current_bin < boundaries.len() - 1 && value >= boundaries[current_bin + 1] {
                current_bin += 1;
            }
            sizebin_lookuptable[value as usize] = current_bin as i32;
        }

        // Ensure all throughput values are within the respective bins
        for (i, &tput_value) in bin_pktsize_values.iter().enumerate() {
            if tput_value < boundaries[i] || tput_value >= boundaries[i + 1] {
                panic!(
                    "Throughput value {} at index {} is out of bounds for bin {}-{}.",
                    tput_value,
                    i,
                    boundaries[i],
                    boundaries[i + 1]
                );
            }
        }

        Self {
            boundaries: boundaries.to_vec(),
            sizebin_lookuptable,
            bin_pktsize_values: bin_pktsize_values.to_vec(),
            max_value,
        }
    }

    pub fn get_bin_idx(&self, value: i32) -> i32 {
        if value >= self.max_value {
            panic!("Value {} is above range [0, {}]", value, self.max_value);
        }
        self.sizebin_lookuptable[value as usize]
    }

    pub fn get_bin_pktsize(&self, value: i32) -> i32 {
        let bin_index = self.get_bin_idx(value) as usize;
        self.bin_pktsize_values[bin_index]
    }
}

/// Creates a default sizebin lookup table for high-resolution trace processing.
///
/// # Internal API
///
/// This function is primarily for developer tooling (xtask) when creating link traces.
/// Most users should use [`load_linktrace_from_file`] to load pre-computed traces.
pub fn mk_sizebin_lookuptable() -> SizebinLookupTable {
    // Boundary values created to minimize binning errors. Minimum change is 16
    // bytes due to assumed Wireguard tunneling which pads to multiples of 16.
    // The bin_pktsize_values are used in the computation of the busy_to lookup
    // table. pkt_size value at the upper bin boundary will lead to the obtained
    // tput for smaller packets to be slightly underestimated as the pktsize
    // used in the computation is overstated by the binning. Should likely tweak
    // these values as they are currently partly based on wireguard application
    // data size distro from TP.
    let boundaries = [
        0, 49, 65, 81, 97, 113, 129, 145, 161, 193, 241, 289, 369, 449, 513, 577, 705, 849, 1009,
        1201, 1421, 1501,
    ];
    let bin_pktsize_values = [
        48, 64, 80, 96, 112, 128, 144, 160, 192, 240, 288, 368, 448, 512, 576, 704, 848, 1008,
        1200, 1420, 1500,
    ];

    // Return the LookupTable struct
    SizebinLookupTable::new(&boundaries, &bin_pktsize_values)
}

// Save the entire LinkTrace instance to a file, optionally gzipped
pub fn save_linktrace_to_file(file_path: &str, linktrace: &LinkTrace) -> io::Result<()> {
    let encoded: Vec<u8> = bincode::serialize(linktrace).unwrap();

    if file_path.ends_with(".gz") {
        // Save as gzipped
        let file = File::create(file_path)?;
        let mut encoder = GzEncoder::new(file, Compression::default());
        encoder.write_all(&encoded)?;
        encoder.finish()?;
    } else {
        // Save as plain binary
        let mut file = File::create(file_path)?;
        file.write_all(&encoded)?;
    }

    Ok(())
}

// Load the entire LinkTrace instance from a file, optionally gzipped
pub fn load_linktrace_from_file(file_path: &str) -> io::Result<Arc<LinkTrace>> {
    let mut encoded = Vec::new();

    if file_path.ends_with(".gz") {
        // Load from gzipped file
        let file = File::open(file_path)?;
        let mut decoder = GzDecoder::new(file);
        decoder.read_to_end(&mut encoded)?;
    } else {
        // Load from plain binary file
        let mut file = File::open(file_path)?;
        file.read_to_end(&mut encoded)?;
    }

    let linktrace: LinkTrace = bincode::deserialize(&encoded).unwrap();
    Ok(Arc::new(linktrace))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(
        expected = "index out of bounds: the len is 50 but the index is 18446744073709551615"
    )]
    fn sizebin_lookup_table_panic_below_min() {
        // Example boundary values
        let boundaries = [0, 10, 20, 30, 50];
        let bin_tput_values = [5, 15, 25, 40];
        let sizebin_lookuptable = SizebinLookupTable::new(&boundaries, &bin_tput_values);

        // This should panic because -1 is below the minimum boundary value (0)
        sizebin_lookuptable.get_bin_idx(-1);
    }

    #[test]
    #[should_panic(expected = "Value 50 is above range [0, 50")]
    fn sizebin_lookup_table_panic_above_max() {
        // Example boundary values
        let boundaries = [0, 10, 20, 30, 50];
        let bin_tput_values = [5, 15, 25, 40];
        let sizebin_lookuptable = SizebinLookupTable::new(&boundaries, &bin_tput_values);

        // This should panic because 50 is outside the maximum boundary value
        // (50)
        sizebin_lookuptable.get_bin_idx(50);
    }

    #[test]
    #[should_panic(expected = "Throughput value 30 at index 2 is out of bounds for bin 20-30.")]
    fn sizebin_lookup_table_panic_above_binboundary() {
        // Example boundary values
        let boundaries = [0, 10, 20, 30, 50];
        let bin_tput_values = [5, 15, 30, 40];
        let sizebin_lookuptable = SizebinLookupTable::new(&boundaries, &bin_tput_values);

        // This should panic because 50 is outside the maximum boundary value (50)
        sizebin_lookuptable.get_bin_idx(50);
    }

    #[test]
    fn sizebin_lookup_table_within_range() {
        // Example boundary values
        let boundaries = [0, 10, 20, 30, 50];
        let bin_tput_values = [9, 11, 25, 30];
        let sizebin_lookuptable = SizebinLookupTable::new(&boundaries, &bin_tput_values);

        // Test various values within the range
        assert_eq!(sizebin_lookuptable.get_bin_idx(5), 0); // 10 -> Bin 0
        assert_eq!(sizebin_lookuptable.get_bin_idx(10), 1); // 15 -> Bin 1
        assert_eq!(sizebin_lookuptable.get_bin_idx(15), 1); // 20 -> Bin 1
        assert_eq!(sizebin_lookuptable.get_bin_idx(25), 2); // 25 -> Bin 2
        assert_eq!(sizebin_lookuptable.get_bin_idx(30), 3); // 30 -> Bin 3
        assert_eq!(sizebin_lookuptable.get_bin_idx(35), 3); // 35 -> Bin 3
        assert_eq!(sizebin_lookuptable.get_bin_idx(49), 3); // 50 -> Bin 3
    }

    #[test]
    fn preconfig_sizebin_lookup() {
        let sizebin_lookuptable = mk_sizebin_lookuptable();

        // These are depenent on the boundaries used in mk_sizebin_lookuptable
        let expected = [64, 240, 576, 1200, 1420];
        for (i, value) in vec![50, 200, 520, 1200, 1201].into_iter().enumerate() {
            let bin_result = std::panic::catch_unwind(|| sizebin_lookuptable.get_bin_idx(value));
            let bin_pktsize = sizebin_lookuptable.get_bin_pktsize(value);
            match bin_result {
                Ok(_) => assert_eq!(bin_pktsize, expected[i], "bin_pktsize not as expected"),
                Err(e) => std::panic::resume_unwind(e),
            }
        }
    }
}
