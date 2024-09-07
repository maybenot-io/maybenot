use bincode;
use chrono::Utc;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use ndarray::Array2;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

/// Link trace
/// that represent the troughput evolution between client and server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LinkTrace {
    // Filenames used for linktraces, if trace is read from file.
    // Otherwise, holds the string used to create the traces (Useful for debugging).
    dl_traceinput: String,
    ul_traceinput: String,

    // Uplink and downlink throughput traces
    dl_bw_trace: Vec<i32>,
    ul_bw_trace: Vec<i32>,

    // The lookuptable to select which busy_to table is appropriate for the packetsize of the specific packet
    sizebin_lookuptable: SizebinLookupTable,

    // The busy_to lookupmatrix precomputed from the link traces
    dl_busy_to_mtx: Array2<i32>,
    ul_busy_to_mtx: Array2<i32>,
}

impl LinkTrace {
    /// Creates a new `LinkTrace` instance, filling in the traces based on the input strings.
    /// Precomputes busy_to lookup tables according to packet sizes set as per-bin representative pkt_size values.
    pub fn new(
        dl_traceinput: &str,
        ul_traceinput: &str,
        sizebin_lookuptable: SizebinLookupTable,
    ) -> Self {
        let (dl_bw_trace, ul_bw_trace) =
            if dl_traceinput.contains('\n') && ul_traceinput.contains('\n') {
                // If inputs contain newlines, assume they are raw trace strings and parse them
                (
                    Self::parse_linktrace(dl_traceinput),
                    Self::parse_linktrace(ul_traceinput),
                )
            } else if dl_traceinput.contains(r".gz") && ul_traceinput.contains(r".gz") {
                // Otherwise, assume they are filenames and read the traces from files
                (
                    Self::parse_linktrace(&Self::read_gzipped_linktrace(dl_traceinput)),
                    Self::parse_linktrace(&Self::read_gzipped_linktrace(ul_traceinput)),
                )
            } else {
                // Otherwise, assume they are filenames and read the traces from files
                (
                    Self::parse_linktrace(&Self::read_linktrace(dl_traceinput)),
                    Self::parse_linktrace(&Self::read_linktrace(ul_traceinput)),
                )
            };

        // Precompute the busy_to matrices by first creating a temporary instance with the necessary data
        let (dl_busy_to_mtx, ul_busy_to_mtx) = Self {
            dl_traceinput: dl_traceinput.to_string(),
            ul_traceinput: ul_traceinput.to_string(),
            dl_bw_trace: dl_bw_trace.clone(),
            ul_bw_trace: ul_bw_trace.clone(),
            sizebin_lookuptable: sizebin_lookuptable.clone(),
            dl_busy_to_mtx: Array2::<i32>::zeros((0, 0)), // placeholder
            ul_busy_to_mtx: Array2::<i32>::zeros((0, 0)), // placeholder
        }
        .precompute_busy_to_mtx();

        Self {
            dl_traceinput: dl_traceinput.to_string(),
            ul_traceinput: ul_traceinput.to_string(),
            dl_bw_trace,
            ul_bw_trace,
            sizebin_lookuptable,
            dl_busy_to_mtx,
            ul_busy_to_mtx,
        }
    }

    /// A function that creates a 2D ndarray where dim1 has the size of the number of items in `sizebin_lookuptable.bin_pktsize_values`
    /// and where dim2 has the size of the number of items in `dl_bw_trace`.
    /// The function loops through each `bin_pktsize_value` in an outer loop, and each `dl_bw_trace` value in an inner loop.
    /// The corresponding `busy_to_mtx` cell is populated with the index of the upcoming `dl_bw_trace` index for which the sum
    /// of values from current to upcoming `dl_bw_trace` is the same or larger than the `bin_pktsize_value`.
    fn precompute_busy_to_mtx(&self) -> (Array2<i32>, Array2<i32>) {
        let num_bins = self.sizebin_lookuptable.bin_pktsize_values.len();
        let num_traces = self.dl_bw_trace.len();

        // Initialize matrices with zeros (stored as i32 for space efficiency)
        let mut dl_busy_to_mtx = Array2::<i32>::zeros((num_bins, num_traces));
        let mut ul_busy_to_mtx = Array2::<i32>::zeros((num_bins, num_traces));

        for (bin_idx, &pkt_size) in self
            .sizebin_lookuptable
            .bin_pktsize_values
            .iter()
            .enumerate()
        {
            // Precompute busy_to for downlink trace
            for start_idx in 0..num_traces {
                let mut sum = 0;
                for end_idx in start_idx..num_traces {
                    sum += self.dl_bw_trace[end_idx];
                    if sum >= pkt_size {
                        dl_busy_to_mtx[(bin_idx, start_idx)] = (end_idx + 1) as i32;
                        break;
                    }
                }
            }

            // Precompute busy_to for uplink trace
            for start_idx in 0..num_traces {
                let mut sum = 0;
                for end_idx in start_idx..num_traces {
                    sum += self.ul_bw_trace[end_idx];
                    if sum >= pkt_size {
                        ul_busy_to_mtx[(bin_idx, start_idx)] = (end_idx + 1) as i32;
                        break;
                    }
                }
            }
        }

        (dl_busy_to_mtx, ul_busy_to_mtx)
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

    /// Parses the content of a link trace string and returns a vector of integers.
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
        self.dl_bw_trace.len() as i32
    }

    pub fn get_dl_busy_to(&self, time_slot: usize, pkt_size: i32) -> usize {
        let bin_idx = self.sizebin_lookuptable.get_bin_idx(pkt_size) as usize;
        self.dl_busy_to_mtx[(bin_idx, time_slot)] as usize
    }
}

//TODO: make more informative
impl fmt::Display for LinkTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        //TODO: Print len, bw
        writeln!(
            f,
            "Shape of downlink lookup matrix: {:?}",
            self.dl_busy_to_mtx.shape()
        )?;
        if !self.dl_traceinput.is_empty() && !self.ul_traceinput.is_empty() {
            write!(
                f,
                "Tracefiles {{ \ndl: {:?}, \nul: {:?} }}",
                self.dl_traceinput, self.ul_traceinput
            )
        } else {
            write!(f, "No trace-file found")
        }
    }
}

pub fn mk_start_instant() -> Instant {
    // Create an arbitary point in time to use as a common time for simulation and link trace handling
    let start_instant_dt = chrono::DateTime::<Utc>::from_timestamp_millis(1722543211000).unwrap();

    // Convert DateTime<Utc> to SystemTime
    let start_instant_system_time = SystemTime::from(start_instant_dt);

    // Calculate the duration between the defined start instance and epoch
    let start_duration_epoch =
        match start_instant_system_time.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(duration) => duration,
            Err(_) => Duration::ZERO, // Handle case where system_time is before the UNIX_EPOCH
        };

    // Get the current time in both representations
    let now_instant = Instant::now();
    let now_systime = SystemTime::now();

    // Calculate the duration between the current time and epoch
    let now_duration_epoch = match now_systime.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => duration,
        Err(_) => Duration::ZERO, // Handle case where system_time is before the UNIX_EPOCH
    };

    // return a "static" Instant by fiddling with the durations, as its the only way for Instant manipulation...
    now_instant - now_duration_epoch + start_duration_epoch
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SizebinLookupTable {
    boundaries: Vec<i32>,
    bin_pktsize_values: Vec<i32>,
    sizebin_lookuptable: Vec<i32>,
    max_value: i32,
}

impl SizebinLookupTable {
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

pub fn mk_sizebin_lookuptable() -> SizebinLookupTable {
    // Boundary values created to minimize binning errors. Minimum change is 16 bytes due to assumed Wireguard tunneling which pads to multiples of 16.
    // The bin_pktsize_values are used in the computation of the busy_to lookup table. pkt_size value at the upper bin boundary will lead to the
    // obtained tput for smaller packets to be slightly underestimated as the pktsize used in the computation is overstated by the binning.
    // Should likely tweak these values as they are currently partly based on wireguard application data size distro from TP.
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
pub fn save_linktrace_to_file(file_path: &str, link_trace: &LinkTrace) -> io::Result<()> {
    let encoded: Vec<u8> = bincode::serialize(link_trace).unwrap();

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

    let link_trace: LinkTrace = bincode::deserialize(&encoded).unwrap();
    Ok(Arc::new(link_trace))
}
