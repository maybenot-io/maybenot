use crate::linktrace::LinkTrace;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkBundle {
    pub bundleinfo: String,
    pub linktraces: Vec<LinkTrace>,
    pub tracefilenames: Vec<String>,
}

impl LinkBundle {
    pub fn new(bundleinfo: &str, linktraces: Vec<LinkTrace>, tracefilenames: Vec<String>) -> Self {
        Self {
            bundleinfo: bundleinfo.to_string(),
            linktraces,
            tracefilenames,
        }
    }

    pub fn get_index_trace(&self, index: usize) -> LinkTrace {
        if index >= self.linktraces.len() {
            panic!("Index out of bounds in LinkBundle.");
        }
        self.linktraces[index].clone()
    }
}

pub fn save_linkbundle_to_file(file_path: &str, link_bundle: &LinkBundle) -> io::Result<()> {
    let encoded = bincode::serialize(link_bundle).unwrap();
    if file_path.ends_with(".gz") {
        let file = File::create(file_path)?;
        let mut encoder = GzEncoder::new(file, Compression::default());
        encoder.write_all(&encoded)?;
        encoder.finish()?;
    } else {
        let mut file = File::create(file_path)?;
        file.write_all(&encoded)?;
    }
    Ok(())
}

pub fn load_linkbundle_from_file(file_path: &str) -> io::Result<LinkBundle> {
    let mut encoded = Vec::new();
    if file_path.ends_with(".gz") {
        let file = File::open(file_path)?;
        let mut decoder = GzDecoder::new(file);
        decoder.read_to_end(&mut encoded)?;
    } else {
        let mut file = File::open(file_path)?;
        file.read_to_end(&mut encoded)?;
    }
    let link_bundle: LinkBundle = bincode::deserialize(&encoded).unwrap();
    Ok(link_bundle)
}

impl fmt::Display for LinkBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Bundle Info: {}", self.bundleinfo)?;
        writeln!(f, "Number of traces: {}", self.linktraces.len())?;
        if !self.linktraces.is_empty() {
            writeln!(f, "Trace at index 0:\n{}", self.linktraces[0])
        } else {
            writeln!(f, "No traces available.")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linktrace::LinkTrace;

    fn create_dummy_linktrace() -> LinkTrace {
        let trace_data = "100\n200\n300";
        LinkTrace::new_std_res(trace_data, trace_data)
    }

    #[test]
    fn test_get_index_trace() {
        let trace = create_dummy_linktrace();
        let bundle = LinkBundle::new(
            "Test Bundle",
            vec![trace.clone()],
            vec!["1".to_string(), "2".to_string()],
        );
        let returned_trace = bundle.get_index_trace(0);
        assert_eq!(returned_trace, trace);
    }

    #[test]
    fn test_save_and_read() {
        let trace1 = create_dummy_linktrace();
        let trace2 = create_dummy_linktrace();
        let bundle = LinkBundle::new(
            "Test Bundle",
            vec![trace1, trace2],
            vec!["1".to_string(), "2".to_string()],
        );
        let file_path = "test_bundle.bin";
        save_linkbundle_to_file(file_path, &bundle).unwrap();
        let loaded_bundle = load_linkbundle_from_file(file_path).unwrap();
        assert_eq!(bundle.bundleinfo, loaded_bundle.bundleinfo);
        assert_eq!(bundle.linktraces.len(), loaded_bundle.linktraces.len());
        std::fs::remove_file(file_path).unwrap();
    }
}
