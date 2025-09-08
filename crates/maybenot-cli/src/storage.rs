use std::fs::File;

use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use anyhow::Result;
use indicatif::ParallelProgressIterator;
use log::info;
use maybenot_gen::defense::Defense;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use serde::{Deserialize, Serialize};

use crate::get_progress_style;

/// A common struct for how we save and load defenses.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Defenses {
    pub description: String,
    pub defenses: Vec<Defense>,
}

/// Saves defenses to a file using all the available cores.
pub fn save_defenses(description: String, defenses: &[Defense], filename: &Path) -> Result<()> {
    // sort by defense.id()
    let mut defenses = defenses.to_vec();
    defenses.sort_by(|a, b| a.id().cmp(b.id()));

    // from description, strip all new lines
    let d = description.replace("\n", " ");

    let defenses = Defenses {
        description: d,
        defenses,
    };

    // iterate over defenses and serialize them
    let mut res: Vec<String> = defenses
        .defenses
        .par_iter()
        .progress_with_style(get_progress_style())
        .map(|defense| serde_json::to_string(defense).unwrap())
        .collect();

    // sort res for deterministic order
    res.sort();

    let file = File::create(filename)?;

    // as the first line, write the description
    let mut writer = BufWriter::new(file);
    writeln!(writer, "{}", defenses.description)?;
    for line in res {
        writeln!(writer, "{line}")?;
    }

    info!("saved defenses to {}", filename.display());
    Ok(())
}

/// Load defenses from a file using all the available cores.
pub fn load_defenses(filename: &Path) -> Result<Defenses> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);

    // read all lines into a vector
    let lines: Vec<String> = reader.lines().map(|l| l.unwrap()).collect();

    // read the first line as the description
    let description = lines[0].clone();

    // read the rest of the lines as defenses, in parallel, dealing with errors
    let defenses: Vec<Option<Defense>> = lines[1..]
        .par_iter()
        .progress_with_style(get_progress_style())
        .map(|line| serde_json::from_str(line).ok())
        .collect();

    // if any none values are found, return an error
    if defenses.iter().any(Option::is_none) {
        return Err(anyhow::anyhow!("error reading defenses"));
    }

    // unwrap the defenses
    let defenses: Vec<Defense> = defenses.into_iter().flatten().collect();

    Ok(Defenses {
        description,
        defenses,
    })
}

// Read dataset into a vector of (class, filename, path to content).
pub fn read_dataset(root: &Path) -> Vec<(usize, String, String)> {
    let mut dataset: Vec<(usize, String, String)> = vec![];

    if root.is_dir() {
        relative_recursive_read(root, None, &mut dataset);
    }

    dataset
}

fn relative_recursive_read(
    root: &Path,
    class: Option<usize>,
    dataset: &mut Vec<(usize, String, String)>,
) {
    for entry in std::fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            // the class is the last part of the path
            let class = class.unwrap_or_else(|| {
                path.file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .parse::<usize>()
                    .unwrap()
            });
            relative_recursive_read(path.as_path(), Some(class), dataset);
        } else {
            // if the path ends with .log, it's a trace, read it
            if path.to_str().unwrap().ends_with(".log") {
                if class.is_none() {
                    panic!("trace file found in root directory, but no class specified");
                }
                let fname = path.file_name().unwrap().to_str().unwrap().to_string();
                dataset.push((class.unwrap(), fname, path.to_str().unwrap().to_string()));
            }
        }
    }
}
