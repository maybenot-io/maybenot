use std::{fmt, str::FromStr};

use maybenot::Machine;
use serde::{Deserialize, Serialize, Serializer, de::Error, ser::SerializeSeq};
use sha2::{Digest, Sha256};

/// Machine names are always 32 characters (hex-encoded) in Maybenot v2.
const MACHINE_NAME_LEN: usize = 32;

/// A defense consists of zero or more client machines and zero or more server
/// machines. The defense identifier is deterministically derived from the
/// machines in the defense (64 characters, hex-encoded SHA-256.). An optional
/// note field is provided for additional information. The note is not part of
/// the identifier.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Defense {
    #[serde(
        serialize_with = "serialize_machines",
        deserialize_with = "deserialize_machines"
    )]
    pub client: Vec<Machine>,
    #[serde(
        serialize_with = "serialize_machines",
        deserialize_with = "deserialize_machines"
    )]
    pub server: Vec<Machine>,
    pub note: Option<String>,
    #[serde(skip)]
    id: String,
}

impl Defense {
    pub fn new(client: Vec<Machine>, server: Vec<Machine>) -> Self {
        let id = get_id(&client, &server);
        Self {
            client,
            server,
            id,
            note: None,
        }
    }

    #[must_use]
    pub fn num_client_machines(&self) -> usize {
        self.client.len()
    }

    #[must_use]
    pub fn num_server_machines(&self) -> usize {
        self.server.len()
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.client.is_empty() && self.server.is_empty()
    }

    /// Update the ID of the defense. This should only be called if the client
    /// or server machines are modified after defense creation, as the ID is
    /// deterministically derived from the machines.
    pub fn update_id(&mut self) {
        self.id = get_id(&self.client, &self.server);
    }
}

// custom serialization function for machines using Maybenot format
fn serialize_machines<S>(machines: &[Machine], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(machines.len()))?;
    for m in machines {
        seq.serialize_element(&m.serialize())?;
    }

    seq.end()
}

// custom deserialization function for machines using Maybenot format
fn deserialize_machines<'de, D>(deserializer: D) -> Result<Vec<Machine>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let machines: Vec<String> = serde::Deserialize::deserialize(deserializer)?;
    let mut result = Vec::with_capacity(machines.len());
    for m in machines {
        match Machine::from_str(&m) {
            Ok(machine) => result.push(machine),
            Err(e) => return Err(Error::custom(format!("invalid machine {m} format: {e}"))),
        }
    }
    Ok(result)
}

fn get_id(client: &[Machine], server: &[Machine]) -> String {
    if client.is_empty() && server.is_empty() {
        // optimize for empty defense case
        let s = Sha256::digest(b"");
        return format!("{s:x}");
    }

    // allocate id with capacity for machine names (32 chars each)
    let mut id =
        String::with_capacity(client.len() * MACHINE_NAME_LEN + server.len() * MACHINE_NAME_LEN);
    for m in client {
        id.push_str(&m.name());
    }
    for m in server {
        id.push_str(&m.name());
    }
    let s = Sha256::digest(id.as_bytes());
    format!("{s:x}")
}

impl fmt::Display for Defense {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "id: {}", self.id)?;
        if let Some(note) = &self.note {
            writeln!(f, "note: {note}")?;
        }
        writeln!(f, "client machine(s): {}", self.client.len())?;
        for m in &self.client {
            writeln!(f, "  {}", m.serialize())?;
        }
        writeln!(f, "server machine(s): {}", self.server.len())?;
        for m in &self.server {
            writeln!(f, "  {}", m.serialize())?;
        }
        Ok(())
    }
}

impl PartialEq for Defense {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Defense {}

impl PartialOrd for Defense {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Defense {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}
