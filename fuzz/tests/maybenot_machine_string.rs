// #[cfg(feature = "fuzz-tests")]
#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use maybenot::Machine;

    #[test]
    fn test_machine_string() {
        let artifacts = vec![
            include_bytes!(
                "../artifacts/machine-str,id:000000,sig:06,sync:binomial-again,src:000002"
            )
            .to_vec(),
            include_bytes!(
                "../artifacts/machine-str,id:000001,sig:06,sync:binomial-again,src:000038"
            )
            .to_vec(),
        ];

        for data in artifacts {
            let s = String::from_utf8_lossy(&data);
            println!("{:?}", s);

            if Machine::from_str(&s).is_err() {
                return;
            }
        }
    }
}
