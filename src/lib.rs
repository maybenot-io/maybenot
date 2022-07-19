pub mod constants;
pub mod dist;
pub mod event;
pub mod framework;
pub mod machine;
pub mod state;

#[cfg(test)]
mod tests {
    #[test]
    fn constants_set() {
        assert_eq!(crate::constants::VERSION, 1);
    }
}
