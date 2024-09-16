use crate::env::Env;
use std::fs;

#[derive(Debug)]
pub struct Workflows {}

impl Workflows {
    pub fn do_cmd(cmd: String) {
        match cmd.as_str() {
            "list" => Self::list(),
            _ => panic!("invrs: unrecognised command for task 'workflows': {cmd:?}"),
        }
    }

    fn list() {
        let paths = fs::read_dir(Env::workflows_root()).unwrap();

        println!("invrs: listing available workflows");
        for entry in paths {
            let entry = entry.unwrap();
            let path = entry.path();

            if path.is_dir() {
                println!("- {}", path.display())
            }
        }
    }
}
