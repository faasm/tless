use std::env;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::PathBuf;

pub struct Env {}

impl Env {
    pub const CONTAINER_REGISTRY_URL: &'static str = "ghcr.io/faasm";
    pub const SYS_NAME: &'static str = "invrs";

    pub fn proj_root() -> PathBuf {
        env::current_dir().expect("invrs: failed to get current directory")
    }

    pub fn ansible_root() -> PathBuf {
        let mut path = Self::proj_root();
        path.push("ansible");
        path
    }

    pub fn docker_root() -> PathBuf {
        let mut path = Self::proj_root();
        path.push("docker");
        path
    }

    pub fn get_version() -> io::Result<String> {
        let mut file_path = Self::proj_root();
        file_path.push("VERSION");

        let file = File::open(file_path)?;
        let mut buf_reader = BufReader::new(file);
        let mut version = String::new();
        buf_reader.read_to_string(&mut version)?;

        Ok(version.trim().to_string())
    }
}
