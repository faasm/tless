use std::{
    env,
    fs::File,
    io::{self, BufReader, Read},
    path::PathBuf,
};

pub struct Env {}

impl Env {
    pub const CONTAINER_REGISTRY_URL: &'static str = "ghcr.io/faasm";
    pub const SYS_NAME: &'static str = "invrs";

    pub fn proj_root() -> PathBuf {
        env!("ACCLESS_ROOT_DIR").into()
    }

    pub fn ansible_root() -> PathBuf {
        let mut path = Self::proj_root();
        path.push("config");
        path.push("ansible");
        path
    }

    pub fn docker_root() -> PathBuf {
        let mut path = Self::proj_root();
        path.push("config");
        path.push("docker");
        path
    }

    pub fn experiments_root() -> PathBuf {
        let mut path = Self::proj_root();
        path.push("experiments");
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

    pub fn get_faasm_version() -> String {
        std::env::var("FAASM_VERSION").unwrap()
    }
}
