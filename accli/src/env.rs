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
        let cargo_root: PathBuf = env!("CARGO_MANIFEST_DIR").into();
        cargo_root.parent().unwrap().to_path_buf()
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
