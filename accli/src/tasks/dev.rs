use crate::Env;
use anyhow::Result;
use log::{error, info};
use regex::Regex;
use std::{
    fmt,
    fs::{self, File},
    io::{self, Write},
    path::Path,
    process,
};

/// Represents the version components.
#[derive(Debug, PartialEq, Eq)]
struct Version {
    major: u32,
    minor: u32,
    patch: u32,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl Version {
    /// Parses a version string (e.g., "1.2.3") into a Version struct.
    fn parse(version_str: &str) -> Result<Self> {
        let parts: Vec<&str> = version_str.trim().split('.').collect();
        if parts.len() != 3 {
            error!("Invalid version format: {}", version_str);
            return Err(anyhow::anyhow!("Invalid version format: {}", version_str));
        }

        let major = parts[0].parse()?;
        let minor = parts[1].parse()?;
        let patch = parts[2].parse()?;

        Ok(Version {
            major,
            minor,
            patch,
        })
    }

    /// Increments the version based on the specified bump type.
    fn bump(&mut self, major: bool, minor: bool, patch: bool) {
        if major {
            self.major += 1;
            self.minor = 0;
            self.patch = 0;
        } else if minor {
            self.minor += 1;
            self.patch = 0;
        } else if patch {
            self.patch += 1;
        }
        // If none are true, the version remains the same.
    }
}

#[derive(Debug)]
pub struct Dev {}

impl Dev {
    /// Helper function to overwrite the VERSION file.
    fn update_version_file(path: &Path, new_version: &str) -> io::Result<()> {
        let mut file = File::create(path)?;
        // The VERSION file contains only the version string, so we overwrite it.
        file.write_all(new_version.as_bytes())?;
        file.write_all(b"\n")?; // Add a newline for clean file ending
        Ok(())
    }

    /// Helper function to update the version in Cargo.toml using regex.
    fn update_cargo_toml(path: &Path, new_version: &str) -> Result<()> {
        let cargo_toml_content = fs::read_to_string(path)?;

        // Regex to find 'version = "X.Y.Z"'
        // It captures everything before and after the version string to replace only the version.
        let re = Regex::new(r#"(version\s*=\s*)"(\d+\.\d+\.\d+)""#)?;

        let replacement = format!("$1\"{}\"", new_version);
        let new_content = re
            .replace(&cargo_toml_content, replacement.as_str())
            .to_string();

        // Overwrite Cargo.toml with the new content
        fs::write(path, new_content)?;

        Ok(())
    }

    /// Bumps the version tag in both the VERSION file and Cargo.toml
    pub fn bump_code_version(major: bool, minor: bool, patch: bool) -> Result<()> {
        // Read current version from version file
        let current_version_str = Env::get_version()?;

        // 2. PARSE AND BUMP THE VERSION
        let mut version = Version::parse(&current_version_str)?;
        version.bump(major, minor, patch);
        let new_version_str = version.to_string();

        info!("current version: {}", current_version_str.trim());
        info!("new version: {}", new_version_str);

        // Update the version file
        let version_file_path = Env::proj_root().join("VERSION");
        Self::update_version_file(&version_file_path, &new_version_str)?;

        // Update the cargo.toml file
        let cargo_toml_path = Env::proj_root().join("Cargo.toml");
        Self::update_cargo_toml(&cargo_toml_path, &new_version_str)?;

        Ok(())
    }

    /// Tags the current commit with the version from the VERSION file.
    pub fn tag_code(force: bool) -> Result<()> {
        let current_version_str = Env::get_version()?;
        let version = Version::parse(&current_version_str)?;
        let tag_name = format!("v{}", version);

        info!("Creating git tag: {}", tag_name);
        let mut tag_cmd = process::Command::new("git");
        tag_cmd.arg("tag").arg(&tag_name);
        let tag_output = tag_cmd.output()?;

        if !tag_output.status.success() {
            error!(
                "Failed to create git tag: {}",
                String::from_utf8_lossy(&tag_output.stderr)
            );
            return Err(anyhow::anyhow!("Failed to create git tag"));
        }

        info!("Pushing git tag to origin: {}", tag_name);
        let mut push_cmd = process::Command::new("git");
        push_cmd.arg("push").arg("origin").arg(&tag_name);
        if force {
            push_cmd.arg("--force");
        }
        let push_output = push_cmd.output()?;

        if !push_output.status.success() {
            error!(
                "Failed to push git tag: {}",
                String::from_utf8_lossy(&push_output.stderr)
            );
            return Err(anyhow::anyhow!("Failed to push git tag"));
        }

        info!("Successfully tagged and pushed version {}", tag_name);
        Ok(())
    }

    /// Format all source code.
    pub fn format_code(check: bool) {
        // First, format all CPP "projects"
        if !process::Command::new("clang-format")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
        {
            error!("clang-format must be installed and in your path");
            process::exit(1);
        }

        let clang_format_cfg = Env::proj_root().join("config").join(".clang-format");

        let extensions = ["cpp", "c", "h", "hpp"];

        fn is_source_file(path: &Path, exts: &[&str]) -> bool {
            path.is_file()
                && path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|ext| exts.contains(&ext))
                    .unwrap_or(false)
        }

        fn is_excluded(entry: &walkdir::DirEntry) -> bool {
            let excluded_dirs = ["build-wasm", "build-native", "target", "venv"];
            entry.file_type().is_dir()
                && entry
                    .file_name()
                    .to_str()
                    .map(|name| excluded_dirs.contains(&name))
                    .unwrap_or(false)
        }

        for entry in walkdir::WalkDir::new(".")
            .into_iter()
            .filter_entry(|e| !is_excluded(e))
            .filter_map(Result::ok)
        {
            let path = entry.path();
            if is_source_file(path, &extensions) {
                let mut cmd = process::Command::new("clang-format");
                cmd.arg("-i").arg(path);
                cmd.arg(format!("--style=file:{}", clang_format_cfg.display()));

                if check {
                    cmd.arg("--dry-run").arg("--Werror").arg(path);
                }

                match cmd.status() {
                    Ok(status) if status.success() => {}
                    Ok(status) => {
                        error!(
                            "clang-format failed on {} with status {}",
                            path.display(),
                            status
                        );
                        process::exit(1);
                    }
                    Err(err) => {
                        error!("Failed to run clang-format on {}: {}", path.display(), err);
                        process::exit(1);
                    }
                }
            }
        }

        // Now format rust code
        // cargo fmt
        let mut fmt_cmd = process::Command::new("cargo");
        fmt_cmd.arg("fmt");
        if check {
            fmt_cmd.arg("--").arg("--check");
        }
        fmt_cmd.current_dir(Env::proj_root());

        match fmt_cmd.status() {
            Ok(status) if status.success() => {}
            Ok(status) => {
                error!("cargo fmt failed with status {}", status);
                process::exit(1);
            }
            Err(err) => {
                error!("failed to run cargo fmt (err={err:?})");
                process::exit(1);
            }
        }

        // cargo clippy
        let mut clippy_cmd = process::Command::new("cargo");
        clippy_cmd.arg("clippy");
        if check {
            clippy_cmd.arg("--").arg("-D").arg("warnings");
        }
        clippy_cmd.current_dir(Env::proj_root());

        match clippy_cmd.status() {
            Ok(status) if status.success() => {}
            Ok(status) => {
                error!("cargo clippy failed with status {}", status);
                process::exit(1);
            }
            Err(err) => {
                error!("failed to run cargo clippy (error={err:?})");
                process::exit(1);
            }
        }
    }
}
