use anyhow::Result;
use log::{error, info};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::{
    fs::{self, File},
    io::{BufReader, ErrorKind},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
};
use tokio_rustls::TlsAcceptor;

/// # Description
///
/// Returns the path to the directory where the TLS certificates are stored.
pub fn get_default_certs_dir() -> PathBuf {
    PathBuf::from(env!("ACCLESS_ROOT_DIR"))
        .join("config")
        .join("certs")
}

/// # Description
///
/// Returns the path to the private key file.
///
/// # Arguments
///
/// * `certs_dir`: the path to the directory where the TLS certificates are
///   stored.
pub fn get_private_key_path(certs_dir: &Path) -> PathBuf {
    certs_dir.join("key.pem")
}

/// # Description
///
/// Returns the path to the public certificate file.
///
/// # Arguments
///
/// * `certs_dir`: the path to the directory where the TLS certificates are
///   stored.
pub fn get_public_certificate_path(certs_dir: &Path) -> PathBuf {
    certs_dir.join("cert.pem")
}

/// # Description
///
/// Get the external node IP for this server.
///
/// This corresponds to parsing the `src` field from the output of:
/// ```bash
/// ip -o route get to 8.8.8.8
/// ```
///
/// # Returns
///
/// The external node IP as a string.
pub fn get_node_url() -> Result<String> {
    let output = Command::new("ip")
        .args(["-o", "route", "get", "to", "8.8.8.8"])
        .output()?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "failed to run `ip route get`: {:?}",
            output.status.code()
        ));
    }

    let stdout = String::from_utf8(output.stdout)?.trim().to_string();

    // Split by whitespace, find "src", and return the next token.
    let parts: Vec<&str> = stdout.split_whitespace().collect();
    let idx = parts
        .iter()
        .position(|&p| p == "src")
        .ok_or_else(|| anyhow::anyhow!("`src` token not found in `ip route get` output"))?;

    let ip = parts
        .get(idx + 1)
        .ok_or_else(|| anyhow::anyhow!("no IP found after `src` token"))?;

    Ok((*ip).to_string())
}

/// # Description
///
/// Initializes the TLS keys and certificates. If the keys and certificates
/// already exist, it does nothing. Otherwise, it generates them using openssl.
///
/// # Arguments
///
/// * `certs_dir`: the path to the directory where the TLS certificates are
///   stored.
/// * `clean`: if true, it removes the existing TLS certificates and generates
///   new ones.
///
/// # Returns
///
/// The path to the directory where the TLS certificates are stored.
fn initialize_tls_keys(certs_dir: Option<PathBuf>, clean: bool) -> Result<PathBuf> {
    let certs_dir = certs_dir.unwrap_or(get_default_certs_dir());

    if clean {
        match fs::remove_dir_all(&certs_dir) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => {
                error!("error removing certificates directory (path={certs_dir:?}, error={e:?})");
                anyhow::bail!("error removing certificates directory");
            }
        }
    }

    let key_path = get_private_key_path(&certs_dir);
    let cert_path = get_public_certificate_path(&certs_dir);
    if key_path.exists() | cert_path.exists() {
        info!("TLS certificates already exist, skipping TLS initialisation");
        return Ok(certs_dir);
    }

    if !certs_dir.is_dir() {
        std::fs::create_dir_all(&certs_dir)?;
    }

    let url = get_node_url()?;
    let status = Command::new("openssl")
        .arg("req")
        .arg("-x509")
        .arg("-newkey")
        .arg("rsa:4096")
        .arg("-keyout")
        .arg(&key_path)
        .arg("-out")
        .arg(&cert_path)
        .arg("-days")
        .arg("365")
        .arg("-nodes")
        .arg("-subj")
        .arg(format!("/CN={}", url))
        .arg("-addext")
        .arg(format!(
            "subjectAltName = IP:{},IP:127.0.0.1,IP:0.0.0.0,DNS:localhost",
            url
        ))
        .stderr(Stdio::null())
        .stdout(Stdio::null())
        .status()?;

    if status.success() {
        info!(
            "generated private key and certs at: {}",
            certs_dir.display()
        );
        Ok(certs_dir)
    } else {
        error!("error generating TLS private key and certificates");
        Err(anyhow::anyhow!("openssl failed with status {}", status))
    }
}

/// # Description
///
/// Loads the TLS configuration.
///
/// # Arguments
///
/// - `certs_dir`: the path to the directory where the TLS certificates are
///   stored.
/// * `clean`: if true, it removes the existing TLS certificates and generates
///   new ones.
///
/// # Returns
///
/// The TLS acceptor.
pub async fn load_config(certs_dir: Option<PathBuf>, clean: bool) -> Result<TlsAcceptor> {
    // Initialize, generating if necessary, the TLS keys and certificates.
    let certs_dir = initialize_tls_keys(certs_dir, clean)?;

    let cert_file = &mut BufReader::new(File::open(get_public_certificate_path(&certs_dir))?);
    let key_file = &mut BufReader::new(File::open(get_private_key_path(&certs_dir))?);

    let cert_chain: Vec<CertificateDer> = certs(cert_file)?
        .into_iter()
        .map(CertificateDer::from)
        .collect();

    let mut keys = pkcs8_private_keys(key_file)?;
    if keys.is_empty() {
        error!(
            "found 0 keys in PEM key file (path={:?})",
            get_private_key_path(&certs_dir)
        );
        anyhow::bail!("0 private keys found in PEM file");
    }
    let raw_key = keys.remove(0);
    let private_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(raw_key));

    let config = ServerConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
        &rustls::version::TLS12,
    ])
    .with_no_client_auth()
    .with_single_cert(cert_chain, private_key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::CryptoProvider;
    use std::{fs, io::Write};
    use tempfile::tempdir;

    #[test]
    fn test_get_certs_dir() {
        let certs_dir = get_default_certs_dir();
        assert!(certs_dir.ends_with("config/certs"));
    }

    #[test]
    fn test_get_private_key_path() {
        let certs_dir = PathBuf::from("/tmp/certs");
        let private_key_path = get_private_key_path(&certs_dir);
        assert_eq!(private_key_path, PathBuf::from("/tmp/certs/key.pem"));
    }

    #[test]
    fn test_get_public_certificate_path() {
        let certs_dir = PathBuf::from("/tmp/certs");
        let public_certificate_path = get_public_certificate_path(&certs_dir);
        assert_eq!(
            public_certificate_path,
            PathBuf::from("/tmp/certs/cert.pem")
        );
    }

    #[test]
    fn test_get_node_url() {
        // This test can only run in a linux environment with the `ip` command.
        if cfg!(not(target_os = "linux")) {
            return;
        }
        let result = get_node_url();
        assert!(result.is_ok());
    }

    #[test]
    fn test_initialize_tls_keys() {
        // This test can only run in a linux environment with the `ip` and `openssl`
        // commands.
        if cfg!(not(target_os = "linux")) {
            return;
        }
        let temp_dir = tempdir().unwrap();
        let certs_dir = temp_dir.path().to_path_buf();

        // First time, keys should be generated.
        let result = initialize_tls_keys(Some(certs_dir.clone()), false);
        assert!(result.is_ok());
        assert!(get_private_key_path(&certs_dir).exists());
        assert!(get_public_certificate_path(&certs_dir).exists());

        // Second time, keys should not be regenerated.
        let result = initialize_tls_keys(Some(certs_dir.clone()), false);
        assert!(result.is_ok());

        // With clean flag, keys should be regenerated.
        let result = initialize_tls_keys(Some(certs_dir.clone()), true);
        assert!(result.is_ok());
        assert!(get_private_key_path(&certs_dir).exists());
        assert!(get_public_certificate_path(&certs_dir).exists());
    }

    #[tokio::test]
    async fn test_load_config() {
        // This test can only run in a linux environment with the `ip` and `openssl`
        // commands.
        if cfg!(not(target_os = "linux")) {
            return;
        }

        let temp_dir = tempdir().unwrap();
        let certs_dir = temp_dir.path().to_path_buf();

        CryptoProvider::install_default(rustls::crypto::ring::default_provider()).unwrap();

        // Test with non-existent certs_dir, it should be created.
        let result = load_config(Some(certs_dir.clone()), false).await;
        assert!(result.is_ok());

        // Test with existing certs_dir.
        let result = load_config(Some(certs_dir.clone()), false).await;
        assert!(result.is_ok());

        // Test with the clean flag.
        let result = load_config(Some(certs_dir.clone()), true).await;
        assert!(result.is_ok());

        // Test with corrupted private key.
        let private_key_path = get_private_key_path(&certs_dir);
        let mut file = fs::File::create(private_key_path).unwrap();
        file.write_all(b"corrupted key").unwrap();
        let result = load_config(Some(certs_dir.clone()), false).await;
        assert!(result.is_err());

        // Test with corrupted public cert.
        let result = initialize_tls_keys(Some(certs_dir.clone()), true);
        assert!(result.is_ok());
        let public_cert_path = get_public_certificate_path(&certs_dir);
        let mut file = fs::File::create(public_cert_path).unwrap();
        file.write_all(b"corrupted cert").unwrap();
        let result = load_config(Some(certs_dir.clone()), false).await;
        assert!(result.is_err());
    }
}
