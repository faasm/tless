use crate::tls;
use anyhow::Result;
use jsonwebtoken::EncodingKey;
use log::{debug, error};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// # Description
///
/// Generate a JWT encoding key based on a certificate PEM File.
pub fn generate_encoding_key(certs_dir: &Path) -> Result<EncodingKey> {
    let priv_key_path = tls::get_private_key_path(certs_dir);
    debug!("loading private key path from: {}", priv_key_path.display());
    let pem_bytes = match std::fs::read(&priv_key_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!(
                "failed to read private key file (path={:?}, error={e:?})",
                priv_key_path
            );
            anyhow::bail!("failed to read private PEM file");
        }
    };
    let jwt_encoding_key = EncodingKey::from_rsa_pem(&pem_bytes)?;

    Ok(jwt_encoding_key)
}

/// # Description
///
/// This struct corresponds to the JWT that the attestation service returns
/// irrespective of the incoming TEE that sent the request.
#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    sub: String,
    exp: usize,
    aud: String,
    tee: String,
    /// Base64 encoded partial User Secret Key for the attributes `wf` and
    /// `node` managed by this attestation service.
    usk: String,
}

impl JwtClaims {
    pub fn new(tee: &str) -> Result<Self> {
        // FIXME: missing calling CP-ABE keygen here and populate USK.

        Ok(Self {
            sub: "attested-client".to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::minutes(5)).timestamp() as usize,
            aud: "accless-attestation-service".to_string(),
            tee: tee.to_string(),
            usk: String::new(),
        })
    }
}
