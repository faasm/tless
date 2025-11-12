use crate::Env;
use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose};
use reqwest::{Client, tls};
use std::{env, fs};

// FIXME: this is all old code, probably can delete

fn get_as_url() -> Result<String> {
    env::var("AS_URL").context("AS_URL env. var not set")
}

fn get_tls_client() -> Result<Client> {
    let certs_path = Env::proj_root().join("attestation-service/certs/cert.pem");
    let cert_bytes = fs::read(certs_path).context("cannot open attestaion-service cert path")?;
    let cert = tls::Certificate::from_pem(&cert_bytes)?;

    let client = Client::builder().add_root_certificate(cert).build()?;

    Ok(client)
}

/// See note below
pub async fn get_tee_identity() -> Result<String> {
    let resp = get_tls_client()?
        .get(format!("{}/get-tee-identity", get_as_url()?))
        .send()
        .await?;
    Ok(resp.text().await?)
}

/// This method gets the TEE shared encryption key from the attestation
/// service. Note that, in a production environment, this key would only be
/// delivered if this method is being called from a TEE with the right
/// measurement.
///
/// TODO: implement logic to fetch our attestation report here and send it
/// as part of the `get-keys` request.
pub async fn get_tee_shared_key() -> Result<[u8; 32]> {
    let resp = get_tls_client()?
        .get(format!("{}/get-keys", get_as_url()?))
        .send()
        .await?;
    let key_b64 = resp.text().await?;

    let decoded = general_purpose::STANDARD.decode(key_b64)?;
    if decoded.len() != 32 {
        bail!("invalid AES-256 key length");
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);

    Ok(key)
}
