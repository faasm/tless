use crate::{request::Tee, state::AttestationServiceState, tls};
use abe4::{policy::UserAttribute, scheme::types::PartialUSK};
use anyhow::Result;
use ark_serialize::CanonicalSerialize;
use base64::engine::{Engine as _, general_purpose};
use jsonwebtoken::EncodingKey;
use log::{debug, error};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// # Description
///
/// Constant for the workflow attribute label managed by the attestation
/// service.
const ATTRIBUTE_WORKFLOW_LABEL: &str = "wf";

/// # Description
///
/// Constant for the node attribute label managed by the attestation service.
const ATTRIBUTE_NODE_LABEL: &str = "node";

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
    partial_usk_b64: String,
}

impl JwtClaims {
    /// # Description
    ///
    /// Generates a new JWT based on the attestation service state, and the
    /// specific request metadata.
    ///
    /// # Arguments
    ///
    /// - `state`: handle to the attestation service state.
    /// - `tee`: type of TEE we are generating the claim for.
    /// - `gid`: unique user identifier owning the encrypted data.
    /// - `workflow_id`: unique identifier of the workflow graph we are
    ///   executing.
    /// - `node_id`: unique identifier of the node in the workflow graph we are
    ///   executing.
    pub fn new(
        state: &AttestationServiceState,
        tee: &Tee,
        gid: &str,
        workflow_id: &str,
        node_id: &str,
    ) -> Result<Self> {
        let rng = rand::thread_rng();
        let user_attributes: Vec<UserAttribute> = vec![
            abe4::policy::UserAttribute::new(&state.id, ATTRIBUTE_WORKFLOW_LABEL, workflow_id),
            abe4::policy::UserAttribute::new(&state.id, ATTRIBUTE_NODE_LABEL, node_id),
        ];
        debug!("Generating partial USK for gid: {}", gid);
        debug!("- Workflow ID: {}", workflow_id);
        debug!("- Node ID: {}", node_id);
        debug!("- User Attributes: {:?}", user_attributes);

        let user_attribute_refs: Vec<&UserAttribute> = user_attributes.iter().collect();
        let iota = abe4::scheme::iota::Iota::new(&user_attributes);
        let partial_usk: PartialUSK =
            abe4::scheme::keygen_partial(rng, gid, &state.partial_msk, &user_attribute_refs, &iota);
        let mut partial_usk_bytes: Vec<u8> = Vec::new();
        partial_usk.serialize_compressed(&mut partial_usk_bytes)?;

        Ok(Self {
            sub: "attested-client".to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::minutes(5)).timestamp() as usize,
            aud: "accless-attestation-service".to_string(),
            tee: tee.to_string(),
            partial_usk_b64: general_purpose::STANDARD.encode(&partial_usk_bytes),
        })
    }
}
