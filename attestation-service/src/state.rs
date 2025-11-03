#[cfg(feature = "azure-cvm")]
use crate::azure_cvm;
use crate::jwt;
use anyhow::Result;
use jsonwebtoken::EncodingKey;

/// Unique identifier for the demo attestation service.
const ATTESTATION_SERVICE_ID: &str = "accless-demo-as";

#[derive(Clone)]
pub struct AttestationServiceState {
    /// Unique ID for this attestation service. This is the field that must be
    /// included in the template graph.
    pub id: String,
    #[cfg(feature = "azure-cvm")]
    pub vcek_pem: Vec<u8>,
    pub jwt_encoding_key: EncodingKey,
}

impl AttestationServiceState {
    /// # Description
    ///
    /// Create a new instance of the attestation service state.
    pub fn new() -> Result<Self> {
        Ok(Self {
            id: ATTESTATION_SERVICE_ID.to_string(),
            #[cfg(feature = "azure-cvm")]
            vceck_pem: azure_cvm::fetch_vcek_pem()?,
            jwt_encoding_key: jwt::generate_encoding_key()?,
        })
    }
}
