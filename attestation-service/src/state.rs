#[cfg(feature = "azure-cvm")]
use crate::azure_cvm;
#[cfg(feature = "sgx")]
use crate::intel::{IntelCa, SgxCollateral};
use crate::{jwt, tls::get_default_certs_dir};
use anyhow::Result;
#[cfg(feature = "sgx")]
use jsonwebtoken::EncodingKey;
use std::{collections::HashMap, path::PathBuf};
use tokio::sync::RwLock;

/// Unique identifier for the demo attestation service.
const ATTESTATION_SERVICE_ID: &str = "accless-demo-as";

pub struct AttestationServiceState {
    /// Unique ID for this attestation service. This is the field that must be
    /// included in the template graph, and is the field we use to run CP-ABE
    /// key generation.
    pub id: String,
    #[cfg(feature = "azure-cvm")]
    pub vcek_pem: Vec<u8>,
    pub jwt_encoding_key: EncodingKey,
    /// URL to a Provisioning Certificate Caching Service (PCCS) to verify SGX
    /// quotes.
    #[cfg(feature = "sgx")]
    pub sgx_pccs_url: Option<PathBuf>,
    /// Cache of SGX collateral. The key is a tuple that identifies the TCB
    /// version of the quote, as different TCB versions require different
    /// collaterals.
    #[cfg(feature = "sgx")]
    pub sgx_collateral_cache: RwLock<HashMap<(String, IntelCa), SgxCollateral>>,
    /// Run the SGX handler in mock mode, skipping quote verification while
    /// still exercising the rest of the request flow.
    pub mock_sgx: bool,
}

impl AttestationServiceState {
    /// # Description
    ///
    /// Create a new instance of the attestation service state.
    pub fn new(
        certs_dir: Option<PathBuf>,
        sgx_pccs_url: Option<PathBuf>,
        mock_sgx: bool,
    ) -> Result<Self> {
        let certs_dir = certs_dir.unwrap_or_else(get_default_certs_dir);

        Ok(Self {
            id: ATTESTATION_SERVICE_ID.to_string(),
            #[cfg(feature = "azure-cvm")]
            vceck_pem: azure_cvm::fetch_vcek_pem()?,
            jwt_encoding_key: jwt::generate_encoding_key(&certs_dir)?,
            #[cfg(feature = "sgx")]
            sgx_pccs_url,
            #[cfg(feature = "sgx")]
            sgx_collateral_cache: RwLock::new(HashMap::new()),
            mock_sgx,
        })
    }
}
