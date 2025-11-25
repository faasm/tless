#[cfg(feature = "snp")]
use crate::amd::{SnpCa, SnpProcType, SnpVcek, SnpVcekCacheKey};
#[cfg(feature = "azure-cvm")]
use crate::azure_cvm;
#[cfg(feature = "sgx")]
use crate::intel::{IntelCa, SgxCollateral};
use crate::{jwt, tls::get_default_certs_dir};
use abe4::scheme::types::{PartialMPK, PartialMSK};
use anyhow::Result;
#[cfg(feature = "sgx")]
use jsonwebtoken::EncodingKey;
use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
};
use tokio::sync::RwLock;

/// Unique alphanumeric identifier for the demo attestation service.
const ATTESTATION_SERVICE_ID: &str = "4CL3SSD3M0";

pub struct AttestationServiceState {
    // General attestation service fields.
    /// Run the attestation handlers in mock mode, skipping quote verification
    /// while still exercising the rest of the request flow.
    pub mock_attestation: bool,
    /// JWT encoding key derived from the service's public certificate.
    pub jwt_encoding_key: EncodingKey,

    // Fields related to attribute-based encryption.
    /// Unique ID for this attestation service. This is the field that must be
    /// included in the template graph, and is the field we use to run CP-ABE
    /// key generation.
    pub id: String,
    /// Master Secret Key for the attestation service as one of the authorities
    /// of the decentralized CP-ABE scheme.
    pub partial_msk: PartialMSK,
    /// Master Pulic Key for the attestation service as one of the authorities
    /// of the decentralized CP-ABE scheme.
    pub partial_mpk: PartialMPK,

    // Fields related to verifying attestation reports from TEEs.

    // Intel SGX.
    /// URL to a Provisioning Certificate Caching Service (PCCS) to verify SGX
    /// quotes.
    #[cfg(feature = "sgx")]
    pub sgx_pccs_url: Option<PathBuf>,
    /// Cache of SGX collateral. The key is a tuple that identifies the TCB
    /// version of the quote, as different TCB versions require different
    /// collaterals.
    #[cfg(feature = "sgx")]
    pub sgx_collateral_cache: RwLock<HashMap<(String, IntelCa), SgxCollateral>>,

    // Amd SEV-SNP.
    #[cfg(feature = "snp")]
    /// AMD's root (ARK) and signing (ASK) keys, which make up the ceritificate
    /// chain of SNP reports:
    pub amd_signing_keys: RwLock<BTreeMap<SnpProcType, SnpCa>>,
    /// Cache of VCEK certificates used to validate the signatures of SNP
    /// reports.
    ///
    /// We use a BTreeMap to workaround the lack of Hash traits for the cache
    /// key, which is a tuple of types we don't control.
    pub snp_vcek_cache: RwLock<BTreeMap<SnpVcekCacheKey, SnpVcek>>,

    #[cfg(feature = "azure-cvm")]
    pub vcek_pem: Vec<u8>,
    /// Port the server is listening on.
    pub port: u16,
}

impl AttestationServiceState {
    /// # Description
    ///
    /// Create a new instance of the attestation service state.
    pub fn new(
        certs_dir: Option<PathBuf>,
        sgx_pccs_url: Option<PathBuf>,
        mock_attestation: bool,
        port: u16,
    ) -> Result<Self> {
        let certs_dir = certs_dir.unwrap_or_else(get_default_certs_dir);

        // Initialize CP-ABE authority.
        let mut rng = rand::thread_rng();
        let (partial_msk, partial_mpk): (PartialMSK, PartialMPK) =
            abe4::scheme::setup_partial(&mut rng, ATTESTATION_SERVICE_ID);

        // Fetch AMD signing keys.

        Ok(Self {
            mock_attestation,
            jwt_encoding_key: jwt::generate_encoding_key(&certs_dir)?,
            id: ATTESTATION_SERVICE_ID.to_string(),
            partial_msk,
            partial_mpk,
            #[cfg(feature = "azure-cvm")]
            vceck_pem: azure_cvm::fetch_vcek_pem()?,
            #[cfg(feature = "sgx")]
            sgx_pccs_url,
            #[cfg(feature = "sgx")]
            sgx_collateral_cache: RwLock::new(HashMap::new()),
            #[cfg(feature = "snp")]
            amd_signing_keys: RwLock::new(BTreeMap::new()),
            #[cfg(feature = "snp")]
            snp_vcek_cache: RwLock::new(BTreeMap::new()),
            port,
        })
    }
}
