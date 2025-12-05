#[cfg(feature = "sgx")]
use crate::intel::{IntelCa, SgxCollateral};
#[cfg(any(feature = "snp", feature = "azure-cvm"))]
use crate::types::snp::{SnpCa, SnpProcType, SnpVcek, SnpVcekCacheKey};
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
    /// Full URL of the attestation service, including IP and port.
    pub external_url: String,
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

    // Amd SEV-SNP (bare-metal or para-virtualized).
    /// AMD's root (ARK) and signing (ASK) keys, which make up the ceritificate
    /// chain of SNP reports:
    #[cfg(any(feature = "snp", feature = "azure-cvm"))]
    pub amd_signing_keys: RwLock<BTreeMap<SnpProcType, SnpCa>>,
    /// Cache of VCEK certificates used to validate the signatures of SNP
    /// reports.
    ///
    /// We use a BTreeMap to workaround the lack of Hash traits for the cache
    /// key, which is a tuple of types we don't control.
    #[cfg(any(feature = "snp", feature = "azure-cvm"))]
    pub snp_vcek_cache: RwLock<BTreeMap<SnpVcekCacheKey, SnpVcek>>,
}

impl AttestationServiceState {
    /// # Description
    ///
    /// Create a new instance of the attestation service state.
    pub fn new(
        certs_dir: Option<PathBuf>,
        sgx_pccs_url: Option<PathBuf>,
        mock_attestation: bool,
        external_url: String,
    ) -> Result<Self> {
        let certs_dir = certs_dir.unwrap_or_else(get_default_certs_dir);

        // Initialize CP-ABE authority.
        let mut rng = rand::thread_rng();
        let (partial_msk, partial_mpk): (PartialMSK, PartialMPK) =
            abe4::scheme::setup_partial(&mut rng, ATTESTATION_SERVICE_ID);

        // Fetch AMD signing keys.

        Ok(Self {
            external_url,
            mock_attestation,
            jwt_encoding_key: jwt::generate_encoding_key(&certs_dir)?,
            id: ATTESTATION_SERVICE_ID.to_string(),
            partial_msk,
            partial_mpk,
            #[cfg(feature = "sgx")]
            sgx_pccs_url,
            #[cfg(feature = "sgx")]
            sgx_collateral_cache: RwLock::new(HashMap::new()),
            #[cfg(any(feature = "snp", feature = "azure-cvm"))]
            amd_signing_keys: RwLock::new(BTreeMap::new()),
            #[cfg(any(feature = "snp", feature = "azure-cvm"))]
            snp_vcek_cache: RwLock::new(BTreeMap::new()),
        })
    }
}
