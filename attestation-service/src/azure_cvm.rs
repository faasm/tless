use log::warn;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VcekResponse {
    vcek_cert: String,
    certificate_chain: String,
}

/// This method can only be called from an Azure cVM
pub fn fetch_vcek_pem() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // FIXME(#55): re-introduce azure cvm quote validation. In the past we used this
    // URL to fetch VCEK certificates:
    // http://169.254.169.254/metadata/THIM/amd/certification
    Ok(vec![])
}
