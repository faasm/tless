use log::warn;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VcekResponse {
    vcek_cert: String,
    certificate_chain: String,
}

/// This method can only be called from an Azure cVM
/// FIXME: gate  be
pub fn fetch_vcek_pem() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match ureq::get("http://169.254.169.254/metadata/THIM/amd/certification")
        .set("Metadata", "true")
        .call()
    {
        Ok(resp) => match resp.into_json::<VcekResponse>() {
            Ok(data) => {
                let pem = format!("{}\n{}", data.vcek_cert, data.certificate_chain);
                Ok(pem.into_bytes())
            }
            Err(e) => {
                warn!("failed to parse VCECK response JSON: {e}");
                Ok(vec![])
            }
        },
        Err(e) => {
            warn!("failed to fetch VCECK certificates: {e}");
            Ok(vec![])
        }
    }
}
