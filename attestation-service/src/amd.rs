use anyhow::Result;
use log::{error, trace};
use sev::{
    certs::snp::{Certificate, Verifiable, ca::Chain},
    firmware::{guest::AttestationReport, host::TcbVersion},
};
use snpguest::fetch::ProcType;

/// SNP certificate authority chain made up of AMD's root key (ARK) and AMD's
/// signing key (ASK). Certificate chain is: ARK --(signs)--> ASK --(signs)-->
/// VCEK --(signs)--> Report
pub type SnpCa = Chain;

/// SNP-enabled processor type.
pub type SnpProcType = ProcType;

/// SNP attestation report
pub type SnpReport = AttestationReport;

/// Vendor Chip Endorsement Key
pub type SnpVcek = Certificate;

/// # Description
///
/// We cache VCEK certificates to validate SNP reports by the processor type,
/// and the reported TCB. Note that even though the TCB version is
/// self-reported, it is included in the report and signed by the PSP.
pub type SnpVcekCacheKey = (SnpProcType, TcbVersion);

const AMD_KDS_SITE: &str = "https://kdsintf.amd.com";

fn proc_type_to_kds_url(proc_type: &SnpProcType) -> &str {
    match proc_type {
        SnpProcType::Genoa | SnpProcType::Siena | SnpProcType::Bergamo => "Genoa",
        SnpProcType::Milan => "Milan",
        SnpProcType::Turin => "Turin",
    }
}

/// Fetches AMD's ceritifcate authorities from AMD's Key Distribution Service.
pub async fn fetch_ca_from_kds(proc_type: &SnpProcType) -> Result<SnpCa> {
    const AMD_KDS_CERT_CHAIN: &str = "cert_chain";

    let proc_str = proc_type_to_kds_url(proc_type);
    let url: String = format!("{AMD_KDS_SITE}/vcek/v1/{proc_str}/{AMD_KDS_CERT_CHAIN}");
    trace!("fetch_ca_from_kds(): fetching AMD's CA (url={url})");
    let client = reqwest::Client::new();
    let response = client.get(url).send().await?;
    let response = response.error_for_status()?;

    let body = response.bytes().await?;
    let ca_chain = Chain::from_pem_bytes(&body)?;

    // Before returning it, verify the signatures.
    ca_chain.verify()?;
    trace!("fetch_ca_from_kds(): verified CA's signature");

    Ok(ca_chain)
}

/// Fetches a processor's Vendor-Chip Endorsement Key (VCEK) from AMD's KDS.
pub async fn fetch_vcek_from_kds(
    proc_type: &SnpProcType,
    att_report: &SnpReport,
) -> Result<SnpVcek> {
    const KDS_VCEK: &str = "/vcek/v1";

    // The URL generation part in this function is adapted from the snpguest crate.
    let hw_id: String = if att_report.chip_id != [0; 64] {
        match proc_type {
            ProcType::Turin => {
                let shorter_bytes: &[u8] = &att_report.chip_id[0..8];
                hex::encode(shorter_bytes)
            }
            _ => hex::encode(att_report.chip_id),
        }
    } else {
        let reason = "fetch_vcek_from_kds(): hardware ID is 0s on attestation report";
        error!("{reason}");
        anyhow::bail!(reason);
    };
    let url: String = match proc_type {
        ProcType::Turin => {
            let fmc = if let Some(fmc) = att_report.reported_tcb.fmc {
                fmc
            } else {
                return Err(anyhow::anyhow!("A Turin processor must have a fmc value"));
            };
            format!(
                "{AMD_KDS_SITE}{KDS_VCEK}/{}/\
                {hw_id}?fmcSPL={:02}&blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                proc_type_to_kds_url(proc_type),
                fmc,
                att_report.reported_tcb.bootloader,
                att_report.reported_tcb.tee,
                att_report.reported_tcb.snp,
                att_report.reported_tcb.microcode
            )
        }
        _ => {
            format!(
                "{AMD_KDS_SITE}{KDS_VCEK}/{}/\
                {hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                proc_type_to_kds_url(proc_type),
                att_report.reported_tcb.bootloader,
                att_report.reported_tcb.tee,
                att_report.reported_tcb.snp,
                att_report.reported_tcb.microcode
            )
        }
    };

    trace!("fetch_vcek_from_kds(): fetching node's VCEK (url={url})");
    let client = reqwest::Client::new();
    let response = client.get(url).send().await?;
    let response = response.error_for_status()?;

    let body = response.bytes().await?;
    let vcek = Certificate::from_bytes(&body)?;

    Ok(vcek)
}
