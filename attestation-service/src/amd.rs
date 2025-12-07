use crate::{
    request::snp::Collateral,
    state::AttestationServiceState,
    types::snp::{SnpCa, SnpProcType, SnpVcek},
};
use anyhow::Result;
use log::{debug, error, trace};
use sev::{
    certs::snp::{Verifiable, ca::Chain},
    firmware::host::TcbVersion,
};
use snpguest::fetch::ProcType;
use std::sync::Arc;

const AMD_KDS_SITE: &str = "https://kdsintf.amd.com";

/// Minimal view of an SNP report needed for AMD KDS & caching.
///
/// This trait is intentionally tiny so we can implement it for multiple report
/// types (i.e. bare metal, using snpguest, and para-virtualized using
/// az-snp-vtpm).
// FIXME(#62): unify SNP and SNP-vTPM verification logic to `sev` crate.
pub trait AmdKdsReport {
    fn version(&self) -> u32;
    fn cpuid_fam_id(&self) -> Option<u8>;
    fn cpuid_mod_id(&self) -> Option<u8>;
    fn chip_id(&self) -> &[u8; 64];
    fn tcb_version(&self) -> TcbVersion;
}

/// Implementation for the AttestationReport structure used in the `snpguest`
/// crate.
impl AmdKdsReport for sev::firmware::guest::AttestationReport {
    fn version(&self) -> u32 {
        self.version
    }

    fn cpuid_fam_id(&self) -> Option<u8> {
        self.cpuid_fam_id
    }

    fn cpuid_mod_id(&self) -> Option<u8> {
        self.cpuid_mod_id
    }

    fn chip_id(&self) -> &[u8; 64] {
        &self.chip_id
    }

    fn tcb_version(&self) -> TcbVersion {
        self.reported_tcb
    }
}

/// Implementation for the AttestationReport structure used in the az-snp-vtpm
/// crate.
impl AmdKdsReport for az_snp_vtpm::report::AttestationReport {
    fn version(&self) -> u32 {
        self.version
    }

    fn cpuid_fam_id(&self) -> Option<u8> {
        self.cpuid_fam_id
    }

    fn cpuid_mod_id(&self) -> Option<u8> {
        self.cpuid_mod_id
    }

    fn chip_id(&self) -> &[u8; 64] {
        &self.chip_id
    }

    fn tcb_version(&self) -> TcbVersion {
        TcbVersion {
            bootloader: self.reported_tcb.bootloader,
            tee: self.reported_tcb.tee,
            snp: self.reported_tcb.snp,
            microcode: self.reported_tcb.microcode,
            fmc: self.reported_tcb.fmc,
        }
    }
}

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
pub async fn fetch_vcek_from_kds<R>(proc_type: &SnpProcType, att_report: &R) -> Result<SnpVcek>
where
    R: AmdKdsReport,
{
    const KDS_VCEK: &str = "/vcek/v1";

    // The URL generation part in this function is adapted from the snpguest crate.
    let chip_id: &[u8; 64] = att_report.chip_id();
    let hw_id: String = if *chip_id != [0; 64] {
        match proc_type {
            ProcType::Turin => {
                let shorter_bytes: &[u8] = &chip_id[0..8];
                hex::encode(shorter_bytes)
            }
            _ => hex::encode(chip_id),
        }
    } else {
        let reason = "fetch_vcek_from_kds(): hardware ID is 0s on attestation report";
        error!("{reason}");
        anyhow::bail!(reason);
    };
    let tcb = att_report.tcb_version();
    let url: String = match proc_type {
        ProcType::Turin => {
            let fmc = if let Some(fmc) = tcb.fmc {
                fmc
            } else {
                return Err(anyhow::anyhow!("A Turin processor must have a fmc value"));
            };
            format!(
                "{AMD_KDS_SITE}{KDS_VCEK}/{}/\
                {hw_id}?fmcSPL={:02}&blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                proc_type_to_kds_url(proc_type),
                fmc,
                tcb.bootloader,
                tcb.tee,
                tcb.snp,
                tcb.microcode
            )
        }
        _ => {
            format!(
                "{AMD_KDS_SITE}{KDS_VCEK}/{}/\
                {hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                proc_type_to_kds_url(proc_type),
                tcb.bootloader,
                tcb.tee,
                tcb.snp,
                tcb.microcode
            )
        }
    };

    trace!("fetch_vcek_from_kds(): fetching node's VCEK (url={url})");
    let client = reqwest::Client::new();
    let response = client.get(url).send().await?;
    let response = response.error_for_status()?;

    let body = response.bytes().await?;
    let vcek = SnpVcek::from_bytes(&body)?;

    Ok(vcek)
}

async fn get_snp_ca(
    proc_type: &SnpProcType,
    state: &Arc<AttestationServiceState>,
    maybe_ca: Option<String>,
) -> Result<SnpCa> {
    debug!("get_snp_ca(): getting CA chain for SNP processor (type={proc_type})");

    // Fast path: read CA from the cache.
    let ca: Option<SnpCa> = {
        let cache = state.amd_signing_keys.read().await;
        cache.get(proc_type).cloned()
    };
    if let Some(ca) = ca {
        debug!("get_snp_ca(): cache hit, fetching CA from local cache");
        return Ok(ca);
    }

    // Slow path: parse from collateral (if provided) or fetch from AMD's KDS.

    debug!("get_snp_ca(): cache miss, fetching CA from AMD's KDS");
    let ca = if let Some(ca_str) = maybe_ca {
        let ca_chain = Chain::from_pem_bytes(ca_str.as_bytes())?;
        ca_chain.verify()?;

        trace!("get_snp_ca(): verified CA's signature from collateral");
        ca_chain
    } else {
        // This method also verifies the CA signatures.
        fetch_ca_from_kds(proc_type).await?
    };

    // Cache CA for future use.
    {
        let mut cache = state.amd_signing_keys.write().await;
        cache.insert(proc_type.clone(), ca.clone());
    }

    Ok(ca)
}

/// Helper method to get the processor model from a generic attestation report.
///
/// The logic in this model is adapted from the `snpguest` crate.
pub fn get_processor_model<R>(att_report: &R) -> Result<ProcType>
where
    R: AmdKdsReport,
{
    if att_report.version() < 3 {
        if [0u8; 64] == *att_report.chip_id() {
            let reason = "attestation report version is lower than 3 and Chip ID is all 0s. Make sure MASK_CHIP_ID is set to 0 or update firmware";
            error!("get_processor_model(): {reason}");
            anyhow::bail!(reason);
        } else {
            let chip_id = att_report.chip_id();
            if chip_id[8..64] == [0; 56] {
                return Ok(ProcType::Turin);
            } else {
                return Err(anyhow::anyhow!(
                    "Attestation report could be either Milan or Genoa. Update firmware to get a new version of the report."
                ));
            }
        }
    }

    let cpu_fam = att_report
        .cpuid_fam_id()
        .ok_or_else(|| anyhow::anyhow!("Attestation report version 3+ is missing CPU family ID"))?;

    let cpu_mod = att_report
        .cpuid_mod_id()
        .ok_or_else(|| anyhow::anyhow!("Attestation report version 3+ is missing CPU model ID"))?;

    match cpu_fam {
        0x19 => match cpu_mod {
            0x0..=0xF => Ok(ProcType::Milan),
            0x10..=0x1F | 0xA0..0xAF => Ok(ProcType::Genoa),
            _ => Err(anyhow::anyhow!("Processor model not supported")),
        },
        0x1A => match cpu_mod {
            0x0..=0x11 => Ok(ProcType::Turin),
            _ => Err(anyhow::anyhow!("Processor model not supported")),
        },
        _ => Err(anyhow::anyhow!("Processor family not supported")),
    }
}

/// Helper method to fetch the VCEK certificate to validate an SNP quote. We
/// cache the certificates based on the platform and TCB info to avoid
/// round-trips to the AMD servers during verification (in the general case).
/// When running in Azure cVMs, clients may self-report their collateral using
/// Azure's THIM layer, in which case we use that instead of AMD's KDS to
/// populate the cache.
pub async fn get_snp_vcek<R>(
    report: &R,
    state: &Arc<AttestationServiceState>,
    maybe_collateral: Option<Collateral>,
) -> Result<SnpVcek>
where
    R: AmdKdsReport,
{
    // Split the collateral into the certificate chain and the VCEK proper.
    let (maybe_vcek, maybe_chain): (Option<String>, Option<String>) = maybe_collateral
        .map(|c| (Some(c.vcek_cert_pem), Some(c.certificate_chain_pem)))
        .unwrap_or((None, None));

    // Fetch the certificate chain from the processor model.
    let proc_type = get_processor_model(report)?;
    let ca = get_snp_ca(&proc_type, state, maybe_chain).await?;

    // Work-out cache key from report.
    let tcb_version = report.tcb_version();
    let cache_key = (proc_type.clone(), tcb_version);
    debug!(
        "get_snp_vcek(): fetching VCEK key for report (proc_type={proc_type}, tcb={tcb_version})"
    );

    // Fast path: read VCEK from the cache.
    let vcek: Option<SnpVcek> = {
        let cache = state.snp_vcek_cache.read().await;
        cache.get(&cache_key).cloned()
    };
    if let Some(vcek) = vcek {
        debug!("get_snp_vcek(): cache hit, fetching VCEK from local cache");
        return Ok(vcek);
    }

    // Slow path: fetch collateral from request or, if empty, from AMD's KDS.
    let vcek = if let Some(vcek_str) = maybe_vcek {
        debug!("get_snp_vcek(): cache miss, parsing VCEK from collateral");
        SnpVcek::from_bytes(vcek_str.as_bytes())?
    } else {
        debug!("get_snp_vcek(): cache miss, fetching VCEK from AMD's KDS");
        fetch_vcek_from_kds(&proc_type, report).await?
    };

    // Once we fetch a new VCEK, verify its certificate chain before caching it.
    (&ca.ask, &vcek).verify()?;

    // Cache VCEK for future use.
    {
        let mut cache = state.snp_vcek_cache.write().await;
        cache.insert(cache_key, vcek.clone());
    }

    Ok(vcek)
}
