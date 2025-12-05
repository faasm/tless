//! This module contains type definitions and re-exports with convenient names.

#[cfg(any(feature = "snp", feature = "azure-cvm"))]
pub mod snp {
    use sev::{
        certs::snp::{Certificate, ca::Chain},
        firmware::{guest::AttestationReport, host::TcbVersion},
    };
    // FIXME: remove this dependency.
    use snpguest::fetch::ProcType;

    /// SNP certificate authority chain made up of AMD's root key (ARK) and
    /// AMD's signing key (ASK). Certificate chain is: ARK --(signs)--> ASK
    /// --(signs)--> VCEK --(signs)--> Report
    pub type SnpCa = Chain;

    /// SNP-enabled processor type.
    pub type SnpProcType = ProcType;

    /// SNP attestation report
    pub type SnpReport = AttestationReport;

    /// Vendor Chip Endorsement Key (i.e. X509 certificate).
    pub type SnpVcek = Certificate;

    /// We cache VCEK certificates to validate SNP reports by the processor
    /// type, and the reported TCB. Note that even though the TCB version is
    /// self-reported, it is included in the report and signed by the PSP.
    pub type SnpVcekCacheKey = (SnpProcType, TcbVersion);
}
