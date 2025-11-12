use dcap_qvl::{QuoteCollateralV3, quote::Quote};
use std::str::FromStr;

/// Re-export types with convenient names.
pub type SgxCollateral = QuoteCollateralV3;
pub type SgxQuote = Quote;

/// # Description
///
/// Intel's Provisioning Certificate Service URL.
pub const INTEL_PCS_URL: &str = "https://api.trustedservices.intel.com";

/// # Description
///
/// Identifier of the CA that issued the request, Intel only allows two values:
/// "processor" and "platform".
///
/// See: https://api.portal.trustedservices.intel.com/content/documentation.html
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum IntelCa {
    Processor,
    Platform,
}

impl IntelCa {
    pub fn as_str(self) -> &'static str {
        match self {
            IntelCa::Processor => "processor",
            IntelCa::Platform => "platform",
        }
    }
}

impl FromStr for IntelCa {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "processor" | "Processor" => Ok(IntelCa::Processor),
            "platform" | "Platform" => Ok(IntelCa::Platform),
            _ => Err("invalid CA: must be 'processor' or 'platform'"),
        }
    }
}
