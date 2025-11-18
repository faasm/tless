use anyhow::{Result, anyhow};
use core::fmt;

const MOCK_QUOTE_MAGIC_SGX: &[u8; 8] = b"ACCLSGX!";
const MOCK_QUOTE_MAGIC_SNP: &[u8; 8] = b"ACCLSNP!";
const MOCK_QUOTE_VERSION: u32 = 1;
const MOCK_QUOTE_HEADER_LEN: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum MockQuoteType {
    Sgx,
    Snp,
}

impl MockQuoteType {
    pub fn from_magic(magic: &[u8]) -> Result<MockQuoteType> {
        if magic == MOCK_QUOTE_MAGIC_SGX {
            Ok(MockQuoteType::Sgx)
        } else if magic == MOCK_QUOTE_MAGIC_SNP {
            Ok(MockQuoteType::Snp)
        } else {
            Err(anyhow!("Invalid MockQuoteType"))
        }
    }
}

impl fmt::Display for MockQuoteType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MockQuoteType::Sgx => write!(f, "SGX"),
            MockQuoteType::Snp => write!(f, "SNP"),
        }
    }
}

pub struct MockQuote {
    pub quote_type: MockQuoteType,
    pub user_data: Vec<u8>,
}

impl MockQuote {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < MOCK_QUOTE_HEADER_LEN {
            return Err(anyhow!("Invalid MockQuote format"));
        }

        let quote_type = MockQuoteType::from_magic(&bytes[..8])?;

        let version_bytes: [u8; 4] = bytes[8..12].try_into()?;
        let version = u32::from_le_bytes(version_bytes);
        if version != MOCK_QUOTE_VERSION {
            return Err(anyhow!("Invalid version"));
        }

        let user_data = bytes[MOCK_QUOTE_HEADER_LEN..].to_vec();

        Ok(MockQuote {
            quote_type,
            user_data,
        })
    }
}
