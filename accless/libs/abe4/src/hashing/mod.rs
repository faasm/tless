use crate::curve::{G1Config, GAffine, ScalarField};
use ark_ec::{hashing::HashToCurve, short_weierstrass::Projective};
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use sha2::{Digest, Sha256};
use swift_ec::SwiftECMap;
use swift_hasher::SwiftMapToCurveBasedHasher;

pub mod swift_ec;
pub mod swift_hasher;

const DEFAULT_FIELD_HASHER_SEC_PARAM: usize = 128;
const GID_DOMAIN: &str = "GID";
const AUTH_ID_DOMAIN: &str = "AID";
const XATTR_DOMAIN: &str = "XAT";
const HASH_SIGN_POS: &str = "POS";
const HASH_SIGN_NEG: &str = "NEG";

#[derive(Copy, Clone)]
pub enum HashSign {
    Pos,
    Neg,
}

fn sha256(data: impl AsRef<[u8]>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub fn hash_gid(gid: &str) -> GAffine {
    let domain = GID_DOMAIN.as_bytes();
    let g_mapper = SwiftMapToCurveBasedHasher::<
        Projective<G1Config>,
        DefaultFieldHasher<Sha256, DEFAULT_FIELD_HASHER_SEC_PARAM>,
        SwiftECMap<G1Config>,
    >::new(domain)
    .unwrap();
    g_mapper.hash(gid.as_bytes()).unwrap()
}

pub fn hash_attr(attr: &str) -> ScalarField {
    let domain = XATTR_DOMAIN.as_bytes();
    let hasher = <DefaultFieldHasher<Sha256> as HashToField<ScalarField>>::new(domain);
    hasher.hash_to_field(attr.as_bytes(), 1)[0]
}

pub fn hash_lbl(auth_id: &str, lbl: &str, sign: HashSign, i: u64) -> GAffine {
    let domain = AUTH_ID_DOMAIN.as_bytes();
    let g_mapper = SwiftMapToCurveBasedHasher::<
        Projective<G1Config>,
        DefaultFieldHasher<Sha256, DEFAULT_FIELD_HASHER_SEC_PARAM>,
        SwiftECMap<G1Config>,
    >::new(domain)
    .unwrap();
    let sign = match sign {
        HashSign::Pos => HASH_SIGN_POS,
        HashSign::Neg => HASH_SIGN_NEG,
    };
    let mut input = Vec::new();
    input.extend_from_slice(&sha256(auth_id));
    input.extend_from_slice(&sha256(lbl));
    input.extend_from_slice(&sha256(sign));
    input.extend_from_slice(&i.to_be_bytes());
    g_mapper.hash(input.as_slice()).unwrap()
}
