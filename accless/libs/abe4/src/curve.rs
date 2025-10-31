use crate::hashing::swift_ec::SwiftConfig;
use ark_bls12_381::Bls12_381;
// Use the regular group assignment: G is G and H is H
pub use ark_bls12_381::{
    Fq, Fq12 as Gt, Fr as ScalarField, G1Affine as GAffine, G1Projective as G, G2Projective as H,
    g1::Config as G1Config,
};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ff::MontFp;

impl SwiftConfig for G1Config {
    const SQRT_MINUS3: Fq = MontFp!(
        "1586958781458431025242759403266842894121773480562120986020912974854563298150952611241517463240701"
    );
}

pub fn pairing(
    p: impl Into<<Bls12_381 as Pairing>::G1Prepared>,
    q: impl Into<<Bls12_381 as Pairing>::G2Prepared>,
) -> PairingOutput<Bls12_381> {
    Bls12_381::pairing(p, q)
}

// Flip the groups, i.e. each G is actually H and each H is actually G
// pub use ark_bls12_381::{
//     g2::Config as G1Config, Fq12 as Gt, Fr as ScalarField, G2Affine as
// GAffine,     G2Projective as G, G1Projective as H
// };

// use ark_bls12_381::Bls12_381;
// use ark_ec::pairing::{Pairing, PairingOutput};

// pub fn pairing(
//         p: impl Into<<Bls12_381 as Pairing>::G2Prepared>,
//         q: impl Into<<Bls12_381 as Pairing>::G1Prepared>)
//     -> PairingOutput<Bls12_381> {
//     Bls12_381::pairing(q, p)
// }
