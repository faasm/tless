use crate::{
    curve::{G, H, ScalarField},
    scheme::types::{GID, MPK, MSK, PartialMPK, PartialMSK},
};
use ark_ec::Group;
use ark_ff::UniformRand;
use ark_std::{ops::Mul, rand::Rng};

/// This function sets up the decentralized CP-ABE crypto-system. Based
/// on an array of authorities identified by their global identifier, it
/// generates a key-pair that is a collection of each individual partial key.
pub fn setup(mut rng: impl Rng, authorities: &Vec<GID>) -> (MSK, MPK) {
    let mut msk = MSK::new();
    let mut mpk = MPK::new();

    for auth in authorities {
        let (partial_msk, partial_mpk) = setup_partial(&mut rng, auth.to_string());
        msk.add_partial_key(partial_msk);
        mpk.add_partial_key(partial_mpk);
    }

    (msk, mpk)
}

/// Given an authority identified by its global identifier (GID), generate a
/// parial keypair.
pub fn setup_partial(mut rng: impl Rng, authority: GID) -> (PartialMSK, PartialMPK) {
    let beta = ScalarField::rand(&mut rng);
    let b = ScalarField::rand(&mut rng);
    let b_not = ScalarField::rand(&mut rng);
    let b_prime = ScalarField::rand(&mut rng);
    let msk = PartialMSK {
        auth: authority.clone(),
        beta,
        b,
        b_not,
        b_prime,
    };

    let a = H::generator().mul(beta);
    let b = H::generator().mul(b);
    let b_not = H::generator().mul(b_not);
    let b_prime = G::generator().mul(b_prime);
    let mpk = PartialMPK {
        auth: authority.clone(),
        a,
        b,
        b_not,
        b_prime,
    };

    (msk, mpk)
}
