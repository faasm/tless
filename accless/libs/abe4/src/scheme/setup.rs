use crate::{
    curve::{G, H, ScalarField},
    scheme::types::{MPK, MSK, PartialMPK, PartialMSK},
};
use ark_ec::Group;
use ark_ff::UniformRand;
use ark_std::{ops::Mul, rand::Rng};

/// # Description
///
/// This function sets up the decentralized CP-ABE crypto-system. Based on an
/// array of authorities identified by their global identifier, it generates a
/// key-pair that is a collection of each individual partial key.
///
/// Note that in the setup phase we generate the partial secret and public key
/// for each authority, uniquely identified by their identifier. Technically,
/// this process could be run by each authority individually, here we run all of
/// them together for convenicence.
///
/// # Arguments
///
/// - `rng`: pseudo-random number generator
/// - `authorities`: array of unique string identifiers for each authority
///   involverd in the scheme
///
/// # Returns
///
/// This function returns a tuple (MSK, MPK) where each one is a HashMap of
/// the Secret or Public key for each authority:
/// - MSK: {auth1: auth1_MSK, auth2: auth2_MSK, ... }
/// - MPK: {auth1: auth1_MPK, auth2: auth2_MPK, ... }
///
/// # Example usage
///
/// TODO: add me
pub fn setup(mut rng: impl Rng, authorities: &Vec<&str>) -> (MSK, MPK) {
    let mut msk = MSK::new();
    let mut mpk = MPK::new();

    for auth in authorities {
        let (partial_msk, partial_mpk) = setup_partial(&mut rng, auth);
        msk.add_partial_key(partial_msk);
        mpk.add_partial_key(partial_mpk);
    }

    (msk, mpk)
}

/// Given an authority identified by its global identifier (GID), generate a
/// parial keypair.
pub fn setup_partial(mut rng: impl Rng, authority: &str) -> (PartialMSK, PartialMPK) {
    let beta = ScalarField::rand(&mut rng);
    let b = ScalarField::rand(&mut rng);
    let b_not = ScalarField::rand(&mut rng);
    let b_prime = ScalarField::rand(&mut rng);
    let msk = PartialMSK {
        auth: authority.to_string(),
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
        auth: authority.to_string(),
        a,
        b,
        b_not,
        b_prime,
    };

    (msk, mpk)
}
