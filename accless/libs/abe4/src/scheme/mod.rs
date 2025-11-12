use crate::{
    curve::Gt,
    policy::{Policy, UserAttribute},
};
use iota::Iota;
use rand::Rng;
use tau::Tau;
use types::{Ciphertext, MPK, MSK, PartialMPK, PartialMSK, PartialUSK, USK};

mod decrypt;
mod encrypt;
mod group_pairs;
pub mod iota;
mod keygen;
mod setup;
pub mod tau;
pub mod types;

pub fn setup_partial(rng: impl Rng, authority: &str) -> (PartialMSK, PartialMPK) {
    setup::setup_partial(rng, authority)
}

pub fn setup(rng: impl ark_std::rand::RngCore, auths: &Vec<&str>) -> (MSK, MPK) {
    setup::setup(rng, auths)
}

pub fn keygen_partial(
    rng: impl Rng,
    gid: &str,
    msk: &PartialMSK,
    user_attrs: &[&UserAttribute],
    iota: &Iota,
) -> PartialUSK {
    keygen::keygen_partial(rng, gid, msk, user_attrs, iota)
}

pub fn keygen(
    rng: impl ark_std::rand::RngCore,
    gid: &str,
    msk: &MSK,
    user_attrs: &[UserAttribute],
    iota: &Iota,
) -> USK {
    keygen::keygen(rng, gid, msk, user_attrs, iota)
}

pub fn encrypt(
    rng: impl ark_std::rand::RngCore,
    mpk: &MPK,
    policy: &Policy,
    tau: &Tau,
) -> (Gt, Ciphertext) {
    encrypt::encrypt(rng, mpk, policy, tau)
}

pub fn decrypt(
    usk: &USK,
    gid: &str,
    iota: &Iota,
    tau: &Tau,
    policy: &Policy,
    ct: &Ciphertext,
) -> Option<Gt> {
    decrypt::decrypt(usk, gid, iota, tau, policy, ct)
}
