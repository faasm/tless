use crate::{
    curve::Gt,
    policy::{Policy, UserAttribute},
};
use iota::Iota;
use tau::Tau;
use types::{Ciphertext, MPK, MSK, USK};

mod decrypt;
mod encrypt;
mod group_pairs;
mod iota;
mod keygen;
mod setup;
mod tau;
mod types;

pub fn setup(rng: impl rand::Rng + ark_std::rand::RngCore, auths: &Vec<&str>) -> (MSK, MPK) {
    setup::setup(rng, auths)
}

pub fn keygen(
    rng: impl rand::Rng + ark_std::rand::RngCore,
    gid: &str,
    msk: &MSK,
    user_attrs: &[UserAttribute],
    iota: &Iota,
) -> USK {
    keygen::keygen(rng, gid, msk, user_attrs, iota)
}

pub fn encrypt(
    rng: impl rand::Rng + ark_std::rand::RngCore,
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
