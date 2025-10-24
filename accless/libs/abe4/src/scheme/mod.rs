use crate::{curve::Gt, policy::Policy};
use iota::Iota;
use tau::Tau;
use types::{Ciphertext, GID, MPK, MSK, USK};

mod decrypt;
mod encrypt;
mod group_pairs;
mod iota;
mod keygen;
mod setup;
mod tau;
mod types;

pub fn setup(rng: impl rand::Rng, auths: &Vec<GID>) -> (MSK, MPK) {
    setup::setup(rng, auths)
}

pub fn keygen(
    rng: impl rand::Rng,
    gid: &str,
    msk: &MSK,
    user_attrs: &Vec<crate::policy::UserAttribute>,
    iota: &Iota,
) -> USK {
    keygen::keygen(rng, gid, msk, user_attrs, iota)
}

pub fn encrypt(rng: impl rand::Rng, mpk: &MPK, policy: &Policy, tau: &Tau) -> (Gt, Ciphertext) {
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
