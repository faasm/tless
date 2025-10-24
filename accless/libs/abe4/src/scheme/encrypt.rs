use crate::{
    curve::{G, Gt, H, ScalarField, pairing},
    hashing::{
        HashSign::{NEG, POS},
        hash_attr, hash_lbl,
    },
    policy::Policy,
    scheme::{
        tau::Tau,
        types::{Ciphertext, MPK},
    },
};
use ark_ec::{Group, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_std::{ops::Mul, rand::Rng};
use std::collections::HashMap;

fn share_secret(
    mut rng: impl Rng,
    secret: ScalarField,
    policy: &Policy,
) -> (Vec<ScalarField>, Vec<ScalarField>, usize) {
    let n = policy.len();
    let splits = policy.share_secret();
    let mut v_vec = Vec::with_capacity(n);
    let mut v_prime_vec = Vec::with_capacity(n);
    let mut lambda_vec = Vec::with_capacity(n);
    let mut mu_vec = Vec::with_capacity(n);
    let zero = ScalarField::from(0);
    for _ in 0..n {
        v_vec.push(ScalarField::rand(&mut rng));
        v_prime_vec.push(ScalarField::rand(&mut rng));
        lambda_vec.push(zero);
        mu_vec.push(zero);
    }
    v_vec[0] = secret;
    v_prime_vec[0] = zero;
    for (i, (_, idcs)) in splits.iter().enumerate() {
        for j in idcs {
            if *j >= 0 {
                let k = *j as usize;
                lambda_vec[i] += v_vec[k];
                mu_vec[i] += v_prime_vec[k];
            } else {
                let k = (0 - *j) as usize;
                lambda_vec[i] -= v_vec[k];
                mu_vec[i] -= v_prime_vec[k];
            }
        }
    }
    (lambda_vec, mu_vec, n)
}

pub fn encrypt(mut rng: impl Rng, mpk: &MPK, policy: &Policy, tau: &Tau) -> (Gt, Ciphertext) {
    let s = ScalarField::rand(&mut rng);
    let m = std::cmp::max(tau.get_max(), tau.get_tilde_max());
    let mut s_vec = Vec::with_capacity(m + 1);
    for _ in 0..=m {
        s_vec.push(ScalarField::rand(&mut rng));
    }
    let (lambda_vec, mu_vec, n) = share_secret(&mut rng, s, policy);
    let mut lbl_pos_0 = HashMap::new();
    let mut lbl_pos_1 = HashMap::new();
    let mut lbl_neg_0 = HashMap::new();
    let mut lbl_neg_1 = HashMap::new();
    for j in 0..n {
        let (user_attr, is_neg) = policy.get(j);
        let auth = user_attr.auth;
        let lbl = user_attr.lbl;
        let key = (auth.clone(), lbl.clone());
        if is_neg && !lbl_neg_0.contains_key(&key) {
            lbl_neg_0.insert(key.clone(), hash_lbl(&auth, &lbl, NEG, 0));
            lbl_neg_1.insert(key, hash_lbl(&auth, &lbl, NEG, 1));
        } else if !lbl_pos_0.contains_key(&key) {
            lbl_pos_0.insert(key.clone(), hash_lbl(&auth, &lbl, POS, 0));
            lbl_pos_1.insert(key.clone(), hash_lbl(&auth, &lbl, POS, 1));
        }
    }
    let mut c_1_vec = Vec::with_capacity(n);
    let mut c_2_vec = Vec::with_capacity(n);
    let mut c_3_vec = Vec::with_capacity(n);
    for j in 0..n {
        let (user_attr, is_neg) = policy.get(j);
        let auth = user_attr.auth;
        let attr = user_attr.attr;
        let lbl = user_attr.lbl;
        let mu = mu_vec[j];
        let lambda = lambda_vec[j];
        let s_tilde = s_vec[tau.get_tilde(&auth, &lbl, &attr)];
        let s = s_vec[tau.get(&auth, &lbl, &attr)];
        let x_attr = hash_attr(&attr);
        let mpk = mpk.get_partial_key(&auth).unwrap();
        let b = if is_neg { mpk.b_not } else { mpk.b };
        let h = H::generator();
        let key = (auth.clone(), lbl.clone());
        let (lbl_0, lbl_1) = if is_neg {
            (
                *lbl_neg_0.get(&key).unwrap(),
                *lbl_neg_1.get(&key).unwrap(),
            )
        } else {
            (
                *lbl_pos_0.get(&key).unwrap(),
                *lbl_pos_1.get(&key).unwrap(),
            )
        };
        if is_neg {
            c_1_vec.push(h.mul(mu) + b.mul(s_tilde));
            let c_2 = G::msm(&[lbl_0, lbl_1], &[s_tilde, s_tilde * x_attr]).unwrap();
            c_2_vec.push(c_2);
        } else {
            c_1_vec.push(h.mul(mu) + b.mul(s_tilde));
            let c_2 = G::msm(&[lbl_0, lbl_1], &[s, s * x_attr]).unwrap();
            c_2_vec.push(mpk.b_prime.mul(s_tilde) + c_2);
        }
        c_3_vec.push(h.mul(lambda) + mpk.a.mul(s_tilde));
    }
    let mut c_4_vec = Vec::with_capacity(m + 1);
    for j in 0..=m {
        let h = H::generator();
        let s = s_vec[j];
        c_4_vec.push(h.mul(s));
    }
    let k = pairing(G::generator(), H::generator()).mul(s).0;
    let ct = Ciphertext {
        c_1_vec,
        c_2_vec,
        c_3_vec,
        c_4_vec,
    };
    (k, ct)
}
