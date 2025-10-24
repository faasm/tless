use crate::{
    curve::{G, Gt, H, ScalarField, pairing},
    hashing::{hash_attr, hash_gid},
    policy::Policy,
    scheme::{
        group_pairs::group_pairs,
        iota::Iota,
        tau::Tau,
        types::{Ciphertext, USK},
    },
};
use ark_ec::{CurveGroup, Group, VariableBaseMSM};
use ark_ff::Field;
use ark_std::{Zero, ops::Neg};
use std::collections::HashSet;

fn solve_lse(usk: &USK, policy: &Policy) -> Option<(Vec<usize>, Vec<usize>)> {
    let user_attrs = usk.get_user_attributes();
    let eps_all = policy.reconstruct_secret(&user_attrs)?;
    let (eps_not_vec, eps_vec) = eps_all.into_iter().partition(|i| policy.get(*i).1);
    Some((eps_vec, eps_not_vec))
}

pub fn decrypt(
    usk: &USK,
    gid: &str,
    iota: &Iota,
    tau: &Tau,
    policy: &Policy,
    ct: &Ciphertext,
) -> Option<Gt> {
    let (eps_vec, eps_not_vec) = solve_lse(usk, policy)?;
    let mut k = Gt::ONE;
    let mut c_1 = H::zero();
    let mut c_3 = H::zero();
    for j in eps_vec.iter().chain(eps_not_vec.iter()) {
        c_1 += ct.c_1_vec[*j];
        c_3 += ct.c_3_vec[*j];
    }
    k *= pairing(G::generator(), c_3).0;
    k *= pairing(hash_gid(gid), c_1).0;

    let eps_by_auth_iota = group_pairs(&eps_vec, |j| {
        let (auth, lbl, attr) = policy.get(j).0.auth_lbl_attr();
        (auth.clone(), iota.get(&auth, &lbl, &attr))
    });
    let eps_by_tau = group_pairs(&eps_vec, |j| {
        let (auth, lbl, attr) = policy.get(j).0.auth_lbl_attr();
        tau.get(&auth, &lbl, &attr)
    });
    let eps_by_tau_tilde = group_pairs(&eps_vec, |j| {
        let (auth, lbl, attr) = policy.get(j).0.auth_lbl_attr();
        tau.get_tilde(&auth, &lbl, &attr)
    });
    let eps_not_by_tau_tilde = group_pairs(&eps_not_vec, |j| {
        let (auth, lbl, attr) = policy.get(j).0.auth_lbl_attr();
        tau.get_tilde(&auth, &lbl, &attr)
    });
    let eps_not_by_auth_lbl_attr = group_pairs(&eps_not_vec, |j| policy.get(j).0.auth_lbl_attr());

    let mut domain_pos = HashSet::new();
    for k in eps_by_tau.keys() {
        domain_pos.insert(k);
    }
    for k in eps_by_tau_tilde.keys() {
        domain_pos.insert(k);
    }

    let cost_a_pos = eps_by_auth_iota.len() + eps_by_tau.len();
    let cost_b_pos = domain_pos.len();

    if cost_a_pos < cost_b_pos {
        for ((auth, iota), js) in eps_by_auth_iota.iter() {
            let k_1_1 = usk.get_partial_key(auth).unwrap().k_1_1_vec[*iota].neg();
            let mut c_4 = H::zero();
            for &j in js {
                let ua = policy.get(j).0;
                let auth = ua.authority();
                let lbl = ua.label();
                let attr = ua.attribute();
                let s_tilde = tau.get_tilde(auth, lbl, attr);
                c_4 += ct.c_4_vec[s_tilde];
            }
            k *= pairing(k_1_1, c_4).0;
        }

        for (j_under_tau, js) in eps_by_tau {
            let c_4 = ct.c_4_vec[j_under_tau];
            let mut k_1 = G::zero();
            for j in js {
                let (auth, lbl, attr) = policy.get(j).0.auth_lbl_attr();
                let usk = usk.get_partial_key(&auth).unwrap();
                k_1 += usk.k_1_2_map.get(&(lbl, attr)).unwrap().neg();
            }
            k *= pairing(k_1, c_4).0;
        }
    } else {
        for j_under_tau_or_tau_tilde in domain_pos {
            let c_4 = ct.c_4_vec[*j_under_tau_or_tau_tilde];

            let tmp = Vec::new();
            let js = eps_by_tau.get(j_under_tau_or_tau_tilde).unwrap_or(&tmp);
            let mut k_1_2 = G::zero();
            for j in js {
                let (auth, lbl, attr) = policy.get(*j).0.auth_lbl_attr();
                let usk = usk.get_partial_key(&auth).unwrap();
                k_1_2 += usk.k_1_2_map.get(&(lbl, attr)).unwrap().neg();
            }

            let js = eps_by_tau_tilde
                .get(j_under_tau_or_tau_tilde)
                .unwrap_or(&tmp);
            let mut k_1_1 = G::zero();
            for j in js {
                let (auth, lbl, attr) = policy.get(*j).0.auth_lbl_attr();
                let iota = iota.get(&auth, &lbl, &attr);
                k_1_1 += usk.get_partial_key(&auth).unwrap().k_1_1_vec[iota].neg();
            }
            k *= pairing(k_1_1 + k_1_2, c_4).0;
        }
    }

    for ((auth, iota), js) in eps_by_auth_iota {
        let mut c_2 = G::zero();
        for j in js {
            c_2 += ct.c_2_vec[j];
        }
        let usk = usk.get_partial_key(&auth).unwrap();
        let k_4 = usk.k_4_vec[iota];
        k *= pairing(c_2, k_4).0;
    }

    for (j_under_tau, js) in eps_not_by_tau_tilde {
        let c_4 = ct.c_4_vec[j_under_tau];

        let mut k_2 = G::zero();
        for j in js.iter() {
            let (auth, lbl) = policy.get(*j).0.auth_lbl();
            let usk = usk.get_partial_key(&auth).unwrap();
            k_2 += usk.k_2_map.get(&lbl).unwrap().neg();
        }

        let mut k_3 = G::zero();
        for j in js {
            let (auth, lbl, attr) = policy.get(j).0.auth_lbl_attr();
            let x_attr_not = hash_attr(&attr);
            let usk = usk.get_partial_key(&auth).unwrap();

            let attrs: Vec<String> = usk
                .k_1_2_map
                .keys()
                .filter_map(|k| {
                    if k.0.eq(&lbl) {
                        Some(k.1.clone())
                    } else {
                        None
                    }
                })
                .collect();

            let mut k_3_bases = Vec::with_capacity(attrs.len());
            let mut k_3_exps = Vec::with_capacity(attrs.len());
            let one = ScalarField::from(1);
            for attr in attrs {
                let x_attr = hash_attr(&attr);
                let e = -one / (x_attr_not - x_attr);
                k_3_exps.push(e);
                k_3_bases.push(
                    usk.k_3_map
                        .get(&(lbl.clone(), attr.clone()))
                        .unwrap()
                        .into_affine(),
                );
            }
            k_3 += G::msm(&k_3_bases, &k_3_exps).unwrap();
        }
        k *= pairing(k_2 + k_3, c_4).0;
    }

    for ((auth, lbl, attr), js) in eps_not_by_auth_lbl_attr {
        let mut c_2 = G::zero();
        for j in js {
            c_2 += ct.c_2_vec[j];
        }

        let x_attr_not = hash_attr(&attr);
        let usk = usk.get_partial_key(&auth).unwrap();

        let attrs: Vec<String> = usk
            .k_1_2_map
            .keys()
            .filter_map(|k| {
                if k.0.eq(&lbl) {
                    Some(k.1.clone())
                } else {
                    None
                }
            })
            .collect();
        let mut k_5_bases = Vec::with_capacity(attrs.len());
        let mut k_5_exps = Vec::with_capacity(attrs.len());
        let one = ScalarField::from(1);
        for attr in attrs {
            let x_attr = hash_attr(&attr);
            let e = one / (x_attr_not - x_attr);
            let iota = iota.get(&auth, &lbl, &attr);
            k_5_exps.push(e);
            k_5_bases.push(usk.k_5_vec[iota].into_affine());
        }
        let k_5 = H::msm(&k_5_bases, &k_5_exps).unwrap();
        k *= pairing(c_2, k_5).0;
    }

    Some(k)
}
