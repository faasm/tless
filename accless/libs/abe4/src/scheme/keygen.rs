use crate::{
    curve::{G, H, ScalarField},
    hashing::{
        HashSign::{Neg, Pos},
        hash_attr, hash_gid, hash_lbl,
    },
    policy::UserAttribute,
    scheme::{
        iota::Iota,
        types::{MSK, PartialMSK, PartialUSK, USK},
    },
};
use ark_ec::{Group, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_std::{ops::Mul, rand::Rng};
use std::collections::{HashMap, HashSet};

pub fn keygen(
    mut rng: impl Rng,
    gid: &str,
    msk: &MSK,
    user_attrs: &[UserAttribute],
    iota: &Iota,
) -> USK {
    // Group the given array of `UserAttribute`s by authority.
    let mut user_attr_by_auth: HashMap<&str, Vec<&UserAttribute>> = HashMap::new();
    for ua in user_attrs {
        user_attr_by_auth
            .entry(ua.authority())
            .or_default()
            .push(ua);
    }

    // Run partial key generation for each authority.
    let mut usk = USK::new();
    for (auth, uas) in user_attr_by_auth {
        match msk.get_partial_key(auth) {
            None => panic!("No partial MSK given for authority in user's attribute set"),
            Some(partial_msk) => {
                let partial_usk = keygen_partial(&mut rng, gid, partial_msk, &uas, iota);
                usk.add_partial_key(partial_usk);
            }
        }
    }
    usk
}

pub fn keygen_partial(
    mut rng: impl Rng,
    gid: &str,
    msk: &PartialMSK,
    user_attrs: &[&UserAttribute],
    iota: &Iota,
) -> PartialUSK {
    let zero = ScalarField::from(0);
    let mut r_vec = Vec::new();
    let mut r_not_vec = Vec::new();
    let mut r_lab_map = HashMap::new();
    let mut r_lab_done = HashSet::new();

    for _ in 0..=iota.get_max() {
        r_vec.push(ScalarField::rand(&mut rng));
        r_not_vec.push(ScalarField::rand(&mut rng));
    }

    for user_attr in user_attrs.iter() {
        if user_attr.authority() != msk.auth {
            panic!(
                "Fatal error: cannot generate key for attribute which is managed by a different authority"
            );
        }
        if !r_lab_done.contains(&(user_attr.label(), user_attr.attribute())) {
            let iota = iota.get(
                user_attr.authority(),
                user_attr.label(),
                user_attr.attribute(),
            );
            let r_not = r_not_vec[iota];
            let r_lab = *r_lab_map.get(&user_attr.label()).unwrap_or(&zero) + r_not;
            r_lab_map.insert(user_attr.label(), r_lab);
            r_lab_done.insert((user_attr.label(), user_attr.attribute()));
        }
    }
    let g = G::generator().mul(msk.beta);
    let gid_hashed = hash_gid(gid);
    let gid = gid_hashed.mul(msk.b);
    let gid_not = gid_hashed.mul(msk.b_not);
    let mut k_1_1_vec = Vec::new();
    for r_val in r_vec.iter().take(iota.get_max() + 1) {
        let k_1 = g + gid + G::generator().mul(*r_val * msk.b_prime);
        k_1_1_vec.push(k_1);
    }
    let mut k_1_2_map = HashMap::new();
    let mut k_3_map = HashMap::new();
    let mut lbl_pos_0 = HashMap::new();
    let mut lbl_pos_1 = HashMap::new();
    let mut lbl_neg_0 = HashMap::new();
    let mut lbl_neg_1 = HashMap::new();
    for user_attr in user_attrs.iter() {
        let key = (msk.auth.clone(), user_attr.label());
        if !lbl_pos_0.contains_key(&key) {
            lbl_pos_0.insert(key.clone(), hash_lbl(&msk.auth, user_attr.label(), Pos, 0));
            lbl_pos_1.insert(key.clone(), hash_lbl(&msk.auth, user_attr.label(), Pos, 1));
            lbl_neg_0.insert(key.clone(), hash_lbl(&msk.auth, user_attr.label(), Neg, 0));
            lbl_neg_1.insert(key, hash_lbl(&msk.auth, user_attr.label(), Neg, 1));
        }
    }
    for user_attr in user_attrs.iter() {
        let key = (msk.auth.clone(), user_attr.label());
        let lbl_pos_0 = *lbl_pos_0.get(&key).unwrap();
        let lbl_pos_1 = *lbl_pos_1.get(&key).unwrap();
        let lbl_neg_0 = *lbl_neg_0.get(&key).unwrap();
        let lbl_neg_1 = *lbl_neg_1.get(&key).unwrap();
        let x_attr = hash_attr(user_attr.attribute());
        let iota = iota.get(
            user_attr.authority(),
            user_attr.label(),
            user_attr.attribute(),
        );
        let r = r_vec[iota];
        let r_not = r_not_vec[iota];
        let k_1 = G::msm(&[lbl_pos_0, lbl_pos_1], &[r, r * x_attr]).unwrap();
        k_1_2_map.insert(
            (
                user_attr.label().to_string(),
                user_attr.attribute().to_string(),
            ),
            k_1,
        );
        let k_3 = G::msm(&[lbl_neg_0, lbl_neg_1], &[r_not, r_not * x_attr]).unwrap();
        k_3_map.insert(
            (
                user_attr.label().to_string(),
                user_attr.attribute().to_string(),
            ),
            k_3,
        );
    }
    let mut k_2_map = HashMap::new();
    for user_attr in user_attrs.iter() {
        if !k_2_map.contains_key(user_attr.label()) {
            let r_lab = r_lab_map.get(user_attr.label()).unwrap();
            let key = (msk.auth.clone(), user_attr.label());
            let k_2 = (*lbl_neg_1.get(&key).unwrap()).mul(r_lab);
            k_2_map.insert(user_attr.label().to_string(), g + gid_not + k_2);
        }
    }
    let mut k_4_vec = Vec::with_capacity(r_vec.len());
    let mut k_5_vec = Vec::with_capacity(r_vec.len());
    for iota in 0..r_vec.len() {
        let r = r_vec[iota];
        let r_not = r_not_vec[iota];
        k_4_vec.push(H::generator().mul(r));
        k_5_vec.push(H::generator().mul(r_not));
    }

    PartialUSK {
        auth: msk.auth.clone(),
        k_1_1_vec,
        k_1_2_map,
        k_2_map,
        k_3_map,
        k_4_vec,
        k_5_vec,
    }
}
