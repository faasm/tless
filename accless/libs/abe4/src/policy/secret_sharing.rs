use super::UserAttribute;
use crate::policy::{Expr, Policy};

pub fn share_secret(policy: &Policy) -> Vec<(UserAttribute, Vec<i64>)> {
    let mut n = 0;
    let mut result = Vec::new();
    helper(&mut n, &mut result, vec![0], &policy.expr);
    result
}

fn helper(
    n: &mut i64,
    result: &mut Vec<(UserAttribute, Vec<i64>)>,
    idcs: Vec<i64>,
    expr: &Expr<(bool, UserAttribute)>,
) {
    match expr {
        Expr::Lit((_, user_attr)) => result.push((user_attr.clone(), idcs)),
        Expr::Or(lhs, rhs) => {
            helper(n, result, idcs.clone(), lhs);
            helper(n, result, idcs, rhs)
        }
        Expr::And(lhs, rhs) => {
            let mut idcs_l = idcs.clone();
            *n += 1;
            idcs_l.push(*n);
            let idcs_r = vec![-*n];
            helper(n, result, idcs_l, lhs);
            helper(n, result, idcs_r, rhs)
        }
    }
}

fn satisfies(user_attrs: &Vec<UserAttribute>, curr: &UserAttribute, is_neg: bool) -> Option<usize> {
    let mut matches = 0;
    let mut others = 0;
    for user_attr in user_attrs {
        if user_attr.authority() == curr.authority() && user_attr.label() == curr.label() {
            if user_attr.attribute() == curr.attribute() {
                matches += 1;
            } else {
                others += 1;
            }
        }
    }

    if !is_neg && matches > 0 {
        Some(1)
    } else if is_neg && matches == 0 && others > 0 {
        Some(others)
    } else {
        None
    }
}

pub fn reconstruct_secret(user_attrs: &Vec<UserAttribute>, policy: &Policy) -> Option<Vec<usize>> {
    let mut idx = 0;
    let (_, idcs) = aux(&mut idx, user_attrs, &policy.expr)?;
    Some(idcs)
}

fn aux(
    idx: &mut usize,
    user_attrs: &Vec<UserAttribute>,
    expr: &Expr<(bool, UserAttribute)>,
) -> Option<(usize, Vec<usize>)> {
    match expr {
        Expr::Lit((is_neg, user_attr)) => match satisfies(user_attrs, user_attr, *is_neg) {
            None => {
                *idx += 1;
                None
            }
            Some(cost) => {
                let idcs = vec![*idx];
                *idx += 1;
                Some((cost, idcs))
            }
        },
        Expr::And(lhs, rhs) => {
            let l = aux(idx, user_attrs, lhs);
            let r = aux(idx, user_attrs, rhs);
            match (l, r) {
                (Some((cost_l, mut idcs_l)), Some((cost_r, mut idcs_r))) => {
                    idcs_l.append(&mut idcs_r);
                    Some((cost_l + cost_r, idcs_l))
                }
                (_, _) => None,
            }
        }
        Expr::Or(lhs, rhs) => {
            let l = aux(idx, user_attrs, lhs);
            let r = aux(idx, user_attrs, rhs);
            match (l, r) {
                (None, None) => None,
                (Some((cost_l, idcs_l)), None) => Some((cost_l, idcs_l)),
                (None, Some((cost_r, idcs_r))) => Some((cost_r, idcs_r)),
                (Some((cost_l, idcs_l)), Some((cost_r, idcs_r))) => {
                    if cost_l < cost_r {
                        Some((cost_l, idcs_l))
                    } else {
                        Some((cost_r, idcs_r))
                    }
                }
            }
        }
    }
}

#[test]
fn test_secret_reconstruction() {
    let user_1 = vec!["anda.z:z"]
        .iter()
        .map(|ua| UserAttribute::parse(ua).unwrap())
        .collect();
    let user_2 = vec!["x.b:a"]
        .iter()
        .map(|ua| UserAttribute::parse(ua).unwrap())
        .collect();
    let user_3 = vec!["x.b:a", "orr.y:u"]
        .iter()
        .map(|ua| UserAttribute::parse(ua).unwrap())
        .collect();
    let user_4 = vec!["x.b:a", "x.b:a2", "orr.y:u", "anda.z:z"]
        .iter()
        .map(|ua| UserAttribute::parse(ua).unwrap())
        .collect();
    let user_5 = vec!["x.b:a", "x.b:a2", "orr.y:u", "anda.z:z2"]
        .iter()
        .map(|ua| UserAttribute::parse(ua).unwrap())
        .collect();
    let user_6 = vec!["x.b:a", "x.b:a3", "orr.y:u", "anda.z:z"]
        .iter()
        .map(|ua| UserAttribute::parse(ua).unwrap())
        .collect();

    let policy = Policy::parse("x.b:a & !(x.b:a2 | !orr.y:u) | anda.z:z").unwrap();

    let eps_1 = reconstruct_secret(&user_1, &policy);
    let eps_2 = reconstruct_secret(&user_2, &policy);
    let eps_3 = reconstruct_secret(&user_3, &policy);
    let eps_4 = reconstruct_secret(&user_4, &policy);
    let eps_5 = reconstruct_secret(&user_5, &policy);
    let eps_6 = reconstruct_secret(&user_6, &policy);

    assert_eq!(eps_1, Some(vec![3]));
    assert_eq!(eps_2, None);
    assert_eq!(eps_3, Some(vec![0, 1, 2]));
    assert_eq!(eps_4, Some(vec![3]));
    assert_eq!(eps_5, None);
    assert_eq!(eps_6, Some(vec![3]));
}

#[test]
fn test_secret_sharing() {
    let policy = Policy::parse("x.b:a & !(!x.b:a2 | orr.y:u) | anda.z:z").unwrap();
    let sharing = share_secret(&policy);
    assert_eq!(sharing.len(), 4);
    assert_eq!(sharing[0].1, vec![0, 1]);
    assert_eq!(sharing[1].1, vec![-1, 2]);
    assert_eq!(sharing[2].1, vec![-2]);
    assert_eq!(sharing[3].1, vec![0]);
}
