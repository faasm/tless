use crate::policy::Policy;
#[cfg(test)]
use crate::policy::UserAttribute;
use std::collections::HashMap;

pub struct Tau {
    storage_tilde: HashMap<(String, String, String), usize>,
    m_tilde: usize,
    storage: HashMap<(String, String, String), usize>,
    m: usize,
}

impl Tau {
    pub fn new(policy: &Policy) -> Self {
        let n = policy.len();
        let mut user_attr_by_auth = HashMap::new();
        let mut user_attrs_by_auth_lbl = HashMap::new();
        for i in 0..n {
            let (ua, _) = policy.get(i);
            let uas = user_attr_by_auth
                .entry(String::from(&ua.auth))
                .or_insert(Vec::new());
            uas.push(ua.clone());
            let key = (ua.auth.clone(), ua.lbl.clone());
            let uas = user_attrs_by_auth_lbl.entry(key).or_insert(Vec::new());
            uas.push(ua);
        }

        let mut storage_tilde = HashMap::new();
        let mut m_tilde = 0;
        for (_, uas) in user_attr_by_auth {
            let mut i = 0;
            for ua in uas {
                let key = (ua.auth, ua.lbl, ua.attr);
                storage_tilde.insert(key, i);
                m_tilde = std::cmp::max(m_tilde, i);
                i += 1;
            }
        }

        let mut storage = HashMap::new();
        let mut m = 0;
        for ((_, _), uas) in user_attrs_by_auth_lbl {
            let mut i = 0;
            for ua in uas {
                let key = (ua.auth, ua.lbl, ua.attr);
                storage.insert(key, i);
                m = std::cmp::max(m, i);
                i += 1;
            }
        }

        Tau {
            storage_tilde,
            m_tilde,
            storage,
            m,
        }
    }

    pub fn get_tilde_max(&self) -> usize {
        self.m_tilde
    }

    pub fn get_tilde(&self, auth: &str, lbl: &str, attr: &str) -> usize {
        let key = (String::from(auth), String::from(lbl), String::from(attr));
        *self.storage_tilde.get(&key).unwrap()
    }

    pub fn get_max(&self) -> usize {
        self.m
    }

    pub fn get(&self, auth: &str, lbl: &str, attr: &str) -> usize {
        let key = (String::from(auth), String::from(lbl), String::from(attr));
        *self.storage.get(&key).unwrap()
    }
}

#[test]
fn test_tau_simple() {
    let user_attrs = vec![
        UserAttribute::new("0", "0", "0"),
        UserAttribute::new("0", "0", "1"),
        UserAttribute::new("0", "0", "2"),
        UserAttribute::new("0", "0", "3"),
        UserAttribute::new("1", "0", "0"),
        UserAttribute::new("2", "0", "0"),
    ];
    let policy = Policy::conjunction_of(&user_attrs, 0);
    let tau = Tau::new(&policy);
    assert_eq!(tau.m, 3);
    assert_eq!(tau.get("0", "0", "0"), 0);
    assert_eq!(tau.get("0", "0", "1"), 1);
    assert_eq!(tau.get("0", "0", "2"), 2);
    assert_eq!(tau.get("0", "0", "3"), 3);
    assert_eq!(tau.get("1", "0", "0"), 0);
    assert_eq!(tau.get("2", "0", "0"), 0);
}

#[test]
fn test_tau_complex() {
    let user_attrs = vec![
        UserAttribute::new("0", "0", "0"),
        UserAttribute::new("0", "0", "1"),
        UserAttribute::new("0", "1", "2"),
        UserAttribute::new("0", "1", "3"),
        UserAttribute::new("0", "1", "4"),
        UserAttribute::new("1", "0", "5"),
        UserAttribute::new("1", "1", "6"),
        UserAttribute::new("1", "2", "7"),
        UserAttribute::new("1", "3", "8"),
        UserAttribute::new("1", "3", "9"),
    ];
    let policy = Policy::conjunction_of(&user_attrs, 0);
    let tau = Tau::new(&policy);
    assert_eq!(tau.m, 2);
    assert_eq!(tau.get("0", "0", "0"), 0);
    assert_eq!(tau.get("0", "0", "1"), 1);
    assert_eq!(tau.get("0", "1", "2"), 0);
    assert_eq!(tau.get("0", "1", "3"), 1);
    assert_eq!(tau.get("0", "1", "4"), 2);
    assert_eq!(tau.get("1", "0", "5"), 0);
    assert_eq!(tau.get("1", "1", "6"), 0);
    assert_eq!(tau.get("1", "2", "7"), 0);
    assert_eq!(tau.get("1", "3", "8"), 0);
    assert_eq!(tau.get("1", "3", "9"), 1);
}

#[test]
fn test_tau_tilde_simple() {
    let user_attrs = vec![
        UserAttribute::new("0", "0", "0"),
        UserAttribute::new("0", "1", "1"),
        UserAttribute::new("0", "2", "2"),
        UserAttribute::new("0", "3", "3"),
        UserAttribute::new("0", "4", "4"),
        UserAttribute::new("1", "5", "5"),
        UserAttribute::new("1", "6", "6"),
        UserAttribute::new("1", "7", "7"),
        UserAttribute::new("1", "8", "8"),
        UserAttribute::new("1", "9", "9"),
    ];
    let policy = Policy::conjunction_of(&user_attrs, 0);
    let tau = Tau::new(&policy);
    assert_eq!(tau.m_tilde, 4);
    assert_eq!(tau.get_tilde("0", "0", "0"), 0);
    assert_eq!(tau.get_tilde("0", "1", "1"), 1);
    assert_eq!(tau.get_tilde("0", "2", "2"), 2);
    assert_eq!(tau.get_tilde("0", "3", "3"), 3);
    assert_eq!(tau.get_tilde("0", "4", "4"), 4);
    assert_eq!(tau.get_tilde("1", "5", "5"), 0);
    assert_eq!(tau.get_tilde("1", "6", "6"), 1);
    assert_eq!(tau.get_tilde("1", "7", "7"), 2);
    assert_eq!(tau.get_tilde("1", "8", "8"), 3);
    assert_eq!(tau.get_tilde("1", "9", "9"), 4);
}

#[test]
fn test_tau_tilde_complex() {
    let user_attrs = vec![
        UserAttribute::new("0", "0", "0"),
        UserAttribute::new("0", "0", "1"),
        UserAttribute::new("0", "0", "2"),
        UserAttribute::new("0", "1", "3"),
        UserAttribute::new("1", "1", "0"),
        UserAttribute::new("1", "2", "1"),
        UserAttribute::new("1", "2", "2"),
        UserAttribute::new("1", "2", "3"),
        UserAttribute::new("1", "2", "4"),
        UserAttribute::new("2", "1", "0"),
        UserAttribute::new("2", "2", "1"),
        UserAttribute::new("3", "1", "1"),
        UserAttribute::new("3", "1", "2"),
        UserAttribute::new("3", "2", "1"),
    ];
    let policy = Policy::conjunction_of(&user_attrs, 0);
    let tau = Tau::new(&policy);
    assert_eq!(tau.m_tilde, 4);
    assert_eq!(tau.get_tilde("0", "0", "0"), 0);
    assert_eq!(tau.get_tilde("0", "0", "1"), 1);
    assert_eq!(tau.get_tilde("0", "0", "2"), 2);
    assert_eq!(tau.get_tilde("0", "1", "3"), 3);
    assert_eq!(tau.get_tilde("1", "1", "0"), 0);
    assert_eq!(tau.get_tilde("1", "2", "1"), 1);
    assert_eq!(tau.get_tilde("1", "2", "2"), 2);
    assert_eq!(tau.get_tilde("1", "2", "3"), 3);
    assert_eq!(tau.get_tilde("1", "2", "4"), 4);
    assert_eq!(tau.get_tilde("2", "1", "0"), 0);
    assert_eq!(tau.get_tilde("2", "2", "1"), 1);
    assert_eq!(tau.get_tilde("3", "1", "1"), 0);
    assert_eq!(tau.get_tilde("3", "1", "2"), 1);
    assert_eq!(tau.get_tilde("3", "2", "1"), 2);
}
