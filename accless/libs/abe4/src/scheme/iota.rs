use crate::policy::UserAttribute;
use std::collections::HashMap;

pub struct Iota {
    storage: HashMap<String, HashMap<(String, String), usize>>,
    m: usize,
}

impl Iota {
    pub fn new(user_attrs: &Vec<UserAttribute>) -> Self {
        let mut user_attr_by_auth = HashMap::new();
        for ua in user_attrs.clone() {
            let uas = user_attr_by_auth
                .entry(String::from(&ua.auth))
                .or_insert(Vec::new());
            uas.push(ua);
        }

        let mut storage = HashMap::new();

        let mut m = 0;
        for (auth, uas) in user_attr_by_auth {
            let mut attrs_by_lbl = HashMap::new();
            for ua in uas {
                let attrs = attrs_by_lbl.entry(ua.lbl).or_insert(Vec::new());
                attrs.push(ua.attr);
            }
            let mut inner = HashMap::new();
            for (lbl, attrs) in attrs_by_lbl {
                let mut i = 0;
                for a in attrs {
                    let key = (lbl.clone(), a);
                    inner.insert(key, i);
                    m = std::cmp::max(m, i);
                    i += 1;
                }
            }
            storage.insert(auth, inner);
        }
        Iota { storage, m }
    }

    pub fn get_max(&self) -> usize {
        self.m
    }

    pub fn get(&self, auth: &str, lbl: &str, attr: &str) -> usize {
        let key = (String::from(lbl), String::from(attr));
        *self.storage.get(auth).unwrap().get(&key).unwrap()
    }
}

#[test]
fn test_iota_simple() {
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
    let iota = Iota::new(&user_attrs);
    assert_eq!(iota.m, 0);
    assert_eq!(iota.get("0", "0", "0"), 0);
    assert_eq!(iota.get("0", "1", "1"), 0);
    assert_eq!(iota.get("0", "2", "2"), 0);
    assert_eq!(iota.get("0", "3", "3"), 0);
    assert_eq!(iota.get("0", "4", "4"), 0);
    assert_eq!(iota.get("1", "5", "5"), 0);
    assert_eq!(iota.get("1", "6", "6"), 0);
    assert_eq!(iota.get("1", "7", "7"), 0);
    assert_eq!(iota.get("1", "8", "8"), 0);
    assert_eq!(iota.get("1", "9", "9"), 0);
}

#[test]
fn test_iota_complex() {
    let user_attrs = vec![
        UserAttribute::new("0", "0", "0"),
        UserAttribute::new("0", "0", "1"),
        UserAttribute::new("0", "0", "2"),
        UserAttribute::new("0", "1", "3"),
        UserAttribute::new("0", "1", "4"),
        UserAttribute::new("1", "1", "0"),
        UserAttribute::new("1", "2", "1"),
        UserAttribute::new("1", "2", "2"),
        UserAttribute::new("1", "2", "3"),
        UserAttribute::new("1", "2", "4"),
    ];
    let iota = Iota::new(&user_attrs);
    assert_eq!(iota.m, 3);
    assert_eq!(iota.get("0", "0", "0"), 0);
    assert_eq!(iota.get("0", "0", "1"), 1);
    assert_eq!(iota.get("0", "0", "2"), 2);
    assert_eq!(iota.get("0", "1", "3"), 0);
    assert_eq!(iota.get("0", "1", "4"), 1);
    assert_eq!(iota.get("1", "1", "0"), 0);
    assert_eq!(iota.get("1", "2", "1"), 0);
    assert_eq!(iota.get("1", "2", "2"), 1);
    assert_eq!(iota.get("1", "2", "3"), 2);
    assert_eq!(iota.get("1", "2", "4"), 3);
}
