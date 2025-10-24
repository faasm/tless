use std::{collections::HashMap, hash::Hash};

pub fn group_pairs<T: Eq + Hash>(
    js: &Vec<usize>,
    f: impl Fn(usize) -> T,
) -> HashMap<T, Vec<usize>> {
    let mut map: HashMap<T, Vec<usize>> = HashMap::new();
    for &j in js {
        let key = f(j);
        if map.contains_key(&key) {
            let tmp = map.get_mut(&key).unwrap();
            tmp.push(j);
        } else {
            map.insert(key, vec![j]);
        }
    }
    map
}
