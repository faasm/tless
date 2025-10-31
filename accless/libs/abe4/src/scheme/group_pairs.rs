use std::{collections::HashMap, hash::Hash};

pub fn group_pairs<T: Eq + Hash>(
    js: &Vec<usize>,
    f: impl Fn(usize) -> T,
) -> HashMap<T, Vec<usize>> {
    let mut map: HashMap<T, Vec<usize>> = HashMap::new();
    for &j in js {
        let key = f(j);
        map.entry(key).or_default().push(j);
    }
    map
}
