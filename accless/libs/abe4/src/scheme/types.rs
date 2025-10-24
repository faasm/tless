use crate::{
    curve::{G, H, ScalarField},
    policy::UserAttribute,
};
use std::collections::HashMap;

// -----------------------------------------------------------------------------------------------
// Structure and Trait Definitions
// -----------------------------------------------------------------------------------------------

/// Structure representing a cipher-text.
pub struct Ciphertext {
    pub c_1_vec: Vec<H>,
    pub c_2_vec: Vec<G>,
    pub c_3_vec: Vec<H>,
    pub c_4_vec: Vec<H>,
}

/// Trait shared by all partial key structures.
pub trait PartialKey {
    /// Returns the authority that generated this key.
    fn get_authority(&self) -> String;
}

/// Struct representing a partial Master Secret Key (MSK).
pub struct PartialMSK {
    pub auth: String,
    pub beta: ScalarField,
    pub b: ScalarField,
    pub b_not: ScalarField,
    pub b_prime: ScalarField,
}

/// Struct representing a partial Master Public Key (MPK).
pub struct PartialMPK {
    pub auth: String,
    pub a: H,
    pub b: H,
    pub b_not: H,
    pub b_prime: G,
}

pub struct PartialUSK {
    pub auth: String,
    pub k_1_1_vec: Vec<G>,
    pub k_1_2_map: HashMap<(String, String), G>,
    pub k_2_map: HashMap<String, G>,
    pub k_3_map: HashMap<(String, String), G>,
    pub k_4_vec: Vec<H>,
    pub k_5_vec: Vec<H>,
}

/// Struct representing a full key given a set of partial keys.
pub struct FullKey<T> {
    pub partial_keys: HashMap<String, T>,
}

/// Global identifier for different authorities.
pub type GID = String;
/// Master Public Key.
pub type MPK = FullKey<PartialMPK>;
/// Master Secret Key.
pub type MSK = FullKey<PartialMSK>;
/// User Secret Key.
pub type USK = FullKey<PartialUSK>;

// -----------------------------------------------------------------------------------------------
// Implementations
// -----------------------------------------------------------------------------------------------

impl PartialKey for PartialMSK {
    fn get_authority(&self) -> String {
        self.auth.clone()
    }
}

impl PartialKey for PartialMPK {
    fn get_authority(&self) -> String {
        self.auth.clone()
    }
}

impl PartialKey for PartialUSK {
    fn get_authority(&self) -> String {
        self.auth.clone()
    }
}

impl<T: PartialKey> FullKey<T> {
    pub fn new() -> Self {
        FullKey {
            partial_keys: HashMap::new(),
        }
    }

    pub fn add_partial_key(&mut self, new_key: T) {
        if self.partial_keys.contains_key(&new_key.get_authority()) {
            panic!(
                "Partial key for authority '{}' already exists",
                new_key.get_authority()
            );
        } else {
            self.partial_keys.insert(new_key.get_authority(), new_key);
        }
    }

    pub fn get_partial_key(&self, auth: &str) -> Option<&T> {
        self.partial_keys.get(auth)
    }
}

impl FullKey<PartialUSK> {
    pub fn get_user_attributes(&self) -> Vec<UserAttribute> {
        let mut user_attrs = Vec::new();
        for (auth, usk) in self.partial_keys.iter() {
            for (lbl, attr) in usk.k_1_2_map.keys() {
                user_attrs.push(UserAttribute::new(auth, lbl, attr));
            }
        }

        user_attrs
    }
}
