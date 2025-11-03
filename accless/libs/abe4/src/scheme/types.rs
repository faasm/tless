use crate::{
    curve::{G, H, ScalarField},
    policy::UserAttribute,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, Valid, Write};
use std::collections::{HashMap, hash_map::Entry};

// -----------------------------------------------------------------------------------------------
// Structure and Trait Definitions
// -----------------------------------------------------------------------------------------------

/// Structure representing a cipher-text.
#[derive(PartialEq, Debug)]
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

/// # Description
///
/// Struct representing a partial Master Secret Key (MSK).
///
/// This key belongs to one authority in decentralized CP-ABE. The authority is
/// identified by the `auth` string, a unique identifier. This secret key is
/// given to the authority during the setup phase.
#[derive(PartialEq, Debug)]
pub struct PartialMSK {
    pub auth: String,
    pub beta: ScalarField,
    pub b: ScalarField,
    pub b_not: ScalarField,
    pub b_prime: ScalarField,
}

/// # Description
///
/// Struct representing a partial Master Public Key (MPK).
///
/// This key belongs to one authority in decentralized CP-ABE. The authority is
/// identified by the `auth` string, a unique identifier. This public key is
/// meant to be publicly available, together with the `auth` String, so that
/// users can encrypt policies with attributes from this authority.
#[derive(Debug, PartialEq)]
pub struct PartialMPK {
    pub auth: String,
    pub a: H,
    pub b: H,
    pub b_not: H,
    pub b_prime: G,
}

/// # Description
///
/// Struct representing a partial User Secret Key (UPK).
///
/// A user secret key is the key generated for this user's attributes from
/// authority `auth`. It is called "partial", because it should be combined with
/// other keys from all other necessary authoritties that can potentially be
/// involved in decryption.
#[derive(PartialEq, Debug)]
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
#[derive(Debug, PartialEq)]
pub struct FullKey<T> {
    pub partial_keys: HashMap<String, T>,
}

/// Master Public Key.
#[allow(clippy::upper_case_acronyms)]
pub type MPK = FullKey<PartialMPK>;
/// Master Secret Key.
#[allow(clippy::upper_case_acronyms)]
pub type MSK = FullKey<PartialMSK>;
/// User Secret Key.
#[allow(clippy::upper_case_acronyms)]
pub type USK = FullKey<PartialUSK>;

// -----------------------------------------------------------------------------------------------
// Serialization Helpers
//
// See: https://docs.rs/ark-serialize/latest/ark_serialize/
// -----------------------------------------------------------------------------------------------

impl CanonicalSerialize for PartialMPK {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        mode: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        (self.auth.len() as u64).serialize_with_mode(&mut writer, mode)?;
        writer.write_all(self.auth.as_bytes())?;
        self.a.serialize_with_mode(&mut writer, mode)?;
        self.b.serialize_with_mode(&mut writer, mode)?;
        self.b_not.serialize_with_mode(&mut writer, mode)?;
        self.b_prime.serialize_with_mode(&mut writer, mode)?;
        Ok(())
    }

    fn serialized_size(&self, mode: ark_serialize::Compress) -> usize {
        (self.auth.len() as u64).serialized_size(mode)
            + self.auth.len()
            + self.a.serialized_size(mode)
            + self.b.serialized_size(mode)
            + self.b_not.serialized_size(mode)
            + self.b_prime.serialized_size(mode)
    }
}

impl CanonicalDeserialize for PartialMPK {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let len = u64::deserialize_with_mode(&mut reader, compress, validate)?;
        let mut bytes = vec![0; len as usize];
        reader.read_exact(&mut bytes)?;
        let auth =
            String::from_utf8(bytes).map_err(|_| ark_serialize::SerializationError::InvalidData)?;
        Ok(Self {
            auth,
            a: H::deserialize_with_mode(&mut reader, compress, validate)?,
            b: H::deserialize_with_mode(&mut reader, compress, validate)?,
            b_not: H::deserialize_with_mode(&mut reader, compress, validate)?,
            b_prime: G::deserialize_with_mode(&mut reader, compress, validate)?,
        })
    }
}

impl Valid for PartialMPK {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.a.check()?;
        self.b.check()?;
        self.b_not.check()?;
        self.b_prime.check()?;
        Ok(())
    }
}

impl CanonicalSerialize for PartialMSK {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        mode: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        (self.auth.len() as u64).serialize_with_mode(&mut writer, mode)?;
        writer.write_all(self.auth.as_bytes())?;
        self.beta.serialize_with_mode(&mut writer, mode)?;
        self.b.serialize_with_mode(&mut writer, mode)?;
        self.b_not.serialize_with_mode(&mut writer, mode)?;
        self.b_prime.serialize_with_mode(&mut writer, mode)?;
        Ok(())
    }

    fn serialized_size(&self, mode: ark_serialize::Compress) -> usize {
        (self.auth.len() as u64).serialized_size(mode)
            + self.auth.len()
            + self.beta.serialized_size(mode)
            + self.b.serialized_size(mode)
            + self.b_not.serialized_size(mode)
            + self.b_prime.serialized_size(mode)
    }
}

impl CanonicalDeserialize for PartialMSK {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let len = u64::deserialize_with_mode(&mut reader, compress, validate)?;
        let mut bytes = vec![0; len as usize];
        reader.read_exact(&mut bytes)?;
        let auth =
            String::from_utf8(bytes).map_err(|_| ark_serialize::SerializationError::InvalidData)?;
        Ok(Self {
            auth,
            beta: ScalarField::deserialize_with_mode(&mut reader, compress, validate)?,
            b: ScalarField::deserialize_with_mode(&mut reader, compress, validate)?,
            b_not: ScalarField::deserialize_with_mode(&mut reader, compress, validate)?,
            b_prime: ScalarField::deserialize_with_mode(&mut reader, compress, validate)?,
        })
    }
}

impl Valid for PartialMSK {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.beta.check()?;
        self.b.check()?;
        self.b_not.check()?;
        self.b_prime.check()?;
        Ok(())
    }
}

impl CanonicalSerialize for PartialUSK {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        mode: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        (self.auth.len() as u64).serialize_with_mode(&mut writer, mode)?;
        writer.write_all(self.auth.as_bytes())?;
        self.k_1_1_vec.serialize_with_mode(&mut writer, mode)?;

        // k_1_2_map
        (self.k_1_2_map.len() as u64).serialize_with_mode(&mut writer, mode)?;
        for (k, v) in &self.k_1_2_map {
            k.serialize_with_mode(&mut writer, mode)?;
            v.serialize_with_mode(&mut writer, mode)?;
        }

        // k_2_map
        (self.k_2_map.len() as u64).serialize_with_mode(&mut writer, mode)?;
        for (k, v) in &self.k_2_map {
            k.serialize_with_mode(&mut writer, mode)?;
            v.serialize_with_mode(&mut writer, mode)?;
        }

        // k_3_map
        (self.k_3_map.len() as u64).serialize_with_mode(&mut writer, mode)?;
        for (k, v) in &self.k_3_map {
            k.serialize_with_mode(&mut writer, mode)?;
            v.serialize_with_mode(&mut writer, mode)?;
        }

        self.k_4_vec.serialize_with_mode(&mut writer, mode)?;
        self.k_5_vec.serialize_with_mode(&mut writer, mode)?;
        Ok(())
    }

    fn serialized_size(&self, mode: ark_serialize::Compress) -> usize {
        let mut size = (self.auth.len() as u64).serialized_size(mode) + self.auth.len();
        size += self.k_1_1_vec.serialized_size(mode);

        // k_1_2_map
        size += (self.k_1_2_map.len() as u64).serialized_size(mode);
        for (k, v) in &self.k_1_2_map {
            size += k.serialized_size(mode);
            size += v.serialized_size(mode);
        }

        // k_2_map
        size += (self.k_2_map.len() as u64).serialized_size(mode);
        for (k, v) in &self.k_2_map {
            size += k.serialized_size(mode);
            size += v.serialized_size(mode);
        }

        // k_3_map
        size += (self.k_3_map.len() as u64).serialized_size(mode);
        for (k, v) in &self.k_3_map {
            size += k.serialized_size(mode);
            size += v.serialized_size(mode);
        }

        size += self.k_4_vec.serialized_size(mode);
        size += self.k_5_vec.serialized_size(mode);
        size
    }
}

impl CanonicalDeserialize for PartialUSK {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let auth_len = u64::deserialize_with_mode(&mut reader, compress, validate)?;
        let mut auth_bytes = vec![0; auth_len as usize];
        reader.read_exact(&mut auth_bytes)?;
        let auth = String::from_utf8(auth_bytes)
            .map_err(|_| ark_serialize::SerializationError::InvalidData)?;

        let k_1_1_vec = Vec::<G>::deserialize_with_mode(&mut reader, compress, validate)?;

        // k_1_2_map
        let k_1_2_map_len = u64::deserialize_with_mode(&mut reader, compress, validate)?;
        let mut k_1_2_map = HashMap::with_capacity(k_1_2_map_len as usize);
        for _ in 0..k_1_2_map_len {
            let key = <(String, String)>::deserialize_with_mode(&mut reader, compress, validate)?;
            let value = G::deserialize_with_mode(&mut reader, compress, validate)?;
            k_1_2_map.insert(key, value);
        }

        // k_2_map
        let k_2_map_len = u64::deserialize_with_mode(&mut reader, compress, validate)?;
        let mut k_2_map = HashMap::with_capacity(k_2_map_len as usize);
        for _ in 0..k_2_map_len {
            let key = String::deserialize_with_mode(&mut reader, compress, validate)?;
            let value = G::deserialize_with_mode(&mut reader, compress, validate)?;
            k_2_map.insert(key, value);
        }

        // k_3_map
        let k_3_map_len = u64::deserialize_with_mode(&mut reader, compress, validate)?;
        let mut k_3_map = HashMap::with_capacity(k_3_map_len as usize);
        for _ in 0..k_3_map_len {
            let key = <(String, String)>::deserialize_with_mode(&mut reader, compress, validate)?;
            let value = G::deserialize_with_mode(&mut reader, compress, validate)?;
            k_3_map.insert(key, value);
        }

        let k_4_vec = Vec::<H>::deserialize_with_mode(&mut reader, compress, validate)?;
        let k_5_vec = Vec::<H>::deserialize_with_mode(&mut reader, compress, validate)?;

        Ok(Self {
            auth,
            k_1_1_vec,
            k_1_2_map,
            k_2_map,
            k_3_map,
            k_4_vec,
            k_5_vec,
        })
    }
}

impl Valid for PartialUSK {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.k_1_1_vec.check()?;
        for (k, v) in &self.k_1_2_map {
            k.check()?;
            v.check()?;
        }
        for (k, v) in &self.k_2_map {
            k.check()?;
            v.check()?;
        }
        for (k, v) in &self.k_3_map {
            k.check()?;
            v.check()?;
        }
        self.k_4_vec.check()?;
        self.k_5_vec.check()?;
        Ok(())
    }
}

// -----------------------------------------------------------------------------------------------
// Serialization Of Ciphertexts
// -----------------------------------------------------------------------------------------------

impl CanonicalSerialize for Ciphertext {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        mode: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.c_1_vec.serialize_with_mode(&mut writer, mode)?;
        self.c_2_vec.serialize_with_mode(&mut writer, mode)?;
        self.c_3_vec.serialize_with_mode(&mut writer, mode)?;
        self.c_4_vec.serialize_with_mode(&mut writer, mode)?;
        Ok(())
    }

    fn serialized_size(&self, mode: ark_serialize::Compress) -> usize {
        self.c_1_vec.serialized_size(mode)
            + self.c_2_vec.serialized_size(mode)
            + self.c_3_vec.serialized_size(mode)
            + self.c_4_vec.serialized_size(mode)
    }
}

impl CanonicalDeserialize for Ciphertext {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        Ok(Self {
            c_1_vec: Vec::<H>::deserialize_with_mode(&mut reader, compress, validate)?,
            c_2_vec: Vec::<G>::deserialize_with_mode(&mut reader, compress, validate)?,
            c_3_vec: Vec::<H>::deserialize_with_mode(&mut reader, compress, validate)?,
            c_4_vec: Vec::<H>::deserialize_with_mode(&mut reader, compress, validate)?,
        })
    }
}

impl Valid for Ciphertext {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.c_1_vec.check()?;
        self.c_2_vec.check()?;
        self.c_3_vec.check()?;
        self.c_4_vec.check()?;
        Ok(())
    }
}

// -----------------------------------------------------------------------------------------------
// Serialization Of Full Keys
// -----------------------------------------------------------------------------------------------

impl<T: CanonicalSerialize + PartialKey> CanonicalSerialize for FullKey<T> {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        mode: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        (self.partial_keys.len() as u64).serialize_with_mode(&mut writer, mode)?;
        for (auth, partial_key) in &self.partial_keys {
            // Serialize authority string
            (auth.len() as u64).serialize_with_mode(&mut writer, mode)?;
            writer.write_all(auth.as_bytes())?;

            // Serialize partial key with its size
            let mut key_bytes = Vec::new();
            partial_key.serialize_with_mode(&mut key_bytes, mode)?;
            (key_bytes.len() as u64).serialize_with_mode(&mut writer, mode)?;
            writer.write_all(&key_bytes)?;
        }
        Ok(())
    }

    fn serialized_size(&self, mode: ark_serialize::Compress) -> usize {
        let mut size = (self.partial_keys.len() as u64).serialized_size(mode);
        for (auth, partial_key) in &self.partial_keys {
            size += (auth.len() as u64).serialized_size(mode);
            size += auth.len();
            let key_size = partial_key.serialized_size(mode);
            size += (key_size as u64).serialized_size(mode);
            size += key_size;
        }
        size
    }
}

impl<T: CanonicalDeserialize + PartialKey> CanonicalDeserialize for FullKey<T> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let num_keys = u64::deserialize_with_mode(&mut reader, compress, validate)?;
        let mut partial_keys = HashMap::new();
        for _ in 0..num_keys {
            // Deserialize authority string
            let auth_len = u64::deserialize_with_mode(&mut reader, compress, validate)?;
            let mut auth_bytes = vec![0; auth_len as usize];
            reader.read_exact(&mut auth_bytes)?;
            let auth = String::from_utf8(auth_bytes)
                .map_err(|_| ark_serialize::SerializationError::InvalidData)?;

            // Deserialize partial key
            let key_len = u64::deserialize_with_mode(&mut reader, compress, validate)?;
            let mut key_bytes = vec![0; key_len as usize];
            reader.read_exact(&mut key_bytes)?;
            let partial_key = T::deserialize_with_mode(&key_bytes[..], compress, validate)?;

            // Check that the deserialized authority matches the one in the partial key
            if auth != partial_key.get_authority() {
                return Err(ark_serialize::SerializationError::InvalidData);
            }

            partial_keys.insert(auth, partial_key);
        }
        Ok(FullKey { partial_keys })
    }
}

impl<T: Valid> Valid for FullKey<T> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        for key in self.partial_keys.values() {
            key.check()?;
        }
        Ok(())
    }
}

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
        match self.partial_keys.entry(new_key.get_authority()) {
            Entry::Vacant(entry) => entry.insert(new_key),
            Entry::Occupied(_) => {
                panic!(
                    "Partial key for authority '{}' already exists",
                    new_key.get_authority()
                );
            }
        };
    }

    pub fn get_partial_key(&self, auth: &str) -> Option<&T> {
        self.partial_keys.get(auth)
    }
}

impl<T: PartialKey> Default for FullKey<T> {
    fn default() -> Self {
        Self::new()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::{iota::Iota, keygen, setup};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::test_rng;

    #[test]
    fn test_key_serialization() {
        let mut rng = test_rng();
        let auths = vec!["A", "B"];
        let (msk, mpk) = setup(&mut rng, &auths);

        let mut msk_bytes = Vec::new();
        msk.serialize_compressed(&mut msk_bytes).unwrap();

        let mut mpk_bytes = Vec::new();
        mpk.serialize_compressed(&mut mpk_bytes).unwrap();

        let msk_deserialized: MSK = MSK::deserialize_compressed(&msk_bytes[..]).unwrap();
        let mpk_deserialized: MPK = MPK::deserialize_compressed(&mpk_bytes[..]).unwrap();

        assert_eq!(msk, msk_deserialized);
        assert_eq!(mpk, mpk_deserialized);
    }

    #[test]
    fn test_partial_key_deserialization() {
        let mut rng = test_rng();
        let auths = vec!["A", "B"];
        let (_msk, mpk) = setup(&mut rng, &auths);

        let mut mpk_bytes = Vec::new();
        mpk.serialize_compressed(&mut mpk_bytes).unwrap();

        let mut reader = &mpk_bytes[..];
        let num_keys = u64::deserialize_compressed(&mut reader).unwrap();
        assert_eq!(num_keys, 2);

        for _ in 0..num_keys {
            let auth_len = u64::deserialize_compressed(&mut reader).unwrap();
            let mut auth_bytes = vec![0; auth_len as usize];
            reader.read_exact(&mut auth_bytes).unwrap();
            let auth = String::from_utf8(auth_bytes).unwrap();

            let key_len = u64::deserialize_compressed(&mut reader).unwrap();
            let mut key_bytes = vec![0; key_len as usize];
            reader.read_exact(&mut key_bytes).unwrap();

            let partial_key = PartialMPK::deserialize_compressed(&key_bytes[..]).unwrap();
            assert_eq!(auth, partial_key.get_authority());
        }
    }

    #[test]
    fn test_usk_serialization() {
        let mut rng = test_rng();
        let auths = vec!["A", "B"];
        let (msk, _mpk) = setup(&mut rng, &auths);
        let user_attrs = vec![
            UserAttribute::new("A", "L1", "A1"),
            UserAttribute::new("B", "L2", "A2"),
        ];
        let iota = Iota::new(&user_attrs);
        let usk = keygen(&mut rng, "gid", &msk, &user_attrs, &iota);

        let mut usk_bytes = Vec::new();
        usk.serialize_compressed(&mut usk_bytes).unwrap();

        let usk_deserialized: USK = USK::deserialize_compressed(&usk_bytes[..]).unwrap();

        assert_eq!(usk, usk_deserialized);
    }
}
