use ark_ec::{
    AffineRepr, CurveGroup,
    hashing::{HashToCurve, HashToCurveError, map_to_curve_hasher::MapToCurve},
};
use ark_ff::field_hashers::HashToField;
use ark_std::marker::PhantomData;

/// Helper struct that can be used to construct elements on the elliptic curve
/// from arbitrary messages, by first hashing the message onto a field element
/// and then mapping it to the elliptic curve defined over that field.
#[derive(Default)]
pub struct SwiftMapToCurveBasedHasher<T, H2F, M2C>
where
    T: CurveGroup,
    H2F: HashToField<T::BaseField>,
    M2C: MapToCurve<T>,
{
    field_hasher: H2F,
    curve_mapper: M2C,
    _params_t: PhantomData<T>,
}

impl<T, H2F, M2C> HashToCurve<T> for SwiftMapToCurveBasedHasher<T, H2F, M2C>
where
    T: CurveGroup,
    H2F: HashToField<T::BaseField>,
    M2C: MapToCurve<T>,
{
    fn new(domain: &[u8]) -> Result<Self, HashToCurveError> {
        let field_hasher = H2F::new(domain);
        let curve_mapper = M2C::new()?;
        let _params_t = PhantomData;
        Ok(SwiftMapToCurveBasedHasher {
            field_hasher,
            curve_mapper,
            _params_t,
        })
    }

    fn hash(&self, msg: &[u8]) -> Result<T::Affine, HashToCurveError> {
        let rand_field_elem = self.field_hasher.hash_to_field(msg, 1)[0];

        let rand_curve_elem = self.curve_mapper.map_to_curve(rand_field_elem)?;

        let rand_subgroup_elem = rand_curve_elem.clear_cofactor();

        Ok(rand_subgroup_elem)
    }
}
