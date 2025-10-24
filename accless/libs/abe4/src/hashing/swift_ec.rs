use ark_ec::{
    hashing::{HashToCurveError, map_to_curve_hasher::MapToCurve},
    models::short_weierstrass::{Affine, Projective, SWCurveConfig},
};
use ark_ff::{
    BigInteger, Field, One, PrimeField, Zero,
    field_hashers::{DefaultFieldHasher, HashToField},
};
use core::marker::PhantomData;
use sha2::Sha256;

pub struct SwiftECMap<P: SWCurveConfig>(PhantomData<fn() -> P>);

/// Trait defining a parity method on the Field elements based on [\[1\]]
/// Section 4.1
///
/// - [\[1\]] <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/>
pub fn parity<F: Field>(element: &F) -> bool {
    element
        .to_base_prime_field_elements()
        .find(|&x| !x.is_zero())
        .map_or(false, |x| x.into_bigint().is_odd())
}

pub trait SwiftConfig: SWCurveConfig {
    /// An element of the base field corresponding to the square root of -3.
    const SQRT_MINUS3: Self::BaseField;
}

impl<P: SwiftConfig> MapToCurve<Projective<P>> for SwiftECMap<P> {
    fn new() -> Result<Self, HashToCurveError> {
        let one = <P::BaseField as One>::one();
        let minus3 = -(one + one + one);
        if minus3.legendre().is_qr() == false {
            return Err(HashToCurveError::MapToCurveError(
                "-3 should be a QR in the field".to_string(),
            ));
        }

        // Verifying the prerequisite for applicability  of SWU map
        if !P::COEFF_A.is_zero() || P::COEFF_B.is_zero() {
            return Err(HashToCurveError::MapToCurveError("Simplified SwiftEC requires a == 0 and b != 0 in the short Weierstrass form of y^2 = x^3 + a*x + b ".to_string()));
        }

        Ok(SwiftECMap(PhantomData))
    }

    /// Map an arbitrary base field element to a curve point.
    /// Based on
    /// <https://github.com/zcash/pasta_curves/blob/main/src/hashtocurve.rs>.
    fn map_to_curve(&self, t1: P::BaseField) -> Result<Affine<P>, HashToCurveError> {
        let b = P::COEFF_B;
        let field_hasher = <DefaultFieldHasher<Sha256> as HashToField<P::BaseField>>::new(&[0]);
        let str = t1.to_string();
        // We need to hash again because trait only allows one field element.
        let t2: P::BaseField = field_hasher.hash_to_field(&str.as_bytes(), 1)[0];

        // h_0 = t1^3, h1 = t2^2, h2 = h0 + b - h1, h3 = 2h1 + h2.
        let h0 = t1 * t1.square();
        let h1 = t2.square();
        let h2 = h0 + b - h1;
        let h3 = h1.double() + h2;

        // h6 = t1\tau, v = h7 = h2h6, h8 = 2h6t2.
        let h6 = t1 * P::SQRT_MINUS3;
        let h7 = h2 * h6;
        let h8 = (h6 * t2).double();

        // n1 = h8(h7 - t1h3), n2 = (2h3)^2, d1 = 2h3h8
        let n1 = h8 * (h7 - t1 * h3);
        let n2 = h3.double().square();
        let d1 = (h3 * h8).double();

        if d1.is_zero() {
            return Ok(Affine::identity());
        }

        let inv = d1.inverse().unwrap();
        let x1 = n1 * inv;
        let x2 = -(t1 + x1);
        let x3 = (n2 * inv).square() + t1;

        let u = x1.square() * x1 + b;
        let v = x2.square() * x2 + b;
        let w = x3.square() * x3 + b;

        let x_affine;
        let y;
        if w.legendre().is_qr() {
            x_affine = x3;
            y = w.sqrt().unwrap();
        } else if v.legendre().is_qr() {
            x_affine = x2;
            y = v.sqrt().unwrap();
        } else {
            x_affine = x1;
            y = u.sqrt().unwrap();
        }

        let y_affine = if parity(&y) != parity(&t1) { -y } else { y };

        let point_on_curve = Affine::new_unchecked(x_affine, y_affine);
        debug_assert!(
            point_on_curve.is_on_curve(),
            "SwiftEC mapped to a point off the curve"
        );
        Ok(point_on_curve)
    }
}
