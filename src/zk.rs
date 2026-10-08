// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use core::ops::Index;
use dusk_bytes::Serializable;
use dusk_jubjub::GENERATOR;
use dusk_plonk::prelude::*;

// Point arguments use `TorsionFreeWitnessPoint` so callers must establish
// subgroup membership at the circuit boundary before invoking these gadgets.

/// Enumeration used to decrypt ciphertexts in-circuit
pub enum DecryptFrom {
    /// From a secret key
    SecretKey(Witness),
    /// From a shared key
    SharedKey(TorsionFreeWitnessPoint),
}

/// `ElGamal` encryption of a [`JubJubExtended`] plaintext in a
/// subgroup-qualified witness form, meant to be used in-circuit.
#[derive(Debug)]
pub struct Encryption {
    pub(crate) ciphertext_1: TorsionFreeWitnessPoint,
    pub(crate) ciphertext_2: TorsionFreeWitnessPoint,
}

impl Encryption {
    /// Creates a new [`Encryption`] from two subgroup-qualified witness
    /// points.
    #[must_use]
    pub fn new(
        ciphertext_1: TorsionFreeWitnessPoint,
        ciphertext_2: TorsionFreeWitnessPoint,
    ) -> Self {
        Self {
            ciphertext_1,
            ciphertext_2,
        }
    }

    /// Returns the `ciphertext_1` point of the [`Encryption`] in a Witness
    /// form.
    #[must_use]
    pub fn c1(&self) -> &TorsionFreeWitnessPoint {
        &self.ciphertext_1
    }

    /// Returns the `ciphertext_2` point of the [`Encryption`] in a Witness
    /// form.
    #[must_use]
    pub fn c2(&self) -> &TorsionFreeWitnessPoint {
        &self.ciphertext_2
    }

    /// Uses the given `public_key` and a fresh random number `r` to encrypt a
    /// plaintext [`TorsionFreeWitnessPoint`] in a gadget that can be used in a
    /// plonk-circuit.
    ///
    /// ## Return
    /// Returns the ciphertext plus the `shared_key`.
    ///
    /// ## Errors
    /// This function will error if `r` is not a valid jubjub-scalar.
    /// It will also make Plonk fail to prove if the [`Encryption`] cannot
    /// be decrypted.
    pub fn encrypt(
        composer: &mut Composer,
        public_key: TorsionFreeWitnessPoint,
        plaintext: TorsionFreeWitnessPoint,
        generator: Option<TorsionFreeWitnessPoint>,
        r: Witness,
    ) -> Result<(Self, TorsionFreeWitnessPoint), Error> {
        let ciphertext_1 = match generator {
            Some(generator) => composer.component_mul_point(r, generator),
            _ => composer.component_mul_generator(r, GENERATOR)?,
        };

        let shared_key = composer.component_mul_point(r, public_key);
        let ciphertext_2 = composer.component_add_point(plaintext, shared_key);

        // we check if the original message can be recovered
        let dec = composer.component_sub_point(ciphertext_2, shared_key);
        composer.assert_equal_point(dec.into(), plaintext.into());

        Ok((
            Self {
                ciphertext_1,
                ciphertext_2,
            },
            shared_key,
        ))
    }

    /// Uses the given `public_key` and a fresh random number `r` to encrypt a
    /// unsigned 64-bit plaintext [`Witness`] in a gadget that can be used in a
    /// plonk-circuit. It does it by computing a curve mapping [`WitnessPoint`],
    /// which the circuit enforces to match the original plaintext.
    ///
    /// ## Return
    /// Returns the ciphertext plus the `shared_key`.
    ///
    /// ## Panics
    /// Panics if fails to convert scalar to LE bytes.
    ///
    /// ## Errors
    /// This function will error if `r` is not a valid jubjub-scalar.
    /// It will also make Plonk fail to prove if the [`Encryption`] cannot
    /// be decrypted.
    pub fn encrypt_u64(
        composer: &mut Composer,
        public_key: TorsionFreeWitnessPoint,
        plaintext: Witness,
        generator: Option<TorsionFreeWitnessPoint>,
        r: Witness,
    ) -> Result<(Self, TorsionFreeWitnessPoint), Error> {
        // we take the u64 plaintext from the Witness
        let plaintext_le_u64 =
            &composer.index(plaintext).to_bytes()[..u64::SIZE];
        let plaintext_u64 =
            u64::from_le_bytes(plaintext_le_u64.try_into().unwrap());

        // we map the plaintext to a point on the curve
        let mapped_plaintext = composer
            .append_point(JubJubExtended::map_to_point(&plaintext_u64))?;
        let mapped_plaintext =
            composer.assert_torsion_free_point(mapped_plaintext);

        // we enforce the mapped point to match the plaintext
        assert_u64_map(composer, mapped_plaintext.into(), plaintext);

        // we return the encryption of the mapped plaintext
        let (ciphertext, shared_key) = Self::encrypt(
            composer,
            public_key,
            mapped_plaintext,
            generator,
            r,
        )?;
        Ok((ciphertext, shared_key))
    }

    /// Uses the given `key` to decrypt the [`Encryption`] to the
    /// original plaintext in a gadget that can be used in a plonk-circuit.
    ///
    /// ## Return
    /// Returns the [`TorsionFreeWitnessPoint`] plaintext.
    #[must_use]
    pub fn decrypt(
        &self,
        composer: &mut Composer,
        key: &DecryptFrom,
    ) -> TorsionFreeWitnessPoint {
        match key {
            DecryptFrom::SecretKey(secret_key) => {
                let c1_sk = composer
                    .component_mul_point(*secret_key, self.ciphertext_1);
                // return plaintext
                composer.component_sub_point(self.ciphertext_2, c1_sk)
            }
            DecryptFrom::SharedKey(shared_key) => {
                // return plaintext
                composer.component_sub_point(self.ciphertext_2, *shared_key)
            }
        }
    }

    /// Uses the given `key` to decrypt the [`Encryption`] to the
    /// original [`u64`] plaintext in a gadget that can be used in a
    /// plonk-circuit.
    ///
    /// ## Errors
    /// Plonk fails to prove if the decrypted point is not in the u64 map form:
    /// an odd `x`, or a `y` of `2^254` or more.
    ///
    /// ## Panics
    /// Panics if fails to convert scalar to LE bytes.
    ///
    /// ## Return
    /// Returns the [`Witness`] plaintext.
    #[must_use]
    pub fn decrypt_u64(
        &self,
        composer: &mut Composer,
        key: &DecryptFrom,
    ) -> Witness {
        let mapped_dec_plaintext = self.decrypt(composer, key);

        // we take the u64 plaintext from the WitnessPoint (i.e. we unmap)
        let dec_plaintext_le_u64 =
            &composer.index(*mapped_dec_plaintext.y()).to_bytes()[..u64::SIZE];
        let dec_plaintext_u64 =
            u64::from_le_bytes(dec_plaintext_le_u64.try_into().unwrap());
        let dec_plaintext = composer.append_witness(dec_plaintext_u64);

        // we enforce the unmapped plaintext to match the decryption output
        assert_u64_map(composer, mapped_dec_plaintext.into(), dec_plaintext);

        dec_plaintext
    }
}

/// `2^-1` in the BLS12-381 scalar field.
const HALF: BlsScalar = BlsScalar::from_raw([
    0x7fff_ffff_8000_0001,
    0xa9de_d201_7fff_2dff,
    0x199c_ec04_04d0_ec02,
    0x39f6_d3a9_94ce_bea4,
]);

/// `2^-64` in the BLS12-381 scalar field.
const SHIFT: BlsScalar = BlsScalar::from_raw([
    0xac43_fffd_0001_a403,
    0x16e1_f3f5_a29e_dff6,
    0x95ae_b36c_acca_82b5,
    0x73ed_a752_b5af_d5f4,
]);

/// Constrains `point` to have an even `x` and a canonical `y` with `value` as
/// its low 64 bits: `y = value + 2^64·k` with `value < 2^64` and `k < 2^190`.
///
/// This does not pin `point` to the output of [`JubJubExtended::map_to_point`]:
/// `k` is not constrained to be minimal and `point` is not checked to be in
/// the prime-order subgroup, see
/// <https://github.com/dusk-network/jubjub-elgamal/issues/37>.
fn assert_u64_map(
    composer: &mut Composer,
    point: WitnessPoint,
    value: Witness,
) {
    // k = (y - value) / 2^64
    let k = composer.gate_add(
        Constraint::new()
            .left(SHIFT)
            .a(*point.y())
            .right(-SHIFT)
            .b(value),
    );
    composer.component_range_bits::<64>(value);
    composer.component_range_bits::<190>(k);

    // x is even iff x/2 <= (p - 1)/2, i.e. iff both x/2 and
    // (p - 1)/2 - x/2 = -(x + 1)/2 fit in 254 bits
    let x_half = composer.gate_add(Constraint::new().left(HALF).a(*point.x()));
    let x_half_neg = composer
        .gate_add(Constraint::new().left(-HALF).a(*point.x()).constant(-HALF));
    composer.component_range_bits::<254>(x_half);
    composer.component_range_bits::<254>(x_half_neg);
}

/// Uses the given `public_key` and a fresh random number `r` to encrypt a
/// plaintext [`JubJubExtended`] in a gadget that can be used in a
/// plonk-circuit.
///
/// Unlike [`Encryption::encrypt`], this does not add in-circuit constraints
/// to verify that the ciphertext decrypts back to the plaintext. This
/// produces fewer gates, matching the circuit description from v0.2.0.
///
/// # Return
/// Returns the ciphertext tuple of [`TorsionFreeWitnessPoint`]s.
///
/// # Errors
/// This function will error if `r` is not a valid jubjub-scalar.
pub fn encrypt_unchecked(
    composer: &mut Composer,
    public_key: TorsionFreeWitnessPoint,
    plaintext: TorsionFreeWitnessPoint,
    r: Witness,
) -> Result<(TorsionFreeWitnessPoint, TorsionFreeWitnessPoint), Error> {
    let r_point = composer.component_mul_point(r, public_key);
    let ciphertext_1 = composer.component_mul_generator(r, GENERATOR)?;
    let ciphertext_2 = composer.component_add_point(plaintext, r_point);

    Ok((ciphertext_1, ciphertext_2))
}

/// Uses the given `secret_key` to decrypt the given `ciphertext` to the
/// original plaintext in a gadget that can be used in a plonk-circuit.
///
/// This is the standalone counterpart to [`Encryption::decrypt`], matching
/// the circuit description from v0.2.0.
///
/// ## Return
/// Returns the [`TorsionFreeWitnessPoint`] plaintext.
#[must_use]
pub fn decrypt_unchecked(
    composer: &mut Composer,
    secret_key: Witness,
    ciphertext_1: TorsionFreeWitnessPoint,
    ciphertext_2: TorsionFreeWitnessPoint,
) -> TorsionFreeWitnessPoint {
    let c1_sk = composer.component_mul_point(secret_key, ciphertext_1);

    // return plaintext
    composer.component_sub_point(ciphertext_2, c1_sk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn inverse_constants() {
        assert_eq!(HALF * BlsScalar::from(2), BlsScalar::one());
        assert_eq!(SHIFT * BlsScalar::pow_of_2(64), BlsScalar::one());
    }

    #[derive(Default)]
    struct MapCircuit(JubJubAffine, BlsScalar);

    impl Circuit for MapCircuit {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            let point = composer.append_point(self.0)?;
            let value = composer.append_witness(self.1);
            assert_u64_map(composer, point, value);
            Ok(())
        }
    }

    #[test]
    fn u64_map_rejects_value_above_u64() {
        let mut rng = StdRng::seed_from_u64(0xc0b);
        let pp = PublicParameters::setup(1 << 10, &mut rng).unwrap();
        let (prover, verifier) =
            Compiler::compile::<MapCircuit>(&pp, b"u64-map").unwrap();
        let point = JubJubAffine::from(JubJubExtended::map_to_point(&18));
        let mut prove = |value| {
            prover
                .prove(&mut rng, &MapCircuit(point, value))
                .and_then(|(proof, pi)| verifier.verify(&proof, &pi))
        };

        prove(BlsScalar::from(18)).expect("map of 18 must verify");
        // `18 - 2^64` raises `k` by one, which stays in range
        assert!(prove(BlsScalar::from(18) - BlsScalar::pow_of_2(64)).is_err());
    }
}
