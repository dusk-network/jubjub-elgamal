// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use core::ops::Index;
use dusk_bytes::Serializable;
use dusk_jubjub::GENERATOR;
use dusk_plonk::prelude::*;

/// Enumeration used to decrypt ciphertexts in-circuit
pub enum DecryptFrom {
    /// From a secret key
    SecretKey(Witness),
    /// From a shared key
    SharedKey(WitnessPoint),
}

/// `ElGamal` encryption of a [`JubJubExtended`] plaintext
/// in a Witness form, meant to be used in-circuit
#[derive(Debug)]
pub struct Encryption {
    pub(crate) ciphertext_1: WitnessPoint,
    pub(crate) ciphertext_2: WitnessPoint,
}

impl Encryption {
    /// Creates a new [`Encryption`] from two Witness points
    #[must_use]
    pub fn new(ciphertext_1: WitnessPoint, ciphertext_2: WitnessPoint) -> Self {
        Self {
            ciphertext_1,
            ciphertext_2,
        }
    }

    /// Returns the `ciphertext_1` point of the [`Encryption`] in a Witness
    /// form.
    #[must_use]
    pub fn c1(&self) -> &WitnessPoint {
        &self.ciphertext_1
    }

    /// Returns the `ciphertext_2` point of the [`Encryption`] in a Witness
    /// form.
    #[must_use]
    pub fn c2(&self) -> &WitnessPoint {
        &self.ciphertext_2
    }

    /// Uses the given `public_key` and a fresh random number `r` to encrypt a
    /// plaintext [`WitnessPoint`] in a gadget that can be used in a
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
        public_key: WitnessPoint,
        plaintext: WitnessPoint,
        generator: Option<WitnessPoint>,
        r: Witness,
    ) -> Result<(Self, WitnessPoint), Error> {
        let ciphertext_1 = match generator {
            Some(generator) => composer.component_mul_point(r, generator),
            _ => composer.component_mul_generator(r, GENERATOR)?,
        };

        let shared_key = composer.component_mul_point(r, public_key);
        let ciphertext_2 = composer.component_add_point(plaintext, shared_key);

        // we check if the original message can be recovered
        let dec = composer.component_sub_point(ciphertext_2, shared_key);
        composer.assert_equal_point(dec, plaintext);

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
        public_key: WitnessPoint,
        plaintext: Witness,
        generator: Option<WitnessPoint>,
        r: Witness,
    ) -> Result<(Self, WitnessPoint), Error> {
        // we take the u64 plaintext from the Witness
        let plaintext_le_u64 =
            &composer.index(plaintext).to_bytes()[..u64::SIZE];
        let plaintext_u64 =
            u64::from_le_bytes(plaintext_le_u64.try_into().unwrap());

        // we map the plaintext to a point on the curve
        let mapped_plaintext =
            composer.append_point(JubJubExtended::map_to_point(&plaintext_u64));

        // we enforce the mapped point to match the plaintext
        assert_u64_map(composer, mapped_plaintext, plaintext);

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
    /// Returns the [`WitnessPoint`] plaintext.
    #[must_use]
    pub fn decrypt(
        &self,
        composer: &mut Composer,
        key: &DecryptFrom,
    ) -> WitnessPoint {
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
        assert_u64_map(composer, mapped_dec_plaintext, dec_plaintext);

        dec_plaintext
    }
}

/// Constrains `point` to the form [`JubJubExtended::map_to_point`] gives the
/// u64 `value`: an even `x`, and `y = value + 2^64·k` with `value < 2^64` and
/// `k < 2^190`, so that `value` is the low 64 bits of the canonical `y`.
fn assert_u64_map(
    composer: &mut Composer,
    point: WitnessPoint,
    value: Witness,
) {
    let half = BlsScalar::from(2).invert().expect("2 is invertible");
    let shift = BlsScalar::pow_of_2(64)
        .invert()
        .expect("2^64 is invertible");

    // k = (y - value) / 2^64
    let k = composer.gate_add(
        Constraint::new()
            .left(shift)
            .a(*point.y())
            .right(-shift)
            .b(value),
    );
    composer.component_range::<32>(value);
    composer.component_range::<95>(k);

    // x is even iff x/2 <= (p - 1)/2, i.e. iff both x/2 and
    // (p - 1)/2 - x/2 = -(x + 1)/2 fit in 254 bits
    let x_half = composer.gate_add(Constraint::new().left(half).a(*point.x()));
    let x_half_neg = composer
        .gate_add(Constraint::new().left(-half).a(*point.x()).constant(-half));
    composer.component_range::<127>(x_half);
    composer.component_range::<127>(x_half_neg);
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
/// Returns the ciphertext tuple `(WitnessPoint, WitnessPoint)`.
///
/// # Errors
/// This function will error if `r` is not a valid jubjub-scalar.
pub fn encrypt_unchecked(
    composer: &mut Composer,
    public_key: WitnessPoint,
    plaintext: WitnessPoint,
    r: Witness,
) -> Result<(WitnessPoint, WitnessPoint), Error> {
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
/// Returns the [`WitnessPoint`] plaintext.
#[must_use]
pub fn decrypt_unchecked(
    composer: &mut Composer,
    secret_key: Witness,
    ciphertext_1: WitnessPoint,
    ciphertext_2: WitnessPoint,
) -> WitnessPoint {
    let c1_sk = composer.component_mul_point(secret_key, ciphertext_1);

    // return plaintext
    composer.component_sub_point(ciphertext_2, c1_sk)
}
