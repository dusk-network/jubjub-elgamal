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
    /// Returns the two points of the [`Encryption`] in a Witness form.
    #[must_use]
    pub fn parse(&self) -> (&WitnessPoint, &WitnessPoint) {
        (&self.ciphertext_1, &self.ciphertext_2)
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

        // we take the 64-bit representation of the Witness u64 plaintext
        // as an array of Witnesses
        let plaintext_decom = composer.component_decomposition::<64>(plaintext);

        // we do the same with the map for its bit size (255)
        let map = mapped_plaintext.y();
        let map_decom = composer.component_decomposition::<255>(*map);

        // we enforce both decompositions to be equal up to the 64th bit
        plaintext_decom
            .iter()
            .zip(map_decom)
            .for_each(|(bit_a, bit_b)| composer.assert_equal(*bit_a, bit_b));

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

        // we enforce the unmaped plaintext to match the actual
        // decryption output up to the 64th bit
        let map_plaintext_decom =
            composer.component_decomposition::<255>(*mapped_dec_plaintext.y());
        let dec_plaintext_decom =
            composer.component_decomposition::<64>(dec_plaintext);

        dec_plaintext_decom
            .iter()
            .zip(map_plaintext_decom)
            .for_each(|(bit_a, bit_b)| composer.assert_equal(*bit_a, bit_b));

        dec_plaintext
    }
}
