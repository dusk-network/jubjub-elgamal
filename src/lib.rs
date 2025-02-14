// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![no_std]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::pedantic)]

use dusk_jubjub::{JubJubExtended, JubJubScalar, GENERATOR};

/// Enumeration used to decrypt ciphertexts
pub enum DecryptionOrigin {
    /// From a secret key
    FromSecretKey(JubJubScalar),
    /// From a shared key
    FromSharedKey(JubJubExtended),
}

/// Uses the given `public_key` and a fresh random number `r` to encrypt a
/// plaintext [`JubJubExtended`].
///
/// ## Return
/// Returns the ciphertext plus `shared_key` tuple
/// `(JubJubExtended, JubJubExtended, JubJubExtended)`.
#[must_use]
pub fn encrypt(
    public_key: &JubJubExtended,
    plaintext: &JubJubExtended,
    r: &JubJubScalar,
) -> (JubJubExtended, JubJubExtended, JubJubExtended) {
    let ciphertext_1 = GENERATOR * r;
    let shared_key = public_key * r;
    let ciphertext_2 = plaintext + shared_key;

    (ciphertext_1, ciphertext_2, shared_key)
}

/// Uses the given `key` to decrypt the given `ciphertext` to the
/// original plaintext.
///
/// ## Return
/// Returns the [`JubJubExtended`] plaintext.
#[must_use]
pub fn decrypt(
    key: &DecryptionOrigin,
    ciphertext: &(JubJubExtended, JubJubExtended),
) -> JubJubExtended {
    let ciphertext_1 = ciphertext.0;
    let ciphertext_2 = ciphertext.1;

    // return the plaintext
    match key {
        DecryptionOrigin::FromSecretKey(secret_key) => {
            ciphertext_2 - ciphertext_1 * secret_key
        }
        DecryptionOrigin::FromSharedKey(shared_key) => {
            ciphertext_2 - shared_key
        }
    }
}

/// This module implements the equivalent plonk-gadgets for encrypting and
/// decrypting. These gadgets can be used as part of a larger circuit.
#[cfg(feature = "zk")]
pub mod zk {
    use dusk_jubjub::GENERATOR;
    use dusk_plonk::prelude::*;

    /// Enumeration used to decrypt ciphertexts in-circuit
    pub enum DecryptionOrigin {
        /// From a secret key
        FromSecretKey(Witness),
        /// From a shared key
        FromSharedKey(WitnessPoint),
    }

    /// Uses the given `public_key` and a fresh random number `r` to encrypt a
    /// plaintext [`JubJubExtended`] in a gadget that can be used in a
    /// plonk-circuit.
    ///
    /// # Return
    /// Returns the ciphertext plus `shared_key` tuple
    /// `(WitnessPoint, WitnessPoint, WitnessPoint)`.
    ///
    /// # Errors
    /// This function will error if `r` is not a valid jubjub-scalar.
    /// It will also make Plonk fail to prove if the ciphertext cannot
    /// be decrypted.
    pub fn encrypt(
        composer: &mut Composer,
        public_key: WitnessPoint,
        plaintext: WitnessPoint,
        r: Witness,
    ) -> Result<(WitnessPoint, WitnessPoint, WitnessPoint), Error> {
        let shared_key = composer.component_mul_point(r, public_key);
        let ciphertext_1 = composer.component_mul_generator(r, GENERATOR)?;
        let ciphertext_2 = composer.component_add_point(plaintext, shared_key);

        // we check if the original message can be recovered
        let dec = composer.component_sub_point(ciphertext_2, shared_key);
        composer.assert_equal_point(dec, plaintext);

        Ok((ciphertext_1, ciphertext_2, shared_key))
    }

    /// Uses the given `key` to decrypt the given `ciphertext` to the
    /// original plaintext in a gadget that can be used in a plonk-circuit.
    ///
    /// ## Return
    /// Returns the [`WitnessPoint`] plaintext.
    #[must_use]
    pub fn decrypt(
        composer: &mut Composer,
        key: &DecryptionOrigin,
        ciphertext_1: WitnessPoint,
        ciphertext_2: WitnessPoint,
    ) -> WitnessPoint {
        match key {
            DecryptionOrigin::FromSecretKey(secret_key) => {
                let c1_sk =
                    composer.component_mul_point(*secret_key, ciphertext_1);
                // return plaintext
                composer.component_sub_point(ciphertext_2, c1_sk)
            }
            DecryptionOrigin::FromSharedKey(shared_key) => {
                // return plaintext
                composer.component_sub_point(ciphertext_2, *shared_key)
            }
        }
    }
}
