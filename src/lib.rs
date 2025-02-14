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

/// Uses the given `public_key` and a fresh random number `r` to encrypt a
/// plaintext [`JubJubExtended`].
///
/// ## Return
/// Returns the ciphertext tuple `(JubJubExtended, JubJubExtended)`.
#[must_use]
pub fn encrypt(
    public_key: &JubJubExtended,
    plaintext: &JubJubExtended,
    r: &JubJubScalar,
) -> (JubJubExtended, JubJubExtended) {
    let ciphertext_1 = GENERATOR * r;
    let ciphertext_2 = plaintext + public_key * r;

    (ciphertext_1, ciphertext_2)
}

/// Uses the given `secret_key` to decrypt the given `ciphertext` to the
/// original plaintext.
///
/// ## Return
/// Returns the [`JubJubExtended`] plaintext.
#[must_use]
pub fn decrypt(
    secret_key: &JubJubScalar,
    ciphertext: &(JubJubExtended, JubJubExtended),
) -> JubJubExtended {
    let ciphertext_1 = ciphertext.0;
    let ciphertext_2 = ciphertext.1;

    // return the plaintext
    ciphertext_2 - ciphertext_1 * secret_key
}

/// This module implements the equivalent plonk-gadgets for encrypting and
/// decrypting. These gadgets can be used as part of a larger circuit.
#[cfg(feature = "zk")]
pub mod zk {
    use dusk_jubjub::GENERATOR;
    use dusk_plonk::prelude::*;

    /// Uses the given `public_key` and a fresh random number `r` to encrypt a
    /// plaintext [`JubJubExtended`] in a gadget that can be used in a
    /// plonk-circuit.
    ///
    /// # Return
    /// Returns the ciphertext tuple `(WitnessPoint, WitnessPoint)`.
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
    ) -> Result<(WitnessPoint, WitnessPoint), Error> {
        let r_point = composer.component_mul_point(r, public_key);
        let ciphertext_1 = composer.component_mul_generator(r, GENERATOR)?;
        let ciphertext_2 = composer.component_add_point(plaintext, r_point);

        // we check if the original message can be recovered
        let dec = composer.component_sub_point(ciphertext_2, r_point);
        composer.assert_equal_point(dec, plaintext);

        Ok((ciphertext_1, ciphertext_2))
    }

    /// Uses the given `secret_key` to decrypt the given `ciphertext` to the
    /// original plaintext in a gadget that can be used in a plonk-circuit.
    ///
    /// ## Return
    /// Returns the [`WitnessPoint`] plaintext.
    #[must_use]
    pub fn decrypt(
        composer: &mut Composer,
        secret_key: Witness,
        ciphertext_1: WitnessPoint,
        ciphertext_2: WitnessPoint,
    ) -> WitnessPoint {
        let c1_sk = composer.component_mul_point(secret_key, ciphertext_1);

        // return plaintext
        composer.component_sub_point(ciphertext_2, c1_sk)
    }
}
