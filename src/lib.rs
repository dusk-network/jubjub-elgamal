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

use dusk_bytes::{DeserializableSlice, Error as DuskBytesError, Serializable};
use dusk_jubjub::{
    JubJubAffine, JubJubExtended, JubJubScalar, GENERATOR_EXTENDED,
};

#[cfg(feature = "zk")]
use dusk_plonk::prelude::Composer;

/// This module implements the equivalent plonk-gadgets for encrypting and
/// decrypting. These gadgets can be used as part of a larger circuit.
#[cfg(feature = "zk")]
pub mod zk;

/// Enumeration used to decrypt ciphertexts
pub enum DecryptFrom {
    /// From a secret key
    SecretKey(JubJubScalar),
    /// From a shared key
    SharedKey(JubJubExtended),
}

/// `ElGamal` encryption of a [`JubJubExtended`] plaintext
#[derive(Default, Debug, Clone, Copy)]
pub struct Encryption {
    ciphertext_1: JubJubExtended,
    ciphertext_2: JubJubExtended,
}

impl Encryption {
    /// Creates a new [`Encryption`] from two points
    #[must_use]
    pub fn new(
        ciphertext_1: JubJubExtended,
        ciphertext_2: JubJubExtended,
    ) -> Self {
        Self {
            ciphertext_1,
            ciphertext_2,
        }
    }

    /// Returns the two points of the [`Encryption`]
    #[must_use]
    pub fn parse(&self) -> (&JubJubExtended, &JubJubExtended) {
        (&self.ciphertext_1, &self.ciphertext_2)
    }

    /// Uses the given `public_key` and a fresh random number `r` to encrypt a
    /// plaintext [`JubJubExtended`]. An optional custom generator can be
    /// provided.
    ///
    /// ## Return
    /// Returns an [`Encryption`] plus the computed shared key.
    #[must_use]
    pub fn encrypt(
        public_key: &JubJubExtended,
        plaintext: &JubJubExtended,
        generator: Option<&JubJubExtended>,
        r: &JubJubScalar,
    ) -> (Self, JubJubExtended) {
        let ciphertext_1 = match generator {
            Some(generator) => generator * r,
            _ => GENERATOR_EXTENDED * r,
        };

        let shared_key = public_key * r;
        let ciphertext_2 = plaintext + shared_key;

        (
            Self {
                ciphertext_1,
                ciphertext_2,
            },
            shared_key,
        )
    }

    /// Uses the given `public_key` and a fresh random number `r` to encrypt a
    /// plaintext [`u64`] by means of a curve mapping.
    ///
    /// ## Return
    /// Returns an [`Encryption`] plus the computed shared key.
    #[must_use]
    pub fn encrypt_u64(
        public_key: &JubJubExtended,
        plaintext: &u64,
        generator: Option<&JubJubExtended>,
        r: &JubJubScalar,
    ) -> (Encryption, JubJubExtended) {
        let mapped_plaintext = JubJubExtended::map_to_point(plaintext);
        Self::encrypt(public_key, &mapped_plaintext, generator, r)
    }

    /// Uses the given `key` to decrypt the [`Encryption`] to the
    /// original plaintext.
    ///
    /// ## Return
    /// Returns the [`JubJubExtended`] plaintext.
    #[must_use]
    pub fn decrypt(&self, key: &DecryptFrom) -> JubJubExtended {
        match key {
            DecryptFrom::SecretKey(secret_key) => {
                self.ciphertext_2 - self.ciphertext_1 * secret_key
            }
            DecryptFrom::SharedKey(shared_key) => {
                self.ciphertext_2 - shared_key
            }
        }
    }

    /// Uses the given `key` to decrypt the [`Encryption`] to the
    /// original [`u64`] plaintext, by means of a curve unmapping.
    ///
    /// ## Return
    /// Returns the [`u64`] plaintext.
    #[must_use]
    pub fn decrypt_u64(&self, key: &DecryptFrom) -> u64 {
        let mapped_plaintext = self.decrypt(key);
        JubJubExtended::unmap_from_point(mapped_plaintext)
    }

    /// Appends the [`Encryption`] to the provided [`Composer`]
    #[cfg(feature = "zk")]
    pub fn append_to_composer(
        &self,
        composer: &mut Composer,
    ) -> zk::Encryption {
        let ciphertext_1 = composer.append_point(self.ciphertext_1);
        let ciphertext_2 = composer.append_point(self.ciphertext_2);

        zk::Encryption {
            ciphertext_1,
            ciphertext_2,
        }
    }
}

impl Serializable<64> for Encryption {
    type Error = DuskBytesError;
    const SIZE: usize = 64;

    fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];

        bytes[..32]
            .copy_from_slice(&JubJubAffine::from(self.ciphertext_1).to_bytes());
        bytes[32..]
            .copy_from_slice(&JubJubAffine::from(self.ciphertext_2).to_bytes());

        bytes
    }

    fn from_bytes(buf: &[u8; 64]) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let ciphertext_1: JubJubExtended =
            JubJubAffine::from_slice(&buf[..32])?.into();
        let ciphertext_2: JubJubExtended =
            JubJubAffine::from_slice(&buf[32..])?.into();

        Ok(Encryption {
            ciphertext_1,
            ciphertext_2,
        })
    }
}
