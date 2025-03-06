// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED};
use ff::Field;
use jubjub_elgamal::{DecryptFrom, Encryption};
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn encrypt_decrypt_u64() {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let sk = JubJubScalar::random(&mut rng);
    let pk = GENERATOR_EXTENDED * &sk;

    let message = 1234u64;

    // Encrypt using a fresh random value 'blinder'
    let blinder = JubJubScalar::random(&mut rng);
    let (ciphertext, shared_key) =
        Encryption::encrypt_u64(&pk, &message, None, &blinder);

    // Assert decryption using the secret key
    let dec_message = ciphertext.decrypt_u64(&DecryptFrom::SecretKey(sk));
    assert_eq!(message, dec_message);

    // Assert decryption using the shared key
    let dec_message =
        ciphertext.decrypt_u64(&DecryptFrom::SharedKey(shared_key));
    assert_eq!(message, dec_message);

    // Assert decryption using an incorrect secret key
    let wrong_sk = JubJubScalar::random(&mut rng);
    let dec_message_wrong =
        ciphertext.decrypt_u64(&DecryptFrom::SecretKey(wrong_sk));
    assert_ne!(message, dec_message_wrong);
}

#[cfg(feature = "zk")]
mod zk {
    use dusk_jubjub::{
        JubJubAffine, JubJubExtended, JubJubScalar, GENERATOR_EXTENDED,
    };
    use dusk_plonk::prelude::*;
    use ff::Field;
    use jubjub_elgamal::zk::{
        DecryptFrom as DecryptFromZK, Encryption as EncryptionZK,
    };
    use jubjub_elgamal::Encryption;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    static LABEL: &[u8; 12] = b"dusk-network";
    const CAPACITY: usize = 14; // capacity required for the setup

    #[derive(Default, Debug)]
    pub struct ElGamalCircuit {
        public_key: JubJubAffine,
        secret_key: JubJubScalar,
        plaintext: u64,
        r: JubJubScalar,
        expected_ciphertext: Encryption,
    }

    impl ElGamalCircuit {
        pub fn new(
            public_key: &JubJubExtended,
            secret_key: &JubJubScalar,
            plaintext: &u64,
            r: &JubJubScalar,
            expected_ciphertext: &Encryption,
        ) -> Self {
            Self {
                public_key: JubJubAffine::from(public_key),
                secret_key: *secret_key,
                plaintext: *plaintext,
                r: *r,
                expected_ciphertext: *expected_ciphertext,
            }
        }
    }

    impl Circuit for ElGamalCircuit {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            // import inputs
            let public_key = composer.append_point(self.public_key);
            let secret_key = composer.append_witness(self.secret_key);
            let plaintext = composer.append_witness(self.plaintext);
            let r = composer.append_witness(self.r);

            // encrypt plaintext using the public key
            let (ciphertext, shared_key) = EncryptionZK::encrypt_u64(
                composer, public_key, plaintext, None, r,
            )?;

            // assert that the ciphertext is as expected
            composer.assert_equal_public_point(
                *ciphertext.parse().0,
                self.expected_ciphertext.parse().0,
            );
            composer.assert_equal_public_point(
                *ciphertext.parse().1,
                self.expected_ciphertext.parse().1,
            );

            // decrypt with sk
            let dec_plaintext = ciphertext
                .decrypt_u64(composer, &DecryptFromZK::SecretKey(secret_key));

            // assert decoded plaintext is the same as the original
            composer.assert_equal(dec_plaintext, plaintext);

            // decrypt with shared key
            let dec_plaintext = ciphertext
                .decrypt_u64(composer, &DecryptFromZK::SharedKey(shared_key));
            composer.assert_equal(dec_plaintext, plaintext);

            // encrypt / decrypt plaintext using custom generator
            let custom_gen = composer
                .append_point(GENERATOR_EXTENDED * JubJubScalar::from(1234u64));
            let custom_pk =
                composer.component_mul_point(secret_key, custom_gen);
            let (custom_enc, _) = EncryptionZK::encrypt_u64(
                composer,
                custom_pk,
                plaintext,
                Some(custom_gen),
                r,
            )?;

            let custom_dec_plaintext = custom_enc
                .decrypt_u64(composer, &DecryptFromZK::SecretKey(secret_key));
            composer.assert_equal(custom_dec_plaintext, plaintext);

            Ok(())
        }
    }

    #[test]
    fn encrypt_decrypt_u64() {
        let mut rng = StdRng::seed_from_u64(0xc0b);

        let sk = JubJubScalar::random(&mut rng);
        let pk = GENERATOR_EXTENDED * sk;

        let message = 1234u64;
        let r = JubJubScalar::random(&mut rng);
        let (ciphertext, _) = Encryption::encrypt_u64(&pk, &message, None, &r);

        let pp = PublicParameters::setup(1 << CAPACITY, &mut rng).unwrap();

        let (prover, verifier) =
            Compiler::compile::<ElGamalCircuit>(&pp, LABEL)
                .expect("failed to compile circuit");

        let (proof, public_inputs) = prover
            .prove(
                &mut rng,
                &ElGamalCircuit::new(&pk, &sk, &message, &r, &ciphertext),
            )
            .expect("failed to prove");

        verifier
            .verify(&proof, &public_inputs)
            .expect("failed to verify proof");
    }
}
