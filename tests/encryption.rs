// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::Serializable;
use dusk_jubjub::{GENERATOR_EXTENDED, JubJubScalar};
use ff::Field;
use jubjub_elgamal::{DecryptFrom, Encryption};
use rand::SeedableRng;
use rand::rngs::StdRng;

#[test]
fn encrypt_decrypt() {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let sk = JubJubScalar::random(&mut rng);
    let pk = GENERATOR_EXTENDED * &sk;

    let message = GENERATOR_EXTENDED * JubJubScalar::from(1234u64);

    // Encrypt using a fresh random value 'blinder'
    let blinder = JubJubScalar::random(&mut rng);
    let (ciphertext, shared_key) =
        Encryption::encrypt(&pk, &message, None, &blinder);

    // Assert decryption using the secret key
    let dec_message = ciphertext.decrypt(&DecryptFrom::SecretKey(sk));
    assert_eq!(message, dec_message);

    // Assert decryption using the shared key
    let dec_message = ciphertext.decrypt(&DecryptFrom::SharedKey(shared_key));
    assert_eq!(message, dec_message);

    // Assert decryption using an incorrect secret key
    let wrong_sk = JubJubScalar::random(&mut rng);
    let dec_message_wrong =
        ciphertext.decrypt(&DecryptFrom::SecretKey(wrong_sk));
    assert_ne!(message, dec_message_wrong);

    // encrypt / decrypt plaintext using custom generator
    let custom_gen = GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);
    let custom_pk = custom_gen * sk;

    let (custom_enc, _) =
        Encryption::encrypt(&custom_pk, &message, Some(&custom_gen), &blinder);

    let dec_message = custom_enc.decrypt(&DecryptFrom::SecretKey(sk));
    assert_eq!(message, dec_message);
}

#[test]
fn test_bytes() {
    let mut rng = StdRng::seed_from_u64(0xc0b);
    let point = GENERATOR_EXTENDED * &JubJubScalar::random(&mut rng);

    let ciphertext = Encryption::new(point, point);

    assert_eq!(
        ciphertext,
        Encryption::from_bytes(&ciphertext.to_bytes()).unwrap()
    );
}

#[cfg(feature = "zk")]
mod zk {
    use dusk_jubjub::{
        GENERATOR_EXTENDED, JubJubAffine, JubJubExtended, JubJubScalar,
    };
    use dusk_plonk::prelude::*;
    use ff::Field;
    use jubjub_elgamal::Encryption;
    use jubjub_elgamal::zk::{
        DecryptFrom as DecryptFromZK, Encryption as EncryptionZK,
    };
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    static LABEL: &[u8; 12] = b"dusk-network";
    const CAPACITY: usize = 14; // capacity required for the setup

    #[derive(Default, Debug)]
    pub struct ElGamalCircuit<const MUST_PASS: bool> {
        public_key: JubJubAffine,
        secret_key: JubJubScalar,
        plaintext: JubJubAffine,
        r: JubJubScalar,
        expected_ciphertext: Encryption,
    }

    impl<const MUST_PASS: bool> ElGamalCircuit<MUST_PASS> {
        pub fn new(
            public_key: &JubJubExtended,
            secret_key: &JubJubScalar,
            plaintext: &JubJubExtended,
            r: &JubJubScalar,
            expected_ciphertext: &Encryption,
        ) -> Self {
            Self {
                public_key: JubJubAffine::from(public_key),
                secret_key: *secret_key,
                plaintext: JubJubAffine::from(plaintext),
                r: *r,
                expected_ciphertext: *expected_ciphertext,
            }
        }
    }

    impl<const MUST_PASS: bool> Circuit for ElGamalCircuit<MUST_PASS> {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            // import inputs
            let public_key = composer.append_point(self.public_key);
            let secret_key = composer.append_witness(self.secret_key);
            let plaintext = composer.append_point(self.plaintext);
            let r = composer.append_witness(self.r);

            // encrypt plaintext using the public key
            let (ciphertext, shared_key) = EncryptionZK::encrypt(
                composer, public_key, plaintext, None, r,
            )?;

            // only for the 'encrypt_decrypt' test
            if MUST_PASS {
                // assert that the ciphertext is as expected
                composer.assert_equal_public_point(
                    *ciphertext.c1(),
                    self.expected_ciphertext.c1(),
                );
                composer.assert_equal_public_point(
                    *ciphertext.c2(),
                    self.expected_ciphertext.c2(),
                );

                // decrypt with sk
                let dec_plaintext = ciphertext
                    .decrypt(composer, &DecryptFromZK::SecretKey(secret_key));

                // assert decoded plaintext is the same as the original
                composer.assert_equal_point(dec_plaintext, plaintext);

                // decrypt with shared key
                let dec_plaintext = ciphertext
                    .decrypt(composer, &DecryptFromZK::SharedKey(shared_key));
                composer.assert_equal_point(dec_plaintext, plaintext);

                // encrypt / decrypt plaintext using custom generator
                let custom_gen = composer.append_point(
                    GENERATOR_EXTENDED * JubJubScalar::from(1234u64),
                );
                let custom_pk =
                    composer.component_mul_point(secret_key, custom_gen);
                let (custom_enc, _) = EncryptionZK::encrypt(
                    composer,
                    custom_pk,
                    plaintext,
                    Some(custom_gen),
                    r,
                )?;

                let custom_dec_plaintext = custom_enc
                    .decrypt(composer, &DecryptFromZK::SecretKey(secret_key));
                composer.assert_equal_point(custom_dec_plaintext, plaintext);
            }

            Ok(())
        }
    }

    #[test]
    fn encrypt_decrypt() {
        let mut rng = StdRng::seed_from_u64(0xc0b);

        let sk = JubJubScalar::random(&mut rng);
        let pk = GENERATOR_EXTENDED * sk;

        let message = GENERATOR_EXTENDED * JubJubScalar::from(1234u64);
        let r = JubJubScalar::random(&mut rng);
        let (ciphertext, _) = Encryption::encrypt(&pk, &message, None, &r);

        let pp = PublicParameters::setup(1 << CAPACITY, &mut rng).unwrap();

        let (prover, verifier) =
            Compiler::compile::<ElGamalCircuit<true>>(&pp, LABEL)
                .expect("failed to compile circuit");

        let (proof, public_inputs) = prover
            .prove(
                &mut rng,
                &ElGamalCircuit::<true>::new(
                    &pk,
                    &sk,
                    &message,
                    &r,
                    &ciphertext,
                ),
            )
            .expect("failed to prove");

        verifier
            .verify(&proof, &public_inputs)
            .expect("failed to verify proof");
    }

    #[test]
    #[should_panic]
    fn bad_encryption() {
        let mut rng = StdRng::seed_from_u64(0xc0b);

        let sk = JubJubScalar::random(&mut rng);
        let pk = GENERATOR_EXTENDED * sk;

        // we set a message being a point not on the curve
        let message =
            JubJubExtended::from_affine(JubJubAffine::from_raw_unchecked(
                BlsScalar::from(42),
                BlsScalar::from(42),
            ));

        let r = JubJubScalar::random(&mut rng);

        // not involved in this test
        let ciphertext = Encryption::new(message, message);

        let pp = PublicParameters::setup(1 << CAPACITY, &mut rng).unwrap();

        let (prover, _verifier) =
            Compiler::compile::<ElGamalCircuit<false>>(&pp, LABEL)
                .expect("failed to compile circuit");

        // this should fail
        let (_proof, _public_inputs) = prover
            .prove(
                &mut rng,
                &ElGamalCircuit::<false>::new(
                    &pk,
                    &sk,
                    &message,
                    &r,
                    &ciphertext,
                ),
            )
            .expect("failed to prove");
    }
}
