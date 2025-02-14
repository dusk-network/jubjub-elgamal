// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED};
use ff::Field;
use jubjub_elgamal::{decrypt, encrypt};
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn encrypt_decrypt() {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let sk = JubJubScalar::random(&mut rng);
    let pk = GENERATOR_EXTENDED * &sk;

    let message = GENERATOR_EXTENDED * JubJubScalar::from(1234u64);

    // Encrypt using a fresh random value 'blinder'
    let blinder = JubJubScalar::random(&mut rng);
    let (c1, c2, _) = encrypt(&pk, &message, &blinder);

    // Assert decryption
    let dec_message = decrypt(&sk, &(c1, c2));
    assert_eq!(message, dec_message);

    // Assert decryption using an incorrect key
    let wrong_sk = JubJubScalar::random(&mut rng);
    let dec_message_wrong = decrypt(&wrong_sk, &(c1, c2));
    assert_ne!(message, dec_message_wrong);
}

#[cfg(feature = "zk")]
mod zk {
    use dusk_jubjub::{
        JubJubAffine, JubJubExtended, JubJubScalar, GENERATOR_EXTENDED,
    };
    use dusk_plonk::prelude::*;
    use ff::Field;
    use jubjub_elgamal::encrypt;
    use jubjub_elgamal::zk::{
        decrypt as decrypt_gadget, encrypt as encrypt_gadget,
    };
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    static LABEL: &[u8; 12] = b"dusk-network";
    const CAPACITY: usize = 13; // capacity required for the setup

    #[derive(Default, Debug)]
    pub struct ElGamalCircuit<const MUST_PASS: bool> {
        public_key: JubJubAffine,
        secret_key: JubJubScalar,
        plaintext: JubJubAffine,
        r: JubJubScalar,
        expected_ciphertext_1: JubJubAffine,
        expected_ciphertext_2: JubJubAffine,
    }

    impl<const MUST_PASS: bool> ElGamalCircuit<MUST_PASS> {
        pub fn new(
            public_key: &JubJubExtended,
            secret_key: &JubJubScalar,
            plaintext: &JubJubExtended,
            r: &JubJubScalar,
            expected_ciphertext_1: &JubJubExtended,
            expected_ciphertext_2: &JubJubExtended,
        ) -> Self {
            Self {
                public_key: JubJubAffine::from(public_key),
                secret_key: *secret_key,
                plaintext: JubJubAffine::from(plaintext),
                r: *r,
                expected_ciphertext_1: JubJubAffine::from(
                    expected_ciphertext_1,
                ),
                expected_ciphertext_2: JubJubAffine::from(
                    expected_ciphertext_2,
                ),
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
            let (ciphertext_1, ciphertext_2, _) =
                encrypt_gadget(composer, public_key, plaintext, r)?;

            // only for the 'encrypt_decrypt' test
            if MUST_PASS {
                // assert that the ciphertext is as expected
                composer.assert_equal_public_point(
                    ciphertext_1,
                    self.expected_ciphertext_1,
                );
                composer.assert_equal_public_point(
                    ciphertext_2,
                    self.expected_ciphertext_2,
                );

                // decrypt
                let dec_plaintext = decrypt_gadget(
                    composer,
                    secret_key,
                    ciphertext_1,
                    ciphertext_2,
                );

                // assert decoded plaintext is the same as the original
                composer.assert_equal_point(dec_plaintext, plaintext);
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
        let (c1, c2, _) = encrypt(&pk, &message, &r);

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
                    &c1.into(),
                    &c2.into(),
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

        // don't involved in this test
        let c1 = message;
        let c2 = message;

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
                    &c1.into(),
                    &c2.into(),
                ),
            )
            .expect("failed to prove");
    }
}
