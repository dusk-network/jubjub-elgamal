// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::Serializable;
use dusk_jubjub::{GENERATOR_EXTENDED, JubJubAffine, JubJubScalar};
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

    let ciphertext = Encryption::new(point, point)
        .expect("prime-order points should construct Encryption");

    assert_eq!(
        ciphertext,
        Encryption::from_bytes(&ciphertext.to_bytes()).unwrap()
    );

    // Create a small order point
    let small_order_point = JubJubAffine::identity();
    assert!(!bool::from(small_order_point.is_prime_order()));

    let mut bad_ciphertext_bytes = [0u8; 64];
    bad_ciphertext_bytes[..32].copy_from_slice(&small_order_point.to_bytes());
    bad_ciphertext_bytes[32..]
        .copy_from_slice(&JubJubAffine::from(point).to_bytes());

    // This should fail due to small order point in c1
    let result = Encryption::from_bytes(&bad_ciphertext_bytes);
    assert!(
        result.is_err(),
        "Deserialization should reject small order point in c1."
    );
}

#[cfg(feature = "zk")]
mod zk {
    use dusk_jubjub::{
        GENERATOR_EXTENDED, JubJubAffine, JubJubExtended, JubJubScalar,
    };
    use dusk_plonk::prelude::*;
    use ff::Field;
    use jubjub_elgamal::zk::{
        DecryptFrom as DecryptFromZK, Encryption as EncryptionZK,
    };
    use jubjub_elgamal::{Encryption, zk};
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    static LABEL: &[u8; 12] = b"dusk-network";
    const CAPACITY: usize = 14; // capacity required for the setup

    fn append_torsion_free(
        composer: &mut Composer,
        point: impl Into<JubJubExtended>,
    ) -> Result<TorsionFreeWitnessPoint, Error> {
        let point = composer.append_point(point)?;
        Ok(composer.assert_torsion_free_point(point))
    }

    fn small_order_point() -> JubJubExtended {
        let point = JubJubAffine::from_raw_unchecked(
            BlsScalar::zero(),
            -BlsScalar::one(),
        );
        assert!(bool::from(point.is_on_curve()));
        assert!(!bool::from(JubJubExtended::from(point).is_torsion_free()));
        point.into()
    }

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
            let public_key = append_torsion_free(composer, self.public_key)?;
            let secret_key = composer.append_witness(self.secret_key);
            let plaintext = append_torsion_free(composer, self.plaintext)?;
            let r = composer.append_witness(self.r);

            // encrypt plaintext using the public key
            let (ciphertext, shared_key) = EncryptionZK::encrypt(
                composer, public_key, plaintext, None, r,
            )?;

            // only for the 'encrypt_decrypt' test
            if MUST_PASS {
                // assert that the ciphertext is as expected
                composer.assert_equal_public_point(
                    (*ciphertext.c1()).into(),
                    *self.expected_ciphertext.c1(),
                )?;
                composer.assert_equal_public_point(
                    (*ciphertext.c2()).into(),
                    *self.expected_ciphertext.c2(),
                )?;

                // decrypt with sk
                let dec_plaintext = ciphertext
                    .decrypt(composer, &DecryptFromZK::SecretKey(secret_key));

                // assert decoded plaintext is the same as the original
                composer
                    .assert_equal_point(dec_plaintext.into(), plaintext.into());

                // decrypt with shared key
                let dec_plaintext = ciphertext
                    .decrypt(composer, &DecryptFromZK::SharedKey(shared_key));
                composer
                    .assert_equal_point(dec_plaintext.into(), plaintext.into());

                // encrypt / decrypt plaintext using custom generator
                let custom_gen = composer.append_constant_point(
                    GENERATOR_EXTENDED * JubJubScalar::from(1234u64),
                )?;
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
                composer.assert_equal_point(
                    custom_dec_plaintext.into(),
                    plaintext.into(),
                );
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

    #[derive(Default, Debug)]
    pub struct ElGamalInCircuitCheck {
        public_key: JubJubAffine,
        secret_key: JubJubScalar,
        plaintext: JubJubAffine,
        r: JubJubScalar,
        expected_ciphertext_1: JubJubAffine,
        expected_ciphertext_2: JubJubAffine,
    }

    impl ElGamalInCircuitCheck {
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

    impl Circuit for ElGamalInCircuitCheck {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            // import inputs
            let public_key = append_torsion_free(composer, self.public_key)?;
            let secret_key = composer.append_witness(self.secret_key);
            let plaintext = append_torsion_free(composer, self.plaintext)?;
            let r = composer.append_witness(self.r);

            // encrypt plaintext using the public-key
            let (ciphertext_1, ciphertext_2) =
                zk::encrypt_unchecked(composer, public_key, plaintext, r)?;

            // assert that the ciphertext is as expected
            composer.assert_equal_public_point(
                ciphertext_1.into(),
                self.expected_ciphertext_1,
            )?;
            composer.assert_equal_public_point(
                ciphertext_2.into(),
                self.expected_ciphertext_2,
            )?;

            // decrypt
            let dec_plaintext = zk::decrypt_unchecked(
                composer,
                secret_key,
                ciphertext_1,
                ciphertext_2,
            );

            // assert decoded plaintext is the same as the original
            composer.assert_equal_point(dec_plaintext.into(), plaintext.into());

            Ok(())
        }
    }

    #[test]
    fn encrypt_decrypt_v2() {
        let mut rng = StdRng::seed_from_u64(0xc0b);

        let sk = JubJubScalar::random(&mut rng);
        let pk = GENERATOR_EXTENDED * sk;

        let message = GENERATOR_EXTENDED * JubJubScalar::from(1234u64);
        let r = JubJubScalar::random(&mut rng);
        let (ciphertext, _) = Encryption::encrypt(&pk, &message, None, &r);

        let pp = PublicParameters::setup(1 << CAPACITY, &mut rng).unwrap();

        let (prover, verifier) =
            Compiler::compile::<ElGamalInCircuitCheck>(&pp, LABEL)
                .expect("failed to compile circuit");

        let (proof, public_inputs) = prover
            .prove(
                &mut rng,
                &ElGamalInCircuitCheck::new(
                    &pk,
                    &sk,
                    &message,
                    &r,
                    ciphertext.c1(),
                    ciphertext.c2(),
                ),
            )
            .expect("failed to prove");

        verifier
            .verify(&proof, &public_inputs)
            .expect("failed to verify proof");
    }

    #[test]
    fn checked_encryption_rejects_small_order_inputs() {
        let mut rng = StdRng::seed_from_u64(0xc0b);

        let sk = JubJubScalar::random(&mut rng);
        let public_key = GENERATOR_EXTENDED * sk;
        let plaintext = GENERATOR_EXTENDED * JubJubScalar::from(1234u64);
        let small_order = small_order_point();
        let r = JubJubScalar::random(&mut rng);

        let pp = PublicParameters::setup(1 << CAPACITY, &mut rng).unwrap();

        let (prover, _verifier) =
            Compiler::compile::<ElGamalCircuit<false>>(&pp, LABEL)
                .expect("failed to compile circuit");

        for (public_key, plaintext) in
            [(small_order, plaintext), (public_key, small_order)]
        {
            let circuit = ElGamalCircuit::<false>::new(
                &public_key,
                &sk,
                &plaintext,
                &r,
                &Encryption::default(),
            );
            assert!(
                prover.prove(&mut rng, &circuit).is_err(),
                "small-order input should not prove"
            );
        }
    }

    #[test]
    fn unchecked_encryption_rejects_small_order_inputs() {
        let mut rng = StdRng::seed_from_u64(0xc0b);

        let zero = JubJubScalar::zero();
        let public_key = GENERATOR_EXTENDED;
        let plaintext = GENERATOR_EXTENDED * JubJubScalar::from(1234u64);
        let small_order = small_order_point();
        let ciphertext_1 = GENERATOR_EXTENDED * zero;

        let pp = PublicParameters::setup(1 << CAPACITY, &mut rng).unwrap();
        let (prover, _verifier) =
            Compiler::compile::<ElGamalInCircuitCheck>(&pp, LABEL)
                .expect("failed to compile circuit");

        // With a zero blinder and secret key, every other constraint is
        // satisfied: c1 is the identity and c2 is the plaintext. Rejection is
        // therefore attributable to the subgroup boundary checks.
        for (public_key, plaintext) in
            [(small_order, plaintext), (public_key, small_order)]
        {
            let circuit = ElGamalInCircuitCheck::new(
                &public_key,
                &zero,
                &plaintext,
                &zero,
                &ciphertext_1,
                &plaintext,
            );
            assert!(
                prover.prove(&mut rng, &circuit).is_err(),
                "small-order input should not prove"
            );
        }
    }
}
