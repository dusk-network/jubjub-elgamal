// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::Serializable;
use dusk_jubjub::{
    BlsScalar, GENERATOR_EXTENDED, JubJubAffine, JubJubExtended, JubJubScalar,
};
use ff::Field;
use jubjub_elgamal::{DecryptFrom, Encryption};
use rand::SeedableRng;
use rand::rngs::StdRng;

/// A point outside the prime-order subgroup.
fn torsion_point() -> JubJubExtended {
    let point = JubJubExtended::from(JubJubAffine::from_raw_unchecked(
        BlsScalar::from_raw([
            0xd92e_6a79_2720_0d43,
            0x7aa4_1ac4_3dae_8582,
            0xeaaa_e086_a166_18d1,
            0x71d4_df38_ba9e_7973,
        ]),
        BlsScalar::from_raw([
            0xff0d_2068_eff4_96dd,
            0x9106_ee90_f384_a4a1,
            0x16a1_3035_ad4d_7266,
            0x4958_bdb2_1966_982e,
        ]),
    ));
    assert!(!bool::from(point.is_torsion_free()));
    point
}

/// Asserts that `ciphertext` round-trips through its bytes and, with
/// `rkyv-impl`, through its archive.
fn assert_round_trips(ciphertext: Encryption) {
    let bytes = ciphertext.to_bytes();
    assert_eq!(Encryption::from_bytes(&bytes).unwrap(), ciphertext);

    #[cfg(feature = "rkyv-impl")]
    {
        let bytes = rkyv::to_bytes::<_, 64>(&ciphertext).unwrap();
        assert_eq!(rkyv::from_bytes::<Encryption>(&bytes).unwrap(), ciphertext);
    }
}

#[test]
fn encrypt_decrypt() {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let sk = JubJubScalar::random(&mut rng);
    let pk = GENERATOR_EXTENDED * &sk;

    let message = GENERATOR_EXTENDED * JubJubScalar::from(1234u64);

    // Encrypt using a fresh random value 'blinder'
    let blinder = JubJubScalar::random(&mut rng);
    let (ciphertext, shared_key) =
        Encryption::encrypt(&pk, &message, None, &blinder).unwrap();

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
        Encryption::encrypt(&custom_pk, &message, Some(&custom_gen), &blinder)
            .unwrap();

    let dec_message = custom_enc.decrypt(&DecryptFrom::SecretKey(sk));
    assert_eq!(message, dec_message);
}

#[test]
fn default_round_trips() {
    assert_round_trips(Encryption::default());
}

#[test]
fn encrypt_output_round_trips() {
    let mut rng = StdRng::seed_from_u64(0xc0b);
    let pk = GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);
    let message = GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);
    let generator = GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);
    let r = JubJubScalar::random(&mut rng);

    for generator in [None, Some(&generator)] {
        let (ciphertext, _) =
            Encryption::encrypt(&pk, &message, generator, &r).unwrap();
        assert_round_trips(ciphertext);

        let (ciphertext, _) =
            Encryption::encrypt_u64(&pk, &1234, generator, &r).unwrap();
        assert_round_trips(ciphertext);
    }
}

#[test]
fn encrypt_rejects_components_not_of_prime_order() {
    let mut rng = StdRng::seed_from_u64(0xc0b);
    let pk = GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);
    let message = GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);
    let generator = GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);
    let torsion = torsion_point();
    let identity = JubJubExtended::identity();
    let zero = JubJubScalar::zero();
    // a nonce of one keeps each torsion component in the ciphertext
    let one = JubJubScalar::one();

    for (pk, message, generator, r) in [
        // identity `c1`
        (pk, message, None, zero),
        (pk, message, Some(generator), zero),
        (pk, message, Some(identity), one),
        // identity `c2`
        (pk, -pk, None, one),
        // identity shared key, which would leave the plaintext as `c2`
        (identity, message, None, one),
        // inputs outside the prime-order subgroup
        (pk + torsion, message, None, one),
        (pk, message + torsion, None, one),
        (pk, message, Some(generator + torsion), one),
    ] {
        assert!(
            Encryption::encrypt(&pk, &message, generator.as_ref(), &r).is_err()
        );
    }
    assert!(
        Encryption::encrypt_u64(&(pk + torsion), &1234, None, &one).is_err()
    );
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

#[cfg(feature = "rkyv-impl")]
#[test]
fn rkyv_rejects_small_order_ciphertext() {
    let valid_point = JubJubAffine::from(GENERATOR_EXTENDED).to_bytes();
    let torsion = JubJubAffine::from(torsion_point()).to_bytes();

    for bytes in [
        [torsion, valid_point].concat(),
        [valid_point, torsion].concat(),
    ] {
        assert!(rkyv::check_archived_root::<Encryption>(&bytes).is_err());
        assert!(rkyv::from_bytes::<Encryption>(&bytes).is_err());
    }
}

#[cfg(feature = "rkyv-impl")]
#[test]
fn rkyv_rejects_identity_and_malformed_ciphertext() {
    let valid_point = JubJubAffine::from(GENERATOR_EXTENDED).to_bytes();
    let identity = JubJubAffine::identity().to_bytes();

    for bytes in [
        [identity, valid_point].concat(),
        [valid_point, identity].concat(),
        [0xff; Encryption::SIZE].to_vec(),
    ] {
        assert!(rkyv::check_archived_root::<Encryption>(&bytes).is_err());
        assert!(rkyv::from_bytes::<Encryption>(&bytes).is_err());
    }
}

#[cfg(feature = "rkyv-impl")]
#[test]
fn rkyv_roundtrip() {
    let ciphertext = Encryption::new(
        GENERATOR_EXTENDED,
        GENERATOR_EXTENDED * JubJubScalar::from(2u64),
    )
    .unwrap();
    let bytes = rkyv::to_bytes::<_, 64>(&ciphertext).unwrap();

    assert_eq!(bytes.len(), Encryption::SIZE);
    assert!(rkyv::check_archived_root::<Encryption>(&bytes).is_ok());
    assert_eq!(rkyv::from_bytes::<Encryption>(&bytes).unwrap(), ciphertext);
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
    const CAPACITY: usize = 15; // capacity required for the setup

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
        let (ciphertext, _) =
            Encryption::encrypt(&pk, &message, None, &r).unwrap();

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
        let (ciphertext, _) =
            Encryption::encrypt(&pk, &message, None, &r).unwrap();

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

    fn custom_generator() -> JubJubExtended {
        GENERATOR_EXTENDED * JubJubScalar::from(1234u64)
    }

    /// Encrypts with the gadget `GADGET` picks: `Encryption::encrypt` with a
    /// custom (`0`) or the default (`1`) generator, or `encrypt_unchecked`
    /// (`2`). The nonce is a raw BLS scalar, so tests can make it
    /// non-canonical.
    #[derive(Default)]
    pub struct NonceCircuit<const GADGET: u8> {
        public_key: JubJubAffine,
        plaintext: JubJubAffine,
        r: BlsScalar,
        ciphertext: (JubJubAffine, JubJubAffine),
    }

    impl<const GADGET: u8> Circuit for NonceCircuit<GADGET> {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            let public_key = append_torsion_free(composer, self.public_key)?;
            let plaintext = append_torsion_free(composer, self.plaintext)?;
            let r = composer.append_witness(self.r);

            let (c1, c2) = match GADGET {
                0 => {
                    let generator =
                        composer.append_constant_point(custom_generator())?;
                    let (enc, _) = EncryptionZK::encrypt(
                        composer,
                        public_key,
                        plaintext,
                        Some(generator),
                        r,
                    )?;
                    (*enc.c1(), *enc.c2())
                }
                1 => {
                    let (enc, _) = EncryptionZK::encrypt(
                        composer, public_key, plaintext, None, r,
                    )?;
                    (*enc.c1(), *enc.c2())
                }
                _ => zk::encrypt_unchecked(composer, public_key, plaintext, r)?,
            };
            composer.assert_equal_public_point(c1.into(), self.ciphertext.0)?;
            composer.assert_equal_public_point(c2.into(), self.ciphertext.1)?;

            Ok(())
        }
    }

    fn assert_rejects_non_canonical_nonce<const GADGET: u8>(
        pp: &PublicParameters,
        rng: &mut StdRng,
    ) {
        let generator = (GADGET == 0).then(custom_generator);
        let public_key = GENERATOR_EXTENDED * JubJubScalar::random(&mut *rng);
        let plaintext = GENERATOR_EXTENDED * JubJubScalar::random(&mut *rng);

        let (prover, verifier) =
            Compiler::compile::<NonceCircuit<GADGET>>(pp, LABEL)
                .expect("failed to compile circuit");

        // The ciphertext of the scalar `s`
        let ciphertext = |s: &JubJubScalar| {
            let (enc, _) = Encryption::encrypt(
                &public_key,
                &plaintext,
                generator.as_ref(),
                s,
            )
            .unwrap();
            (*enc.c1(), *enc.c2())
        };

        // Proves with the nonce witness `r` against the ciphertext `(c1, c2)`
        let mut prove =
            |r: BlsScalar, (c1, c2): (JubJubExtended, JubJubExtended)| {
                let circuit = NonceCircuit::<GADGET> {
                    public_key: public_key.into(),
                    plaintext: plaintext.into(),
                    r,
                    ciphertext: (c1.into(), c2.into()),
                };
                prover
                    .prove(&mut *rng, &circuit)
                    .and_then(|(proof, pi)| verifier.verify(&proof, &pi))
            };

        let s = JubJubScalar::from(42u64);
        prove(s.into(), ciphertext(&s)).expect("canonical nonce must verify");

        // `s` plus the subgroup order stays below `2^252`
        let order = BlsScalar::from(-JubJubScalar::one()) + BlsScalar::one();
        assert!(prove(BlsScalar::from(s) + order, ciphertext(&s)).is_err());

        // The boundary: the largest canonical nonce verifies, while the
        // subgroup order, which encrypts like a zero nonce, does not
        let max = -JubJubScalar::one();
        prove(max.into(), ciphertext(&max))
            .expect("largest canonical nonce must verify");
        assert!(prove(order, (JubJubExtended::identity(), plaintext)).is_err());

        // `-1` is below the largest canonical scalar modulo the BLS order
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&(-BlsScalar::one()).to_bytes());
        let s = JubJubScalar::from_bytes_wide(&wide);
        assert!(prove(-BlsScalar::one(), ciphertext(&s)).is_err());
    }

    #[test]
    fn encryption_rejects_non_canonical_nonce() {
        let mut rng = StdRng::seed_from_u64(0xc0b);
        let pp = PublicParameters::setup(1 << CAPACITY, &mut rng).unwrap();

        assert_rejects_non_canonical_nonce::<0>(&pp, &mut rng);
        assert_rejects_non_canonical_nonce::<1>(&pp, &mut rng);
        assert_rejects_non_canonical_nonce::<2>(&pp, &mut rng);
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

        let prove = |rng: &mut StdRng,
                     public_key: JubJubExtended,
                     plaintext: JubJubExtended| {
            let circuit = ElGamalCircuit::<false>::new(
                &public_key,
                &sk,
                &plaintext,
                &r,
                &Encryption::default(),
            );
            prover.prove(rng, &circuit)
        };

        // The honest pair proves with the same key and `r`, so the rejections
        // below come from the subgroup checks
        prove(&mut rng, public_key, plaintext)
            .expect("honest inputs must prove");
        for (public_key, plaintext) in
            [(small_order, plaintext), (public_key, small_order)]
        {
            assert!(
                matches!(
                    prove(&mut rng, public_key, plaintext),
                    Err(Error::CircuitUnsatisfied)
                ),
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

        let prove = |rng: &mut StdRng,
                     public_key: JubJubExtended,
                     plaintext: JubJubExtended| {
            let circuit = ElGamalInCircuitCheck::new(
                &public_key,
                &zero,
                &plaintext,
                &zero,
                &ciphertext_1,
                &plaintext,
            );
            prover.prove(rng, &circuit)
        };

        // With a zero blinder and secret key, c1 is the identity and c2 the
        // plaintext. The honest pair proves in that configuration, so the
        // rejections below come from the subgroup checks.
        prove(&mut rng, public_key, plaintext)
            .expect("honest inputs must prove");
        for (public_key, plaintext) in
            [(small_order, plaintext), (public_key, small_order)]
        {
            assert!(
                matches!(
                    prove(&mut rng, public_key, plaintext),
                    Err(Error::CircuitUnsatisfied)
                ),
                "small-order input should not prove"
            );
        }
    }
}
