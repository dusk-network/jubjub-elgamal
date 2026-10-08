// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{GENERATOR_EXTENDED, JubJubScalar};
use ff::Field;
use jubjub_elgamal::{DecryptFrom, Encryption};
use rand::SeedableRng;
use rand::rngs::StdRng;

#[test]
fn encrypt_decrypt_u64() {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let sk = JubJubScalar::random(&mut rng);
    let pk = GENERATOR_EXTENDED * &sk;

    let message = 1234u64;

    // Encrypt using a fresh random value 'blinder'
    let blinder = JubJubScalar::random(&mut rng);
    let (ciphertext, shared_key) =
        Encryption::encrypt_u64(&pk, &message, None, &blinder).unwrap();

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
        GENERATOR, GENERATOR_EXTENDED, JubJubAffine, JubJubExtended,
        JubJubScalar,
    };
    use dusk_plonk::prelude::*;
    use ff::Field;
    use jubjub_elgamal::zk::{
        DecryptFrom as DecryptFromZK, Encryption as EncryptionZK,
    };
    use jubjub_elgamal::{DecryptFrom, Encryption};
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
            let public_key = append_torsion_free(composer, self.public_key)?;
            let secret_key = composer.append_witness(self.secret_key);
            let plaintext = composer.append_witness(self.plaintext);
            let r = composer.append_witness(self.r);

            // encrypt plaintext using the public key
            let (ciphertext, shared_key) = EncryptionZK::encrypt_u64(
                composer, public_key, plaintext, None, r,
            )?;

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
                .decrypt_u64(composer, &DecryptFromZK::SecretKey(secret_key));

            // assert decoded plaintext is the same as the original
            composer.assert_equal(dec_plaintext, plaintext);

            // decrypt with shared key
            let dec_plaintext = ciphertext
                .decrypt_u64(composer, &DecryptFromZK::SharedKey(shared_key));
            composer.assert_equal(dec_plaintext, plaintext);

            // encrypt / decrypt plaintext using custom generator
            let custom_gen = composer.append_constant_point(
                GENERATOR_EXTENDED * JubJubScalar::from(1234u64),
            )?;
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
        let (ciphertext, _) =
            Encryption::encrypt_u64(&pk, &message, None, &r).unwrap();

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

    #[derive(Default, Debug)]
    pub struct DecryptCircuit {
        secret_key: JubJubScalar,
        plaintext: u64,
        ciphertext: Encryption,
    }

    impl Circuit for DecryptCircuit {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            let secret_key = composer.append_witness(self.secret_key);
            let public_key =
                composer.component_mul_generator(secret_key, GENERATOR)?;
            composer.assert_equal_public_point(
                public_key.into(),
                GENERATOR * self.secret_key,
            )?;

            let c1 = composer.append_public_point(*self.ciphertext.c1())?;
            let c2 = composer.append_public_point(*self.ciphertext.c2())?;
            let c1 = composer.assert_torsion_free_point(c1);
            let c2 = composer.assert_torsion_free_point(c2);
            let plaintext = EncryptionZK::new(c1, c2)
                .decrypt_u64(composer, &DecryptFromZK::SecretKey(secret_key));
            let expected = composer.append_public(self.plaintext);
            composer.assert_equal(plaintext, expected);

            Ok(())
        }
    }

    #[test]
    fn decrypt_u64_rejects_non_canonical_map() {
        let mut rng = StdRng::seed_from_u64(0xc0b);
        let pp = PublicParameters::setup(1 << CAPACITY, &mut rng).unwrap();
        let (prover, verifier) =
            Compiler::compile::<DecryptCircuit>(&pp, LABEL)
                .expect("failed to compile circuit");

        let secret_key = JubJubScalar::from(2u64);
        let pk = GENERATOR_EXTENDED * secret_key;
        let mut prove_and_verify = |ciphertext, plaintext| {
            let circuit = DecryptCircuit {
                secret_key,
                plaintext,
                ciphertext,
            };
            prover
                .prove(&mut rng, &circuit)
                .and_then(|(proof, pi)| verifier.verify(&proof, &pi))
        };
        // Ciphertext `(G, point + 2G)` decrypts to `point` under `pk = 2G`.
        let forge = |point: JubJubExtended| {
            let forged = Encryption::new(GENERATOR_EXTENDED, point + pk)
                .expect("prime-order ciphertext");
            let plaintext =
                forged.decrypt_u64(&DecryptFrom::SecretKey(secret_key));
            (forged, plaintext)
        };

        let r = JubJubScalar::from(1u64);
        let (honest, _) = Encryption::encrypt_u64(&pk, &18, None, &r).unwrap();
        prove_and_verify(honest, 18).expect("honest ciphertext must verify");

        // `GENERATOR` is the map of 18, and `-GENERATOR` shares its `y`.
        let (forged, plaintext) = forge(-GENERATOR_EXTENDED);
        assert_eq!(plaintext, 18);
        assert!(prove_and_verify(forged, plaintext).is_err());

        // The first `±[i]G` whose `x` and `y` bytes match `pred`.
        let find = |pred: fn([u8; 32], [u8; 32]) -> bool| {
            (1u64..)
                .map(|i| GENERATOR_EXTENDED * JubJubScalar::from(i))
                .flat_map(|p| [p, -p])
                .find(|p| {
                    let p = JubJubAffine::from(p);
                    pred(p.get_u().to_bytes(), p.get_v().to_bytes())
                })
                .unwrap()
        };
        // Each point fails exactly one of the range checks.
        for point in [
            // even `x`, `y >= 2^254`: fails the `k` check
            find(|x, y| x[0] & 1 == 0 && y[31] >= 0x40),
            // odd `x < 2^255 - p`, `y < 2^254`: fails the `x_half_neg` check
            find(|x, y| x[0] & 1 == 1 && x[31] < 0x0c && y[31] < 0x40),
            // odd `x > 2p - 2^255`, `y < 2^254`: fails the `x_half` check
            find(|x, y| x[0] & 1 == 1 && x[31] >= 0x68 && y[31] < 0x40),
        ] {
            let (forged, plaintext) = forge(point);
            assert!(prove_and_verify(forged, plaintext).is_err());
        }
    }
}
