# jubjub-elgamal

![Build Status](https://github.com/dusk-network/jubjub-elgamal/workflows/Continuous%20integration/badge.svg)
[![Repository](https://img.shields.io/badge/github-elgamal-blueviolet?logo=github)](https://github.com/dusk-network/jubjub-elgamal)
[![Documentation](https://img.shields.io/badge/docs-elgamal-blue?logo=rust)](https://docs.rs/jubjub-elgamal/)

This crate provides a Rust implementation of the [ElGamal encryption scheme](https://link.springer.com/chapter/10.1007/3-540-39568-7_2) implemented for elements of the [JubJub elliptic curve](https://github.com/dusk-network/jubjub) to be used natively and as part of a Zero-Knowledge circuit using [plonk](https://github.com/dusk-network/plonk). This implementation is designed by the [Dusk](https://dusk.network) team.

## About
The ElGamal encryption system is an asymmetric key encryption algorithm for public-key cryptography based on the Diffie-Hellman key exchange.
Its security relies on the difficulty of computing discrete logarithms over finite fields.
The implementation has been created using the field elements of the [`jubjub`](https://github.com/dusk-network/jubjub) elliptic curve.

## Algorithm

### Notation

In the following:
- Multiplication of a point $P$ by a scalar $s$ stands for adding $P$ $s$-times to itself.
- $\mathbb{F}_q$ is the prime finite field of order $q$
- for a prime $q$: $\mathbb{F}_q^× =  \mathbb{F}_q \setminus 0$ contains all nonzero elements of $\mathbb{F}_q$.

### Setup

Since we implement our ElGamal encryption scheme on the jubjub elliptic curve we have:
- a finite field $\mathbb{F}_q$ over prime $q$, which corresponds to the scalar field of the elliptic curve BLS12-381
- an elliptic curve $E / \mathbb{F}_q$, in our case this is the jubjub elliptic curve
- a subgroup $\mathbb{G} \in E(\mathbb{F}_q)$ of curve points, with prime order $p$
- a fixed generator point $G \in \mathbb{G}$

#### Key generation

- Choose a private signing key, $sk \in \mathbb{F}_p^×$.
- Compute the matching public key, $PK = skG \in \mathbb{G}$.

#### Encrypting

Suppose Alice wants to send Bob an encrypted message $m \in \mathbb{F}_q^×$.
To encrypt the message Alice will use Bob's public-key $PK_B$:

- Choose a random blinder nonce $r \in \mathbb{F}_p^×$.
- Compute first part of the ciphertext $c_1 = R = rG$.
- Compute second part of the ciphertext $c_2 = m + PK_B * r$.
- Send the ciphertext $(c_1, c_2)$ to Bob.

#### Decrypting

To decrypt the ciphertext $(c_1, c_2)$ Bob will use his secret-key $sk_B$:


- Compute $c_2 - c_1 * sk_B = m$

This is true because:
$$
c_2 - c_1 * sk_B = m + PK_B * r - (r * G * sk_B) = m + PK_B * r - PK_B * r = m
$$

## Example

A basic example demonstrating how to encrypt and decrypt a message using ElGamal:
```rust
use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED};
use ff::Field;
use jubjub_elgamal::{decrypt, encrypt};
use rand::rngs::StdRng;
use rand::SeedableRng;

let mut rng = StdRng::seed_from_u64(0xc0b);

let sk = JubJubScalar::random(&mut rng);
let pk = GENERATOR_EXTENDED * &sk;

let message = GENERATOR_EXTENDED * JubJubScalar::from(1234u64);

// Encrypt using a fresh random value 'blinder'
let r = JubJubScalar::random(&mut rng);
let (c1, c2) = encrypt(&pk, &message, &r);

// Assert decryption
let dec_message = decrypt(&sk, &(c1, c2));
assert_eq!(message, dec_message);
```

## Licensing
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.

Copyright (c) DUSK NETWORK. All rights reserved.
